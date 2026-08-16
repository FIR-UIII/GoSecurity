package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"layeh.com/radius"
)

// AttrSpec is a single RADIUS attribute expressed at the byte level, so that
// both well-formed and deliberately malformed attributes can be built.
type AttrSpec struct {
	Type        byte
	Value       []byte
	LenOverride int // -1 means "derive from len(Value)+2"
}

func (a AttrSpec) lengthByte() byte {
	if a.LenOverride >= 0 {
		return byte(a.LenOverride)
	}
	return byte(2 + len(a.Value))
}

func (a AttrSpec) clone() AttrSpec {
	v := make([]byte, len(a.Value))
	copy(v, a.Value)
	return AttrSpec{Type: a.Type, Value: v, LenOverride: a.LenOverride}
}

// RawPacket is a wire-level representation of a RADIUS datagram that is
// built and encoded by hand, deliberately bypassing the validation done by
// the layeh.com/radius library so that malformed/fuzzed datagrams can be
// produced and sent to the server under test.
type RawPacket struct {
	Code           byte
	ID             byte
	Authenticator  [16]byte
	Attrs          []AttrSpec
	LengthOverride int // -1 means "derive from actual encoded size"
}

func (p RawPacket) Clone() RawPacket {
	attrs := make([]AttrSpec, len(p.Attrs))
	for i, a := range p.Attrs {
		attrs[i] = a.clone()
	}
	return RawPacket{
		Code:           p.Code,
		ID:             p.ID,
		Authenticator:  p.Authenticator,
		Attrs:          attrs,
		LengthOverride: p.LengthOverride,
	}
}

// Build encodes the packet to wire format. It never returns an error: any
// out-of-range values (e.g. an attribute length byte that lies about the
// value size) are encoded as-is, since that is often exactly the point of a
// fuzzing run.
func (p RawPacket) Build() []byte {
	var body []byte
	for _, a := range p.Attrs {
		body = append(body, a.Type, a.lengthByte())
		body = append(body, a.Value...)
	}

	total := 20 + len(body)
	lengthField := total
	if p.LengthOverride >= 0 {
		lengthField = p.LengthOverride
	}

	buf := make([]byte, total)
	buf[0] = p.Code
	buf[1] = p.ID
	buf[2] = byte(lengthField >> 8)
	buf[3] = byte(lengthField)
	copy(buf[4:20], p.Authenticator[:])
	copy(buf[20:], body)
	return buf
}

// codeByName resolves a RADIUS code given either its numeric value or a
// name such as "Access-Request".
func codeByName(s string) (byte, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 || n > 255 {
			return 0, fmt.Errorf("code %d out of range", n)
		}
		return byte(n), nil
	}
	names := map[string]radius.Code{
		"access-request":     radius.CodeAccessRequest,
		"access-accept":      radius.CodeAccessAccept,
		"access-reject":      radius.CodeAccessReject,
		"access-challenge":   radius.CodeAccessChallenge,
		"accounting-request": radius.CodeAccountingRequest,
		"status-server":      radius.CodeStatusServer,
	}
	c, ok := names[strings.ToLower(s)]
	if !ok {
		return 0, fmt.Errorf("unknown RADIUS code %q", s)
	}
	return byte(c), nil
}

// parseAttrSpec parses a single -attr flag value.
//
// Grammar: <type>=<kind>:<value>[;len=<n>]
//
//	type  - attribute name (e.g. User-Name) or numeric id (e.g. 1)
//	kind  - str | int | ip | hex | pwd
//	value - the attribute payload, formatted according to kind
//	len   - optional literal length byte override, for building malformed
//	        attributes (e.g. ;len=255 while the actual value is short)
func parseAttrSpec(spec, secret string, authenticator [16]byte) (AttrSpec, error) {
	eq := strings.IndexByte(spec, '=')
	if eq < 0 {
		return AttrSpec{}, fmt.Errorf("invalid -attr %q: expected type=kind:value", spec)
	}
	typeStr := strings.TrimSpace(spec[:eq])
	rest := spec[eq+1:]

	var lenOverride = -1
	if semi := strings.Index(rest, ";len="); semi >= 0 {
		n, err := strconv.Atoi(rest[semi+5:])
		if err != nil {
			return AttrSpec{}, fmt.Errorf("invalid -attr %q: bad len override: %w", spec, err)
		}
		lenOverride = n
		rest = rest[:semi]
	}

	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return AttrSpec{}, fmt.Errorf("invalid -attr %q: expected kind:value", spec)
	}
	kind := strings.ToLower(strings.TrimSpace(rest[:colon]))
	value := rest[colon+1:]

	typ, err := resolveAttrType(typeStr)
	if err != nil {
		return AttrSpec{}, err
	}

	var payload []byte
	switch kind {
	case "str", "string":
		payload = []byte(value)
	case "int", "integer":
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return AttrSpec{}, fmt.Errorf("invalid -attr %q: bad integer: %w", spec, err)
		}
		payload = []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	case "ip":
		ip := net.ParseIP(value).To4()
		if ip == nil {
			return AttrSpec{}, fmt.Errorf("invalid -attr %q: bad IPv4 address", spec)
		}
		payload = ip
	case "hex":
		b, err := hex.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return AttrSpec{}, fmt.Errorf("invalid -attr %q: bad hex: %w", spec, err)
		}
		payload = b
	case "pwd", "password":
		enc, err := radius.NewUserPassword([]byte(value), []byte(secret), authenticator[:])
		if err != nil {
			return AttrSpec{}, fmt.Errorf("invalid -attr %q: %w", spec, err)
		}
		payload = enc
	default:
		return AttrSpec{}, fmt.Errorf("invalid -attr %q: unknown kind %q", spec, kind)
	}

	return AttrSpec{Type: typ, Value: payload, LenOverride: lenOverride}, nil
}

func resolveAttrType(s string) (byte, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 || n > 255 {
			return 0, fmt.Errorf("attribute type %d out of range", n)
		}
		return byte(n), nil
	}
	if t, ok := attrNameToType[strings.ToLower(s)]; ok {
		return t, nil
	}
	return 0, fmt.Errorf("unknown attribute name %q", s)
}
