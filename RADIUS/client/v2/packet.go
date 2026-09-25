package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// radiusCodeNames maps well-known RADIUS Code values to names (RFC 2865/
// 2866), for a "packet" scenario's code: field and for a scenario's
// response: expected-outcome field. accept/reject/challenge are short
// aliases for the three codes an appsec test is normally asserting on.
var radiusCodeNames = map[string]byte{
	"access-request":      1,
	"access-accept":       2,
	"access-reject":       3,
	"accounting-request":  4,
	"accounting-response": 5,
	"access-challenge":    11,
	"status-server":       12,
	"status-client":       13,
	"accept":              2,
	"reject":              3,
	"challenge":           11,
}

// radiusCodeDisplayNames is the canonical (non-alias) reverse lookup, used
// only for human-readable log/error messages.
var radiusCodeDisplayNames = map[byte]string{
	1:  "Access-Request",
	2:  "Access-Accept",
	3:  "Access-Reject",
	4:  "Accounting-Request",
	5:  "Accounting-Response",
	11: "Access-Challenge",
	12: "Status-Server",
	13: "Status-Client",
}

// radiusCodeName returns the display name for a RADIUS Code byte, or
// "Unknown" if unmapped.
func radiusCodeName(c byte) string {
	if n, ok := radiusCodeDisplayNames[c]; ok {
		return n
	}
	return "Unknown"
}

// resolveRadiusCode parses a "packet" scenario's code field or a
// scenario's response field: empty means the default (1, Access-Request),
// a plain integer (0-255) is used directly, otherwise the token is looked
// up case-insensitively by name (including the accept/reject/challenge
// aliases).
func resolveRadiusCode(s string) (byte, error) {
	if s == "" {
		return 1, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 || n > 255 {
			return 0, fmt.Errorf("code %d out of range (0-255)", n)
		}
		return byte(n), nil
	}
	if c, ok := radiusCodeNames[strings.ToLower(s)]; ok {
		return c, nil
	}
	return 0, fmt.Errorf("unknown RADIUS code %q", s)
}

// resolveExpectedResponse parses a scenario's response: field — the RADIUS
// code an appsec test expects back in order to count as a pass. An empty
// string means "no expectation configured" (nil, nil).
func resolveExpectedResponse(s string) (*byte, error) {
	if s == "" {
		return nil, nil
	}
	c, err := resolveRadiusCode(s)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// checkExpectedResponse compares got against a scenario's response: field
// (expected), if one was configured. expected == "" always passes (no
// assertion configured). On a mismatch it returns an error naming both
// sides, so a failed appsec test is unambiguous in the scenario summary.
func checkExpectedResponse(expected string, got byte) error {
	want, err := resolveExpectedResponse(expected)
	if err != nil {
		return err
	}
	if want == nil {
		return nil
	}
	if got != *want {
		return fmt.Errorf("expected response %s (code %d, %s), got code %d (%s)",
			expected, *want, radiusCodeName(*want), got, radiusCodeName(got))
	}
	return nil
}

// isTimeoutResponse reports whether s is the special "Timeout" response:
// value (case-insensitive, surrounding whitespace ignored). It asserts the
// opposite of every other response: value: that the server must NOT reply
// within the configured timeout at all — e.g. a malformed/hostile packet
// that a well-behaved server should silently drop rather than answer.
func isTimeoutResponse(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "timeout")
}

// isNetTimeout reports whether err is specifically a network timeout, as
// opposed to some other network failure (connection refused, unreachable
// host, etc.) — so a response: Timeout scenario can tell "the server never
// replied, as expected" apart from a different, still-unexpected failure.
func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// parseAttrValue interprets an AttrSpec.Value string as hex:<hexstring>
// (raw/binary/invalid bytes) or, otherwise, a literal UTF-8 string.
func parseAttrValue(s string) ([]byte, error) {
	if rest, ok := strings.CutPrefix(s, "hex:"); ok {
		b, err := hex.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			return nil, fmt.Errorf("decode hex value: %w", err)
		}
		return b, nil
	}
	return []byte(s), nil
}

// appendAttr appends Type|Length|Value to attrs. If 2+len(value) exceeds
// 255, the Length byte deliberately wraps (byte(2+len(value))) rather than
// erroring or truncating value — an oversized value is itself a valid,
// intentional thing to want to send here (Length lying about actual
// payload size). A warning is logged so the wrap is visible in run output.
func appendAttr(attrs []byte, typ byte, value []byte) []byte {
	if 2+len(value) > 255 {
		log.Printf("[packet] warning: attr %d (%s) value is %d bytes; length byte wraps to %d",
			typ, attrName(typ), len(value), byte(2+len(value)))
	}
	attrs = append(attrs, typ, byte(2+len(value)))
	attrs = append(attrs, value...)
	return attrs
}

// ipv4Attrs are the well-known RADIUS attributes whose Value MUST be the
// raw 4-octet binary form of an IPv4 address (RFC 2865 §5.4, §5.8, §5.9,
// §5.14), not its dotted-quad text representation. See maybeEncodeIPv4.
var ipv4Attrs = map[byte]bool{
	4:  true, // NAS-IP-Address
	8:  true, // Framed-IP-Address
	9:  true, // Framed-IP-Netmask
	14: true, // Login-IP-Host
}

// maybeEncodeIPv4 converts raw (spec.Value as written in YAML) to its
// 4-octet binary form when typ is one of ipv4Attrs and raw parses as a
// dotted-quad IPv4 address — e.g. "127.0.0.1" becomes the 4 bytes
// 0x7f000001, matching what RFC 2865 requires on the wire and what a
// strict RADIUS server/parser expects. Without this, a literal
// "value: 127.0.0.1" would be sent as its 9-byte ASCII text instead,
// which is malformed for these attributes.
//
// A hex:... value is left untouched (val is already the exact raw bytes
// the author chose), and a raw string that doesn't parse as IPv4 is left
// as val too, so a deliberately malformed IP value is still testable —
// this only fixes the common case of writing a normal address in the
// obvious way.
func maybeEncodeIPv4(typ byte, raw string, val []byte) []byte {
	if !ipv4Attrs[typ] || strings.HasPrefix(raw, "hex:") {
		return val
	}
	if ip4 := net.ParseIP(raw).To4(); ip4 != nil {
		return ip4
	}
	return val
}

// appendAttrSpec resolves spec's Type/Value and appends the resulting TLV
// to attrs, returning the offset (within the returned attrs, i.e. relative
// to the start of the attribute stream) of a 16-byte all-zero
// Message-Authenticator placeholder if this call added one, or -1
// otherwise; see the special case below and runPacketScenario, which
// patches the real hash in once the whole packet is assembled.
//
// If spec.Length is set, it's used as the literal Length byte even if it
// doesn't match len(value) — deliberately allowing malformed lengths,
// since that's a legitimate thing to want full manual control over here.
// Otherwise it falls back to appendAttr's default 2+len(value) encoding
// (including its oversized-value wrap warning).
//
// secret and authenticator are only needed for User-Password's
// auto-PAP-encryption special case below; every other attribute ignores
// them.
func appendAttrSpec(attrs []byte, spec AttrSpec, secret string, authenticator []byte) ([]byte, int, error) {
	typ, err := resolveAttrType(spec.Type)
	if err != nil {
		return nil, -1, err
	}

	// User-Password (type 2) with a plain (non-hex:) value and no
	// explicit length: is PAP-encrypted for you (RFC 2865 §5.2, the same
	// encryptPAP buildPAPPacket uses), keyed off this packet's own
	// secret+authenticator — so a scenario can just write the plaintext
	// password instead of precomputing and pasting in a hex: ciphertext
	// by hand. A hex: value (raw bytes, sent exactly as given) or an
	// explicit length: opts back out of this, same convention as
	// Message-Authenticator below, for testing a deliberately wrong or
	// unencrypted User-Password.
	if typ == 2 && spec.Length == nil && !strings.HasPrefix(spec.Value, "hex:") {
		enc := encryptPAP(spec.Value, secret, authenticator)
		return appendAttr(attrs, typ, enc), -1, nil
	}

	// Message-Authenticator (type 80) with no explicit value or length:
	// treat this as "compute it for me". Its correct value (RFC 2869
	// §5.14: HMAC-MD5 over the entire packet, with this field zeroed) can
	// only be known once the whole packet — including this very
	// attribute's own Length byte — has been assembled, so reserve 18
	// bytes (Type|Length|16 zero bytes) here and report their offset;
	// runPacketScenario computes the real hash afterward and patches it
	// in in place. Supplying an explicit value: or length: opts back out
	// of this and falls through to full manual control, same as any
	// other attribute.
	if typ == 80 && spec.Value == "" && spec.Length == nil {
		valOffset := len(attrs) + 2
		attrs = append(attrs, typ, 18)
		attrs = append(attrs, make([]byte, 16)...)
		return attrs, valOffset, nil
	}

	val, err := parseAttrValue(spec.Value)
	if err != nil {
		return nil, -1, err
	}
	val = maybeEncodeIPv4(typ, spec.Value, val)

	if spec.Length != nil {
		attrs = append(attrs, typ, byte(*spec.Length))
		attrs = append(attrs, val...)
		return attrs, -1, nil
	}
	return appendAttr(attrs, typ, val), -1, nil
}

// buildPacketFromSpec builds a single RADIUS packet entirely from explicit
// code/id/authenticator/attrs values — the same manual-framing logic
// runPacketScenario uses, extracted so other callers (the fuzz scenario
// type's mutation loop) can build one-off packets from a mutated attrs
// list without going through a full Scenario/log/response-check cycle.
//
// Nothing is added automatically beyond what attrs lists. A type-80
// (Message-Authenticator) entry that gives neither value nor length IS
// computed automatically (see appendAttrSpec); an explicit value:/length:
// opts out of that, same as runPacketScenario. authenticatorHex empty
// means: generate one (accounting-style integrity-check authenticator for
// Accounting-Request/Status-Server per RFC 2866 §3 / RFC 5997 §3, random
// otherwise); a non-empty authenticatorHex is decoded and used exactly as
// given.
func buildPacketFromSpec(secret string, code byte, id *byte, authenticatorHex string, attrs []AttrSpec) ([]byte, error) {
	// See runPacketScenario's original comment: Accounting-Request/
	// Status-Server use the Request Authenticator as an integrity check
	// (MD5 of header+attrs+secret), not random data.
	needsAccountingStyleAuth := authenticatorHex == "" && (code == 4 || code == 12)

	var authenticator []byte
	var err error
	if authenticatorHex != "" {
		authenticator, err = hex.DecodeString(authenticatorHex)
		if err != nil {
			return nil, fmt.Errorf("decode authenticator: %w", err)
		}
	} else if needsAccountingStyleAuth {
		authenticator = make([]byte, 16) // placeholder; computed for real below
	} else {
		authenticator = make([]byte, 16)
		if _, err := rand.Read(authenticator); err != nil {
			return nil, fmt.Errorf("generate authenticator: %w", err)
		}
	}

	var attrBytes []byte
	maValOffset := -1 // offset within attrBytes of an auto Message-Authenticator's 16 zero bytes, or -1
	for i, spec := range attrs {
		var off int
		attrBytes, off, err = appendAttrSpec(attrBytes, spec, secret, authenticator)
		if err != nil {
			return nil, fmt.Errorf("attrs[%d]: %w", i, err)
		}
		if off >= 0 {
			if maValOffset >= 0 {
				return nil, fmt.Errorf("attrs[%d]: only one auto-computed Message-Authenticator is supported per packet", i)
			}
			maValOffset = off
		}
	}

	pkt, _, err := buildRadiusPacket(secret, code, id, authenticator, attrBytes, false)
	if err != nil {
		return nil, fmt.Errorf("build packet: %w", err)
	}

	// Compute the real Request Authenticator now that pkt holds the zeroed
	// one plus every attribute (including a zeroed Message-Authenticator
	// placeholder, if any) — exactly the input RFC 2866 §3 / RFC 5997 §3
	// specify — and patch it into the header. This MUST happen before the
	// Message-Authenticator is computed below, since that HMAC covers the
	// packet's real (non-zero) Request Authenticator.
	if needsAccountingStyleAuth {
		sum := md5.Sum(append(append([]byte{}, pkt...), []byte(secret)...))
		copy(pkt[4:20], sum[:])
	}

	// Patch in the real Message-Authenticator now that the full packet
	// (correct Length, all other attributes) is assembled — RFC 2869
	// §5.14 requires the HMAC-MD5 to be computed over the entire packet
	// with this field's 16 bytes zeroed, which is exactly the state pkt
	// is in right now (appendAttrSpec left the placeholder zeroed).
	if maValOffset >= 0 {
		absOffset := 20 + maValOffset
		mac := hmac.New(md5.New, []byte(secret))
		mac.Write(pkt)
		hash := mac.Sum(nil)
		copy(pkt[absOffset:absOffset+16], hash)
	}
	return pkt, nil
}

// runPacketScenario builds a single RADIUS packet entirely from sc's
// explicit code/id/authenticator/attrs fields (via buildPacketFromSpec)
// and sends it, logging and checking the response against sc.Response.
// This is the scenario type to reach for when testing how a server
// handles a request missing something the normal encoder would always
// include, e.g. Message-Authenticator: just leave any type-80 entry out
// of attrs entirely.
func runPacketScenario(addr, secret string, timeout time.Duration, sc Scenario) error {
	code, err := resolveRadiusCode(sc.Code)
	if err != nil {
		return err
	}

	var id *byte
	if sc.ID != nil {
		b := byte(*sc.ID)
		id = &b
	}

	pkt, err := buildPacketFromSpec(secret, code, id, sc.Authenticator, sc.Attrs)
	if err != nil {
		return err
	}
	log.Printf("[packet] sending %d bytes: %x", len(pkt), pkt)

	resp, err := sendRawUDP(addr, pkt, timeout)
	if err != nil {
		if isTimeoutResponse(sc.Response) && isNetTimeout(err) {
			log.Printf("[packet] no response within timeout, as expected (response: Timeout)")
			return nil
		}
		return fmt.Errorf("network: %w", err)
	}
	log.Printf("[packet] response %d bytes: %x", len(resp), resp)

	if parsed, perr := parseAttributes(resp); perr != nil {
		log.Printf("[packet] response did not parse as well-formed RADIUS attributes: %v", perr)
	} else if verbose {
		log.Printf("[packet] parsed response:\n%s", formatParsedResponse(resp, parsed))
	}

	if isTimeoutResponse(sc.Response) {
		return fmt.Errorf("expected no response (Timeout), but got a %d-byte response", len(resp))
	}

	if len(resp) == 0 {
		if sc.Response != "" {
			return fmt.Errorf("empty response, cannot check expected response %s", sc.Response)
		}
		return nil
	}
	return checkExpectedResponse(sc.Response, resp[0])
}
