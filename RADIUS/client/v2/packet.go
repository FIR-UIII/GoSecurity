package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// radiusCodeNames maps well-known RADIUS Code values to names (RFC 2865/
// 2866), for a "packet" scenario's code: field.
var radiusCodeNames = map[string]byte{
	"access-request":      1,
	"access-accept":       2,
	"access-reject":       3,
	"accounting-request":  4,
	"accounting-response": 5,
	"access-challenge":    11,
	"status-server":       12,
	"status-client":       13,
}

// resolveRadiusCode parses a "packet" scenario's code field: empty means
// the default (1, Access-Request), a plain integer (0-255) is used
// directly, otherwise the token is looked up case-insensitively by name.
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

// appendAttrSpec resolves spec's Type/Value and appends the resulting TLV
// to attrs. If spec.Length is set, it's used as the literal Length byte
// even if it doesn't match len(value) — deliberately allowing malformed
// lengths, since that's a legitimate thing to want full manual control
// over here. Otherwise it falls back to appendAttr's default 2+len(value)
// encoding (including its oversized-value wrap warning).
func appendAttrSpec(attrs []byte, spec AttrSpec) ([]byte, error) {
	typ, err := resolveAttrType(spec.Type)
	if err != nil {
		return nil, err
	}
	val, err := parseFuzzValue(spec.Value)
	if err != nil {
		return nil, err
	}
	if spec.Length != nil {
		attrs = append(attrs, typ, byte(*spec.Length))
		attrs = append(attrs, val...)
		return attrs, nil
	}
	return appendAttr(attrs, typ, val), nil
}

// runPacketScenario builds a single RADIUS packet entirely from sc's
// explicit code/id/authenticator/attrs fields. Nothing is ever added
// automatically — in particular, NOT a Message-Authenticator — giving full
// manual control over framing. This is the scenario type to reach for when
// testing how a server handles a request missing something the normal
// encoder would always include, e.g. Message-Authenticator: just leave any
// type-80 entry out of attrs.
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

	var authenticator []byte
	if sc.Authenticator != "" {
		authenticator, err = hex.DecodeString(sc.Authenticator)
		if err != nil {
			return fmt.Errorf("decode authenticator: %w", err)
		}
	} else {
		authenticator = make([]byte, 16)
		if _, err := rand.Read(authenticator); err != nil {
			return fmt.Errorf("generate authenticator: %w", err)
		}
	}

	var attrs []byte
	for i, spec := range sc.Attrs {
		attrs, err = appendAttrSpec(attrs, spec)
		if err != nil {
			return fmt.Errorf("attrs[%d]: %w", i, err)
		}
	}

	pkt, _, err := buildRadiusPacket(secret, code, id, authenticator, attrs, false)
	if err != nil {
		return fmt.Errorf("build packet: %w", err)
	}
	log.Printf("[packet] sending %d bytes: %x", len(pkt), pkt)

	resp, err := sendRawUDP(addr, pkt, timeout)
	if err != nil {
		return fmt.Errorf("network: %w", err)
	}
	log.Printf("[packet] response %d bytes: %x", len(resp), resp)

	parsed, perr := parseAttributes(resp)
	if perr != nil {
		log.Printf("[packet] response did not parse as well-formed RADIUS attributes: %v", perr)
		return nil
	}
	log.Printf("[packet] parsed response attributes: %v", parsed)
	return nil
}
