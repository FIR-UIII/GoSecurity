package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
)

// Attribute представляет структуру RADIUS TLV
type Attribute struct {
	Type  byte
	Value []byte
}

// parseAttributes разбирает атрибуты из ответа сервера
func parseAttributes(rawPacket []byte) ([]Attribute, error) {
	if len(rawPacket) < 20 {
		return nil, fmt.Errorf("packet too short")
	}

	totalLen := int(binary.BigEndian.Uint16(rawPacket[2:4]))
	if totalLen < 20 {
		return nil, fmt.Errorf("declared length %d is shorter than the RADIUS header", totalLen)
	}
	if len(rawPacket) < totalLen {
		return nil, fmt.Errorf("buffer smaller than declared length")
	}

	attrBytes := rawPacket[20:totalLen]
	var attrs []Attribute
	i := 0

	for i < len(attrBytes) {
		if len(attrBytes)-i < 2 {
			break
		}
		typ := attrBytes[i]
		length := int(attrBytes[i+1])

		if length < 2 || i+length > len(attrBytes) {
			return nil, fmt.Errorf("invalid attribute length %d for type %d", length, typ)
		}

		val := make([]byte, length-2)
		copy(val, attrBytes[i+2:i+length])

		attrs = append(attrs, Attribute{Type: typ, Value: val})
		i += length
	}

	return attrs, nil
}

// formatParsedResponse renders resp's header fields and its already-parsed
// attrs as a multi-line human-readable dump — the raw/packet scenario
// types' log.Printf("... parsed response:\n%s", ...) is a much easier read
// than the previous single-line Go %v dump of []Attribute, especially for
// responses carrying several attributes. Callers must have already
// confirmed resp parses (e.g. via a successful parseAttributes(resp) call
// whose result is passed in as attrs).
func formatParsedResponse(resp []byte, attrs []Attribute) string {
	var b strings.Builder
	code := resp[0]
	fmt.Fprintf(&b, "code: %02x (%s)\n", code, radiusCodeName(code))
	fmt.Fprintf(&b, "Identifier: %02x\n", resp[1])
	fmt.Fprintf(&b, "Length: %04x\n", binary.BigEndian.Uint16(resp[2:4]))
	fmt.Fprintf(&b, "Response Authenticator: %x\n", resp[4:20])
	b.WriteString("Attributes:")
	if len(attrs) == 0 {
		b.WriteString(" (none)")
		return b.String()
	}
	for _, a := range attrs {
		fmt.Fprintf(&b, "\n  type: %s, len: %d, value: %x", attrName(a.Type), len(a.Value)+2, a.Value)
		if isPrintableASCII(a.Value) {
			fmt.Fprintf(&b, " (%q)", string(a.Value))
		}
	}
	return b.String()
}

// isPrintableASCII reports whether every byte in v is printable
// (non-empty, no control characters, no bytes above 0x7e) — used by
// formatParsedResponse to also show a text rendering alongside the hex
// dump for attributes like Reply-Message that are typically plain text.
func isPrintableASCII(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// verifyResponseAuth проверяет, что ответ подписан верным Shared Secret
func verifyResponseAuth(response, reqAuth []byte, secret string) bool {
	if len(response) < 20 {
		return false
	}
	totalLen := int(binary.BigEndian.Uint16(response[2:4]))
	if totalLen < 20 || len(response) < totalLen {
		return false
	}
	h := md5.New()
	h.Write(response[0:4])         // Code, ID, Length
	h.Write(reqAuth)               // Request Authenticator
	h.Write(response[20:totalLen]) // Attributes only (not any trailing bytes)
	h.Write([]byte(secret))        // Secret
	return bytes.Equal(response[4:20], h.Sum(nil))
}
