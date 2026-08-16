package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"layeh.com/radius"
)

// decodedAttr is a best-effort, tolerant parse of a single attribute from a
// raw byte stream. Unlike radius.ParseAttributes, it never returns an error:
// malformed attributes (bad length bytes, truncated values) are reported as
// such instead of aborting the whole parse, since a fuzzer must be able to
// print whatever garbage the server sends back.
type decodedAttr struct {
	Type      byte
	Declared  int // length byte as found on the wire
	Value     []byte
	Malformed string // non-empty if the attribute looked corrupt
}

func decodeAttrs(b []byte) []decodedAttr {
	var out []decodedAttr
	for len(b) > 0 {
		if len(b) < 2 {
			out = append(out, decodedAttr{Malformed: fmt.Sprintf("%d trailing byte(s), too short for a header", len(b))})
			return out
		}
		typ := b[0]
		declared := int(b[1])
		switch {
		case declared < 2:
			out = append(out, decodedAttr{Type: typ, Declared: declared, Malformed: "length byte < 2"})
			return out
		case declared > len(b):
			out = append(out, decodedAttr{Type: typ, Declared: declared, Value: b[2:], Malformed: fmt.Sprintf("length byte %d exceeds remaining %d byte(s)", declared, len(b))})
			return out
		default:
			out = append(out, decodedAttr{Type: typ, Declared: declared, Value: b[2:declared]})
			b = b[declared:]
		}
	}
	return out
}

// formatValue renders an attribute value the way scapy's ls()/show() does:
// printable payloads are shown as a Python byte-string literal, everything
// else falls back to hex.
func formatValue(v []byte) string {
	printable := len(v) > 0
	for _, c := range v {
		if c < 0x20 || c > 0x7e {
			printable = false
			break
		}
	}
	if printable {
		return fmt.Sprintf("b'%s'", string(v))
	}
	return hex.EncodeToString(v)
}

// dumpPacket prints a packet in a scapy-inspired layout:
//
//	raw RADIUS packet to server (43 bytes):
//	0186002b...
//	decoded:
//	  code      = Access-Request
//	  id        = 134
//	  len       = 43
//	  authenticator= 996465612f9e31c504089099aa86e8aa
//	  \attributes\
//	   |###[ User-Name ]###
//	   |  type      = User-Name
//	   |  len       = 5
//	   |  value     = b'art'
func dumpPacket(direction string, raw []byte) {
	fmt.Printf("raw RADIUS packet %s (%d bytes):\n", direction, len(raw))
	fmt.Println(hex.EncodeToString(raw))

	if len(raw) < 20 {
		fmt.Printf("decoded: <too short to be a valid RADIUS header (%d bytes)>\n\n", len(raw))
		return
	}

	code := radius.Code(raw[0])
	id := raw[1]
	declaredLen := int(raw[2])<<8 | int(raw[3])
	auth := raw[4:20]

	fmt.Println("decoded:")
	fmt.Printf("  code      = %s\n", code)
	fmt.Printf("  id        = %d\n", id)
	fmt.Printf("  len       = %d\n", declaredLen)
	fmt.Printf("  authenticator= %s\n", hex.EncodeToString(auth))

	body := raw[20:]
	if declaredLen >= 20 && declaredLen <= len(raw) {
		body = raw[20:declaredLen]
	}

	attrs := decodeAttrs(body)
	if len(attrs) == 0 {
		fmt.Println("  \\attributes\\ <none>")
		fmt.Println()
		return
	}

	fmt.Println("  \\attributes\\")
	for _, a := range attrs {
		if a.Malformed != "" {
			fmt.Printf("   |###[ Malformed attribute ]###\n")
			fmt.Printf("   |  type      = %d (%s)\n", a.Type, attrName(a.Type))
			fmt.Printf("   |  declared-len = %d\n", a.Declared)
			fmt.Printf("   |  reason    = %s\n", a.Malformed)
			if len(a.Value) > 0 {
				fmt.Printf("   |  value     = %s\n", formatValue(a.Value))
			}
			continue
		}
		fmt.Printf("   |###[ %s ]###\n", attrName(a.Type))
		fmt.Printf("   |  type      = %s\n", attrName(a.Type))
		fmt.Printf("   |  len       = %d\n", a.Declared)
		fmt.Printf("   |  value     = %s\n", formatValue(a.Value))
	}
	fmt.Println()
}

// summarizeAttrs returns a compact single-line description of a packet's
// attributes, used for the non-verbose fuzzing log.
func summarizeAttrs(attrs []AttrSpec) string {
	parts := make([]string, len(attrs))
	for i, a := range attrs {
		parts[i] = fmt.Sprintf("%s(%d)", attrName(a.Type), len(a.Value))
	}
	return strings.Join(parts, ", ")
}
