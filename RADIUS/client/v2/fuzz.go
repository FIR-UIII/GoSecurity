package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// fuzzCase is one parsed line from a fuzz.txt wordlist: "attr:value".
type fuzzCase struct {
	Line  int    // 1-based source line number, for logging
	Attr  byte
	Value []byte
	Raw   string // original line text, for error/summary logging
}

// loadFuzzFile reads path, skipping blank lines and '#' comments, and
// parses each remaining line as "attr:value" (split on the first ':' only,
// so a hex:... value can't be mis-split).
func loadFuzzFile(path string) ([]fuzzCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var cases []fuzzCase
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			return nil, fmt.Errorf("%s:%d: expected \"attr:value\", got %q", path, lineNo, line)
		}
		attrTok, valTok := line[:idx], line[idx+1:]

		attr, err := resolveAttrType(attrTok)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		val, err := parseFuzzValue(valTok)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		cases = append(cases, fuzzCase{Line: lineNo, Attr: attr, Value: val, Raw: line})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s: no fuzz cases found", path)
	}
	return cases, nil
}

// parseFuzzValue interprets the part of a fuzz.txt line after the first ':'
// as hex:<hexstring> (raw/binary/invalid bytes) or, otherwise, a literal
// UTF-8 string.
func parseFuzzValue(s string) ([]byte, error) {
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
// erroring or truncating value — an oversized fuzz value is itself a valid,
// intentional test case (Length lying about actual payload size). A warning
// is logged so the wrap is visible in run output.
func appendAttr(attrs []byte, typ byte, value []byte) []byte {
	if 2+len(value) > 255 {
		log.Printf("[fuzz] warning: attr %d (%s) value is %d bytes; length byte wraps to %d",
			typ, attrName(typ), len(value), byte(2+len(value)))
	}
	attrs = append(attrs, typ, byte(2+len(value)))
	attrs = append(attrs, value...)
	return attrs
}

// replaceAttrIfPresent walks the flat attrs TLV stream looking for an
// attribute whose Type matches typ; if found, it splices in a
// newly-encoded Type|Length|Value (via appendAttr's length-wrap rules) in
// its place and returns the rebuilt stream with replaced=true. If no match
// is found, attrs is returned unchanged with replaced=false.
func replaceAttrIfPresent(attrs []byte, typ byte, value []byte) (out []byte, replaced bool) {
	i := 0
	for i < len(attrs) {
		if len(attrs)-i < 2 {
			break
		}
		t := attrs[i]
		length := int(attrs[i+1])
		if length < 2 || i+length > len(attrs) {
			// Malformed seed stream shouldn't happen (we build it
			// ourselves), but bail out defensively rather than looping
			// forever or panicking on a slice out-of-range.
			break
		}
		if t == typ {
			out = append(out, attrs[:i]...)
			out = appendAttr(out, typ, value)
			out = append(out, attrs[i+length:]...)
			return out, true
		}
		i += length
	}
	return attrs, false
}

// buildFuzzedPAPPacket builds a seed PAP attrs stream (User-Name +
// PAP-encrypted User-Password from username/password), then either
// replaces the seed attribute whose Type == fc.Attr (letting a fuzz case
// inject raw/malformed bytes straight into User-Name or User-Password,
// bypassing normal PAP encryption), or appends fc as a new attribute
// alongside the valid credentials. Framing (Length, Message-Authenticator)
// is recomputed afterward via buildRadiusPacket.
func buildFuzzedPAPPacket(secret, username, password string, fc fuzzCase) ([]byte, []byte, error) {
	authenticator := make([]byte, 16)
	if _, err := rand.Read(authenticator); err != nil {
		return nil, nil, fmt.Errorf("generate authenticator: %w", err)
	}
	encPassword := encryptPAP(password, secret, authenticator)

	var attrs []byte
	attrs = appendAttr(attrs, 1, []byte(username))
	attrs = appendAttr(attrs, 2, encPassword)

	if out, replaced := replaceAttrIfPresent(attrs, fc.Attr, fc.Value); replaced {
		attrs = out
	} else {
		attrs = appendAttr(attrs, fc.Attr, fc.Value)
	}

	return buildRadiusPacket(secret, 1, nil, authenticator, attrs, true)
}

// sendUDPFireAndForget dials addr, writes pkt once, and closes — with no
// read/wait for a response. Used for the post-response duplicate-datagram
// probe in runFuzzScenario.
func sendUDPFireAndForget(addr string, pkt []byte) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// runFuzzScenario loads fuzzFile, sends a fuzzed request for each case in
// order (logging the response, or logging-and-continuing on error/timeout —
// a fuzzed packet failing is often the expected/interesting result, not a
// tool bug), then fires postResponseDatagrams fire-and-forget copies of
// that same datagram before moving to the next case. Ends with a one-line
// summary.
func runFuzzScenario(addr, secret string, timeout time.Duration, username, password, fuzzFile string, postResponseDatagrams int) error {
	cases, err := loadFuzzFile(fuzzFile)
	if err != nil {
		return err
	}
	log.Printf("[fuzz] loaded %d case(s) from %s", len(cases), fuzzFile)

	var errCount, unexpectedCount int
	for _, fc := range cases {
		pkt, _, err := buildFuzzedPAPPacket(secret, username, password, fc)
		if err != nil {
			errCount++
			log.Printf("[fuzz #%d] build failed for %q: %v", fc.Line, fc.Raw, err)
			continue
		}
		log.Printf("[fuzz #%d] case=%q sending %d bytes: %x", fc.Line, fc.Raw, len(pkt), pkt)

		resp, err := sendRawUDP(addr, pkt, timeout)
		if err != nil {
			errCount++
			log.Printf("[fuzz #%d] case=%q -> ERROR: %v", fc.Line, fc.Raw, err)
		} else {
			log.Printf("[fuzz #%d] case=%q response %d bytes: %x", fc.Line, fc.Raw, len(resp), resp)
			if len(resp) > 0 && resp[0] != 2 && resp[0] != 3 && resp[0] != 11 {
				unexpectedCount++
				log.Printf("[fuzz #%d] case=%q unexpected response code %d", fc.Line, fc.Raw, resp[0])
			}
		}

		for i := 0; i < postResponseDatagrams; i++ {
			if ferr := sendUDPFireAndForget(addr, pkt); ferr != nil {
				log.Printf("[fuzz #%d] post-response datagram %d/%d failed: %v", fc.Line, i+1, postResponseDatagrams, ferr)
			}
		}
		if postResponseDatagrams > 0 {
			log.Printf("[fuzz #%d] fired %d post-response datagram(s)", fc.Line, postResponseDatagrams)
		}
	}

	log.Printf("[fuzz] done: %d case(s), %d error(s)/timeout(s), %d unexpected response code(s)",
		len(cases), errCount, unexpectedCount)
	return nil
}
