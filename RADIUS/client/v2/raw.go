package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode"
)

// runRawScenario decodes packetHex into a complete raw RADIUS packet and
// sends it over UDP byte-for-byte, entirely outside the normal packet
// encoder — for testing malformed/malicious packets the encoder can't
// produce (bad lengths, bad codes, garbage, etc.).
//
// It deliberately does NOT go through exchange() (pap.go), which enforces
// response-authenticator/Message-Authenticator checks: those checks are
// expected to legitimately fail against a hand-crafted request, and that
// failure is itself a valid, interesting result for this scenario type, not
// an error to abort on. If expectedResponse is non-empty, the response's
// Code byte is checked against it (see checkExpectedResponse in packet.go).
func runRawScenario(addr string, timeout time.Duration, packetHex, expectedResponse string) error {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, packetHex)

	raw, err := hex.DecodeString(clean)
	if err != nil {
		return fmt.Errorf("decode packet_hex: %w", err)
	}
	log.Printf("[raw] sending %d bytes: %x", len(raw), raw)

	resp, err := sendRawUDP(addr, raw, timeout)
	if err != nil {
		return fmt.Errorf("network: %w", err)
	}
	log.Printf("[raw] response %d bytes: %x", len(resp), resp)

	if attrs, perr := parseAttributes(resp); perr != nil {
		log.Printf("[raw] response did not parse as well-formed RADIUS attributes: %v", perr)
	} else {
		log.Printf("[raw] parsed response attributes: %v", attrs)
	}

	if len(resp) == 0 {
		if expectedResponse != "" {
			return fmt.Errorf("empty response, cannot check expected response %s", expectedResponse)
		}
		return nil
	}
	return checkExpectedResponse(expectedResponse, resp[0])
}
