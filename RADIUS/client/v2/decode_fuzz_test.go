package main

import (
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex literal used as fuzz seed corpus; panics (at test
// setup time, never during a fuzz run itself) on a typo.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// FuzzParseAttributes fuzzes the client's own RADIUS response decoder
// (challenge.go) with arbitrary bytes. parseAttributes only ever parses
// bytes that came off the network (a server's response, or a hand-crafted
// "raw" scenario's response) — untrusted input — so it must never panic
// or hang, no matter how malformed; returning an error is the correct
// outcome for bad input. This is Phase 2 of the RADIUS fuzzing
// methodology: offline, coverage-guided fuzzing of the decoder, as
// opposed to the network-facing structural fuzzer (type: fuzz in
// scenario.go/fuzz.go).
func FuzzParseAttributes(f *testing.F) {
	// raw-example from config.example.yaml: minimal well-formed
	// Access-Request, no attributes.
	f.Add(mustHex("01050014000102030405060708090a0b0c0d0e0f"))
	// truncated-authenticator from config.example.yaml: a Status-Server
	// packet with its 16-byte Authenticator truncated to 15 bytes,
	// shifting every attribute after it left by one byte.
	f.Add(mustHex("0C3B002B000102030405060708090A0B0C0D0E04067F000001501200000000000000000000000000000000"))
	// A synthetic, well-formed Access-Accept (code=2, id=01, length=42)
	// with two attributes: Reply-Message ("hi", type 18) and a 16-byte
	// State (type 24).
	f.Add(mustHex(
		"0201002a" +
			"00112233445566778899aabbccddeeff" +
			"12046869" + "1812" + "000102030405060708090a0b0c0d0e0f"))
	f.Add([]byte{})
	f.Add(make([]byte, 19))                                    // one byte short of the 20-byte header
	f.Add(make([]byte, 20))                                    // exactly a header, Length field reads 0
	f.Add(mustHex("020100140102030405060708090a0b0c0d0e0f10")) // Length(0x0014=20) but 21 actual bytes

	f.Fuzz(func(t *testing.T, data []byte) {
		// The only property under test is "never panics, never hangs";
		// any returned (attrs, err) pair is an acceptable outcome for
		// arbitrary/malformed input.
		_, _ = parseAttributes(data)
	})
}

// FuzzVerifyMessageAuthenticator fuzzes verifyMessageAuthenticator
// (messageAuthenticator.go), which — unlike verifyResponseAuth — does its
// own manual Type/Length walk over the response bytes after calling
// parseAttributes, so it's worth covering directly rather than assuming
// the parseAttributes fuzz target alone exercises it equivalently.
func FuzzVerifyMessageAuthenticator(f *testing.F) {
	reqAuth := make([]byte, 16)
	secret := "MyRadiusSecret123"

	f.Add(mustHex("01050014000102030405060708090a0b0c0d0e0f"), reqAuth, secret)
	f.Add([]byte{}, reqAuth, secret)
	f.Add(make([]byte, 19), reqAuth, secret)

	f.Fuzz(func(t *testing.T, resp []byte, reqAuth []byte, secret string) {
		_ = verifyMessageAuthenticator(resp, reqAuth, secret)
	})
}
