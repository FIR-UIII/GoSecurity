package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"layeh.com/radius"
)

// EAP codes (RFC 3748)
const (
	eapResponse byte = 2
	eapSuccess  byte = 3
	eapFailure  byte = 4
)

// EAP types
const (
	eapTypeIdentity byte = 1
	eapTypeMD5      byte = 4
)

const (
	attrUserName     = 1
	attrUserPassword = 2
	attrState        = 24
	attrEAPMessage   = 79
)

// stringSlice implements flag.Value to accept a flag multiple times, used
// for repeatable -attr specs.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func newAuthenticator() [16]byte {
	var a [16]byte
	if _, err := rand.Read(a[:]); err != nil {
		panic(err)
	}
	return a
}

func randomID() byte {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return b[0]
}

func buildEAP(code, id byte, body []byte) []byte {
	pkt := make([]byte, 4+len(body))
	pkt[0] = code
	pkt[1] = id
	l := uint16(len(pkt))
	pkt[2] = byte(l >> 8)
	pkt[3] = byte(l)
	copy(pkt[4:], body)
	return pkt
}

func findAttr(attrs []decodedAttr, typ byte) ([]byte, bool) {
	for _, a := range attrs {
		if a.Type == typ && a.Malformed == "" {
			return a.Value, true
		}
	}
	return nil, false
}

// exchangeVerbose sends raw to addr, always logging the request and, if one
// arrives, the response in full scapy-style detail. Used by the single-shot
// (non-fuzz) test modes, where every packet matters.
func exchangeVerbose(ctx context.Context, addr string, raw []byte, timeout time.Duration) ([]byte, error) {
	dumpPacket("to server", raw)
	resp, rtt, err := exchangeRaw(ctx, addr, raw, timeout)
	if err != nil {
		return nil, err
	}
	log.Printf("received response in %s", rtt)
	dumpPacket("from server", resp)
	return resp, nil
}

// buildPAPPacket builds an Access-Request using PAP (User-Password).
func buildPAPPacket(secret, username, password string) (RawPacket, error) {
	p := RawPacket{
		Code:           byte(radius.CodeAccessRequest),
		ID:             randomID(),
		Authenticator:  newAuthenticator(),
		LengthOverride: -1,
	}
	encPass, err := radius.NewUserPassword([]byte(password), []byte(secret), p.Authenticator[:])
	if err != nil {
		return RawPacket{}, fmt.Errorf("encrypt User-Password: %w", err)
	}
	p.Attrs = []AttrSpec{
		{Type: attrUserName, Value: []byte(username), LenOverride: -1},
		{Type: attrUserPassword, Value: encPass, LenOverride: -1},
	}
	return p, nil
}

// testPAP sends a single Access-Request using PAP and returns the response code.
func testPAP(ctx context.Context, addr, secret, username, password string, timeout time.Duration) (byte, error) {
	pkt, err := buildPAPPacket(secret, username, password)
	if err != nil {
		return 0, err
	}
	resp, err := exchangeVerbose(ctx, addr, pkt.Build(), timeout)
	if err != nil {
		return 0, err
	}
	return resp[0], nil
}

// testEAPMD5 performs the two-round EAP-MD5 exchange.
func testEAPMD5(ctx context.Context, addr, secret, username, password string, timeout time.Duration) (byte, error) {
	// Round 1: EAP-Response/Identity
	identBody := make([]byte, 1+len(username))
	identBody[0] = eapTypeIdentity
	copy(identBody[1:], username)

	p1 := RawPacket{
		Code:           byte(radius.CodeAccessRequest),
		ID:             randomID(),
		Authenticator:  newAuthenticator(),
		LengthOverride: -1,
		Attrs: []AttrSpec{
			{Type: attrUserName, Value: []byte(username), LenOverride: -1},
			{Type: attrEAPMessage, Value: buildEAP(eapResponse, 1, identBody), LenOverride: -1},
		},
	}

	resp1, err := exchangeVerbose(ctx, addr, p1.Build(), timeout)
	if err != nil {
		return 0, err
	}
	if resp1[0] != byte(radius.CodeAccessChallenge) {
		return resp1[0], fmt.Errorf("expected Access-Challenge, got code %d", resp1[0])
	}

	declaredLen := int(resp1[2])<<8 | int(resp1[3])
	body := resp1[20:]
	if declaredLen >= 20 && declaredLen <= len(resp1) {
		body = resp1[20:declaredLen]
	}
	attrs := decodeAttrs(body)

	eapChal, ok := findAttr(attrs, attrEAPMessage)
	if !ok || len(eapChal) < 7 || eapChal[4] != eapTypeMD5 {
		return 0, fmt.Errorf("unexpected EAP challenge format")
	}
	chalID := eapChal[1]
	valueSize := int(eapChal[5])
	if len(eapChal) < 6+valueSize {
		return 0, fmt.Errorf("EAP challenge truncated: need %d bytes, have %d", 6+valueSize, len(eapChal))
	}
	chalValue := eapChal[6 : 6+valueSize]

	// RFC 3748 §5.4: MD5(ID || password || challenge)
	h := md5.New()
	h.Write([]byte{chalID})
	h.Write([]byte(password))
	h.Write(chalValue)
	hash := h.Sum(nil)

	md5Body := make([]byte, 2+len(hash))
	md5Body[0] = eapTypeMD5
	md5Body[1] = byte(len(hash))
	copy(md5Body[2:], hash)

	p2 := RawPacket{
		Code:           byte(radius.CodeAccessRequest),
		ID:             randomID(),
		Authenticator:  newAuthenticator(),
		LengthOverride: -1,
		Attrs: []AttrSpec{
			{Type: attrUserName, Value: []byte(username), LenOverride: -1},
			{Type: attrEAPMessage, Value: buildEAP(eapResponse, chalID, md5Body), LenOverride: -1},
		},
	}
	if state, ok := findAttr(attrs, attrState); ok {
		p2.Attrs = append(p2.Attrs, AttrSpec{Type: attrState, Value: state, LenOverride: -1})
	}

	resp2, err := exchangeVerbose(ctx, addr, p2.Build(), timeout)
	if err != nil {
		return 0, err
	}

	if len(resp2) > 20 {
		declaredLen2 := int(resp2[2])<<8 | int(resp2[3])
		body2 := resp2[20:]
		if declaredLen2 >= 20 && declaredLen2 <= len(resp2) {
			body2 = resp2[20:declaredLen2]
		}
		if eapFinal, ok := findAttr(decodeAttrs(body2), attrEAPMessage); ok && len(eapFinal) >= 1 {
			switch eapFinal[0] {
			case eapSuccess:
				log.Println("EAP result: SUCCESS")
			case eapFailure:
				log.Println("EAP result: FAILURE")
			}
		}
	}
	return resp2[0], nil
}

// buildRawPacketFromFlags constructs a fully custom RADIUS packet from the
// -code/-id/-attr flags, for the "raw" and "fuzz" modes.
func buildRawPacketFromFlags(codeStr, secret string, id int, attrSpecs []string) (RawPacket, error) {
	code, err := codeByName(codeStr)
	if err != nil {
		return RawPacket{}, err
	}
	p := RawPacket{
		Code:           code,
		ID:             randomID(),
		Authenticator:  newAuthenticator(),
		LengthOverride: -1,
	}
	if id >= 0 {
		p.ID = byte(id)
	}
	for _, spec := range attrSpecs {
		a, err := parseAttrSpec(spec, secret, p.Authenticator)
		if err != nil {
			return RawPacket{}, err
		}
		p.Attrs = append(p.Attrs, a)
	}
	return p, nil
}

func main() {
	addr := flag.String("addr", "localhost:1812", "RADIUS server address (host:port)")
	secret := flag.String("secret", "secret", "shared secret")
	username := flag.String("user", "art", "username")
	password := flag.String("pass", "12345", "password")
	mode := flag.String("mode", "eap-md5", "test mode: pap | eap-md5 | raw | fuzz")
	expect := flag.String("expect", "accept", "expected outcome for single modes: accept | reject | challenge | any")
	timeout := flag.Duration("timeout", 5*time.Second, "per-exchange timeout")

	// raw / fuzz base packet construction
	code := flag.String("code", "Access-Request", "RADIUS code for raw/fuzz mode (name or number)")
	id := flag.Int("id", -1, "packet identifier for raw/fuzz mode (-1 = random)")
	var attrSpecs stringSlice
	flag.Var(&attrSpecs, "attr", "attribute spec 'type=kind:value[;len=N]', repeatable (kind: str|int|ip|hex|pwd)")

	// fuzz-only options
	fuzzIterations := flag.Int("fuzz-iterations", 100, "number of mutated packets to send in fuzz mode")
	fuzzSeed := flag.Int64("fuzz-seed", time.Now().UnixNano(), "PRNG seed for fuzz mode (fixed value => reproducible run)")
	fuzzVerbose := flag.Bool("fuzz-verbose", false, "dump every packet in fuzz mode instead of only interesting ones")
	fuzzDelay := flag.Duration("fuzz-delay", 0, "delay between fuzz iterations")
	fuzzBase := flag.String("fuzz-base", "pap", "base packet to mutate in fuzz mode: pap | attrs (use -code/-attr)")

	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	switch *mode {
	case "pap", "eap-md5":
		var respCode byte
		var err error
		if *mode == "pap" {
			respCode, err = testPAP(ctx, *addr, *secret, *username, *password, *timeout)
		} else {
			respCode, err = testEAPMD5(ctx, *addr, *secret, *username, *password, *timeout)
		}
		if err != nil {
			log.Fatalf("exchange error: %v", err)
		}
		checkExpectation(respCode, *expect)

	case "raw":
		pkt, err := buildRawPacketFromFlags(*code, *secret, *id, attrSpecs)
		if err != nil {
			log.Fatalf("build packet: %v", err)
		}
		resp, err := exchangeVerbose(ctx, *addr, pkt.Build(), *timeout)
		if err != nil {
			log.Fatalf("exchange error: %v", err)
		}
		checkExpectation(resp[0], *expect)

	case "fuzz":
		var base RawPacket
		var err error
		switch *fuzzBase {
		case "pap":
			base, err = buildPAPPacket(*secret, *username, *password)
		case "attrs":
			base, err = buildRawPacketFromFlags(*code, *secret, *id, attrSpecs)
		default:
			log.Fatalf("unknown -fuzz-base %q (supported: pap, attrs)", *fuzzBase)
		}
		if err != nil {
			log.Fatalf("build base packet: %v", err)
		}
		opts := fuzzOptions{
			Addr:       *addr,
			Iterations: *fuzzIterations,
			Seed:       *fuzzSeed,
			Timeout:    *timeout,
			Verbose:    *fuzzVerbose,
			Delay:      *fuzzDelay,
		}
		if err := runFuzz(context.Background(), base, opts); err != nil {
			log.Fatalf("fuzz error: %v", err)
		}
		return

	default:
		log.Fatalf("unknown mode %q (supported: pap, eap-md5, raw, fuzz)", *mode)
	}
}

// checkExpectation maps a RADIUS code to an outcome string and exits
// non-zero if it doesn't match -expect (unless -expect=any).
func checkExpectation(code byte, expect string) {
	if expect == "any" {
		log.Printf("code=%d (no expectation checked)", code)
		return
	}
	var got string
	switch radius.Code(code) {
	case radius.CodeAccessAccept:
		got = "accept"
	case radius.CodeAccessReject:
		got = "reject"
	case radius.CodeAccessChallenge:
		got = "challenge"
	default:
		got = radius.Code(code).String()
	}
	if got != expect {
		log.Printf("FAIL: expected=%q got=%q", expect, got)
		os.Exit(1)
	}
	log.Printf("PASS: expected=%q got=%q", expect, got)
}
