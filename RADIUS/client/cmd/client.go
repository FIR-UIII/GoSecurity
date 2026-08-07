package main

import (
	"context"
	"crypto/md5"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// EAP codes (RFC 3748)
const (
	eapRequest  byte = 1
	eapResponse byte = 2
	eapSuccess  byte = 3
	eapFailure  byte = 4
)

// EAP types
const (
	eapTypeIdentity byte = 1
	eapTypeMD5      byte = 4
)

func buildEAP(code, id byte, body []byte) []byte {
	pkt := make([]byte, 4+len(body))
	pkt[0] = code
	pkt[1] = id
	l := uint16(len(pkt))
	pkt[2] = byte(l >> 8)
	pkt[3] = byte(l)
	copy(pkt[4:], body)
	fmt.Printf("[DEBUG] buildEAP: code=%d id=%d len=%d body=%x\n", code, id, l, body)
	return pkt
}

// testPAP sends a single Access-Request using PAP (User-Password attribute).
func testPAP(ctx context.Context, addr, secret, username, password string) (radius.Code, error) {
	pkt := radius.New(radius.CodeAccessRequest, []byte(secret))           // create Access-Request to the RADIUS server
	rfc2865.UserName_SetString(pkt, username)                             // set User-Name attribute
	if err := rfc2865.UserPassword_SetString(pkt, password); err != nil { // set User-Password attribute
		return 0, fmt.Errorf("UserPassword_Set: %w", err)
	}
	log.Printf("[DEBUG] -> Access-Request to server pkt=%+v  user=%q  addr=%s", pkt, username, addr)

	// Marshal the packet to raw bytes for logging
	raw, err := pkt.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("marshal radius packet: %w", err)
	}
	log.Printf("[DEBUG] -> raw RADIUS packet to server (%d bytes):\n%x\n", len(raw), raw)

	resp, err := radius.Exchange(ctx, pkt, addr) // send the request and wait for response
	if err != nil {
		return 0, err
	}
	log.Printf("[DEBUG] <- Access-Response from server=%v", resp)
	return resp.Code, nil
}

// testEAPMD5 performs the two-round EAP-MD5 exchange.
func testEAPMD5(ctx context.Context, addr, secret, username, password string) (radius.Code, error) {
	// Round 1: EAP-Response/Identity
	identBody := make([]byte, 1+len(username))
	identBody[0] = eapTypeIdentity
	copy(identBody[1:], username)

	pkt1 := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2865.UserName_SetString(pkt1, username)
	rfc2869.EAPMessage_Set(pkt1, buildEAP(eapResponse, 1, identBody))

	log.Printf("[DEBUG] Access-Request (EAP-Response/Identity)  pkt=%+v  user=%q  addr=%s", pkt1, username, addr)
	chalPkt, err := radius.Exchange(ctx, pkt1, addr)
	if err != nil {
		return 0, err
	}
	log.Printf("[DEBUG] received Access-Challenge  code=%v", chalPkt.Code)

	if chalPkt.Code != radius.CodeAccessChallenge {
		return chalPkt.Code, fmt.Errorf("expected Access-Challenge, got %v", chalPkt.Code)
	}

	// Parse EAP-Request/MD5-Challenge
	// layout: [code=1, id, lenHi, lenLo, type=4, valueSize, value(valueSize), name...]
	eapChal := rfc2869.EAPMessage_Get(chalPkt)
	if len(eapChal) < 7 || eapChal[4] != eapTypeMD5 {
		return 0, fmt.Errorf("unexpected EAP challenge format (len=%d)", len(eapChal))
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

	// Round 2: EAP-Response/MD5
	md5Body := make([]byte, 2+len(hash))
	md5Body[0] = eapTypeMD5
	md5Body[1] = byte(len(hash))
	copy(md5Body[2:], hash)

	pkt2 := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2865.UserName_SetString(pkt2, username)
	rfc2869.EAPMessage_Set(pkt2, buildEAP(eapResponse, chalID, md5Body))
	rfc2865.State_Set(pkt2, rfc2865.State_Get(chalPkt)) // echo State back

	log.Printf("Access-Request (EAP-Response/MD5)  eapID=%d", chalID)
	result, err := radius.Exchange(ctx, pkt2, addr)
	if err != nil {
		return 0, err
	}
	log.Printf("← %v", result.Code)

	eapFinal := rfc2869.EAPMessage_Get(result)
	if len(eapFinal) >= 1 {
		switch eapFinal[0] {
		case eapSuccess:
			log.Println("EAP result: SUCCESS")
		case eapFailure:
			log.Println("EAP result: FAILURE")
		}
	}
	return result.Code, nil
}

func main() {
	addr := flag.String("addr", "localhost:1812", "RADIUS server address (host:port)")
	secret := flag.String("secret", "secret", "shared secret")
	username := flag.String("user", "art", "username")
	password := flag.String("pass", "12345", "password")
	mode := flag.String("mode", "eap-md5", "auth mode: pap | eap-md5")
	expect := flag.String("expect", "accept", "expected outcome: accept | reject | challenge")
	timeout := flag.Duration("timeout", 5*time.Second, "per-exchange timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var (
		code radius.Code
		err  error
	)
	switch *mode {
	case "pap":
		code, err = testPAP(ctx, *addr, *secret, *username, *password)
	case "eap-md5":
		code, err = testEAPMD5(ctx, *addr, *secret, *username, *password)
	default:
		log.Fatalf("unknown mode %q (supported: pap, eap-md5)", *mode)
	}
	if err != nil {
		log.Fatalf("exchange error: %v", err)
	}

	// Map RADIUS code to outcome string for assertion
	var got string
	switch code {
	case radius.CodeAccessAccept:
		got = "accept"
	case radius.CodeAccessReject:
		got = "reject"
	case radius.CodeAccessChallenge:
		got = "challenge"
	default:
		got = code.String()
	}

	if got != *expect {
		log.Printf("FAIL: expected=%q  got=%q", *expect, got)
		os.Exit(1)
	}
	log.Printf("PASS: expected=%q  got=%q", *expect, got)
}
