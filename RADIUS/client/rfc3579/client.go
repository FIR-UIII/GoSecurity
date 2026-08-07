package main

import (
	"context"
	"crypto/md5"
	"log"

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
	return pkt
}

func main() {
	const (
		username = "art"
		password = "12345"
		secret   = "secret"
		addr     = "localhost:1812"
	)

	// ── Round 1: send EAP-Response/Identity ──────────────────────────────────
	identBody := append([]byte{eapTypeIdentity}, []byte(username)...)
	pkt1 := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2869.EAPMessage_Set(pkt1, buildEAP(eapResponse, 1, identBody))

	log.Printf("→ Access-Request  EAP-Response/Identity  user=%q", username)
	chalPkt, err := radius.Exchange(context.Background(), pkt1, addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("← %v", chalPkt.Code)

	if chalPkt.Code != radius.CodeAccessChallenge {
		log.Fatalf("expected Access-Challenge, got %v", chalPkt.Code)
	}

	// Parse EAP-Request/MD5-Challenge
	// layout: [code=1, id, lenHi, lenLo, type=4, valueSize(16), value(16), name...]
	eapChal := rfc2869.EAPMessage_Get(chalPkt)
	if len(eapChal) < 22 || eapChal[4] != eapTypeMD5 {
		log.Fatal("unexpected EAP challenge format")
	}
	chalID := eapChal[1]
	valueSize := int(eapChal[5])
	chalValue := eapChal[6 : 6+valueSize]

	// RFC 3748 §5.4: MD5(ID || password || challenge)
	h := md5.New()
	h.Write([]byte{chalID})
	h.Write([]byte(password))
	h.Write(chalValue)
	hash := h.Sum(nil)

	// ── Round 2: send EAP-Response/MD5 ───────────────────────────────────────
	md5Body := append([]byte{eapTypeMD5, 16}, hash...)
	pkt2 := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2869.EAPMessage_Set(pkt2, buildEAP(eapResponse, chalID, md5Body))
	rfc2865.State_Set(pkt2, rfc2865.State_Get(chalPkt)) // echo State back

	log.Printf("→ Access-Request  EAP-Response/MD5  eapID=%d", chalID)
	result, err := radius.Exchange(context.Background(), pkt2, addr)
	if err != nil {
		log.Fatal(err)
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
}
