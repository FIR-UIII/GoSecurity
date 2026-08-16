package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"time"
)

// exchange sends req, logs the response, and returns it only after validating
// the response authenticator and (if present) Message-Authenticator.
// It also parses and returns the AVP list so callers don't repeat the pattern.
func exchange(addr, secret string, req, reqAuth []byte, timeout time.Duration) (resp []byte, attrs []Attribute, err error) {
	resp, err = sendRawUDP(addr, req, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("network: %w", err)
	}
	log.Printf("raw packet from server %x", resp)

	if !verifyResponseAuth(resp, reqAuth, secret) {
		return nil, nil, fmt.Errorf("security: invalid response authenticator")
	}
	if !verifyMessageAuthenticator(resp, reqAuth, secret) {
		return nil, nil, fmt.Errorf("security: invalid Message-Authenticator")
	}
	attrs, err = parseAttributes(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("parse attributes: %w", err)
	}
	log.Printf("parsed attributes from server: %v", attrs)
	return resp, attrs, nil
}

func buildPAPPacket(secret, username, password string, state []byte) ([]byte, []byte, error) {
	// 1. Генерируем 16 случайных байт Request Authenticator
	authenticator := make([]byte, 16)
	if _, err := rand.Read(authenticator); err != nil {
		return nil, nil, fmt.Errorf("generate authenticator: %w", err)
	}

	// 2. Шифруем пароль
	encPassword := encryptPAP(password, secret, authenticator)

	// 3. Собираем атрибуты (Type | Length | Value)
	var attrs []byte

	// Attribute: User-Name (Type 1)
	attrs = append(attrs, 1)                     // Type
	attrs = append(attrs, byte(2+len(username))) // Length
	attrs = append(attrs, []byte(username)...)   // Value

	// Attribute: User-Password (Type 2)
	attrs = append(attrs, 2)                        // Type
	attrs = append(attrs, byte(2+len(encPassword))) // Length
	attrs = append(attrs, encPassword...)           // Value

	// State (Type 24) — передаем обратно серверу, если получили его в Access-Challenge
	if len(state) > 0 {
		attrs = append(attrs, 24, byte(2+len(state)))
		attrs = append(attrs, state...)
	}

	// 4. Считаем полную длину кадра (20 байт заголовка + длина атрибутов)
	totalLen := 20 + len(attrs)

	// 5. Собираем итоговый пакет
	pkt := make([]byte, totalLen)
	pkt[0] = 1 // Code: Access-Request

	// Случайный Identifier пакета (1 байт)
	idByte := make([]byte, 1)
	rand.Read(idByte)
	pkt[1] = idByte[0]

	// Length (2 байта, BigEndian)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))

	// Authenticator (16 байт)
	copy(pkt[4:20], authenticator)

	// Attributes
	copy(pkt[20:], attrs)

	finalPkt := addMessageAuthenticator(pkt, secret)

	return finalPkt, authenticator, nil
}

func runPAP(addr, secret, username, password string, timeout time.Duration) error {
	req, reqAuth, err := buildPAPPacket(secret, username, password, nil)
	if err != nil {
		return fmt.Errorf("build packet: %w", err)
	}
	log.Printf("raw packet to server %x, authenticator %x", req, reqAuth)

	resp, _, err := exchange(addr, secret, req, reqAuth, timeout)
	if err != nil {
		return err
	}

	switch resp[0] {
	case 2:
		fmt.Println("Result: Access-Accept (Authentication successful)")
	case 3:
		fmt.Println("Result: Access-Reject (Invalid credentials)")
	case 11:
		log.Println("Received Access-Challenge: use -mode pap+otp for 2FA")
	default:
		return fmt.Errorf("unknown RADIUS code: %d", resp[0])
	}
	return nil
}

func runPAPWithOTP(addr, secret, username, password string, timeout time.Duration) error {
	// Round 1: primary credentials.
	req1, req1Auth, err := buildPAPPacket(secret, username, password, nil)
	if err != nil {
		return fmt.Errorf("build packet: %w", err)
	}
	log.Printf("raw packet to server %x, authenticator %x", req1, req1Auth)

	resp1, attrs1, err := exchange(addr, secret, req1, req1Auth, timeout)
	if err != nil {
		return err
	}

	switch resp1[0] {
	case 2:
		fmt.Println("Result: Access-Accept (Authentication successful)")
		return nil
	case 3:
		fmt.Println("Result: Access-Reject (Invalid credentials)")
		return nil
	case 11:
		// fall through to round 2
	default:
		return fmt.Errorf("unknown RADIUS code: %d", resp1[0])
	}

	log.Println("Received Access-Challenge (2FA required)")
	if msg, ok := findAttribute(attrs1, 18); ok {
		log.Printf("Server prompt: %s", string(msg))
	}

	state, ok := findAttribute(attrs1, 24)
	if !ok {
		return fmt.Errorf("server sent Access-Challenge without State attribute")
	}

	// Round 2: OTP.
	// TODO: read otpCode from stdin instead of hardcoding.
	otpCode := "999999"
	req2, req2Auth, err := buildPAPPacket(secret, username, otpCode, state)
	if err != nil {
		return fmt.Errorf("build OTP packet: %w", err)
	}
	log.Printf("raw challenge %x, authenticator %x", req2, req2Auth)

	resp2, _, err := exchange(addr, secret, req2, req2Auth, timeout)
	if err != nil {
		return err
	}

	switch resp2[0] {
	case 2:
		fmt.Println("Result: Access-Accept (2FA Successful!)")
	case 3:
		fmt.Println("Result: Access-Reject (Invalid 2FA Code)")
	default:
		fmt.Printf("Result: unexpected code %d\n", resp2[0])
	}
	return nil
}
