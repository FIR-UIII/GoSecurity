package main

import (
	"crypto/md5"
	"fmt"
	"net"
	"time"
)

func sendRawUDP(addr string, rawPacket []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	// Отправляем пакет
	if _, err := conn.Write(rawPacket); err != nil {
		return nil, fmt.Errorf("write error: %w", err)
	}

	// Читаем ответ от сервера
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	return buf[:n], nil
}

// encryptPAP шифрует пароль по стандарту RFC 2865
func encryptPAP(password, secret string, authenticator []byte) []byte {
	passBytes := []byte(password)

	// Pad to the next multiple of 16 (RFC 2865 §5.2); an empty password pads to 16.
	padLen := 16 - len(passBytes)%16
	if padLen == 16 && len(passBytes) > 0 {
		padLen = 0 // already aligned — do NOT add an extra block (unlike the original dead-code path)
	}
	padded := make([]byte, len(passBytes)+padLen)
	copy(padded, passBytes)

	encrypted := make([]byte, len(padded))

	// Первый блок: XOR c MD5(Secret + Authenticator)
	h := md5.New()
	h.Write([]byte(secret))
	h.Write(authenticator)
	hash := h.Sum(nil)

	for i := 0; i < 16; i++ {
		encrypted[i] = padded[i] ^ hash[i]
	}

	// Последующие блоки (если пароль длиннее 16 байт): XOR c MD5(Secret + PreviousCipherBlock)
	for block := 16; block < len(padded); block += 16 {
		h.Reset()
		h.Write([]byte(secret))
		h.Write(encrypted[block-16 : block])
		hash = h.Sum(nil)
		for i := 0; i < 16; i++ {
			encrypted[block+i] = padded[block+i] ^ hash[i]
		}
	}

	return encrypted
}
