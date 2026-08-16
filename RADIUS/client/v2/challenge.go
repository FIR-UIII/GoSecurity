package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
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

// findAttribute ищет атрибут по его типу (Type)
func findAttribute(attrs []Attribute, typ byte) ([]byte, bool) {
	for _, a := range attrs {
		if a.Type == typ {
			return a.Value, true
		}
	}
	return nil, false
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
