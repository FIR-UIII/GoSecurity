package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
)

// addMessageAuthenticator добавляет атрибут Type 80 к пакету и рассчитывает HMAC-MD5
func addMessageAuthenticator(pkt []byte, secret string) []byte {
	// 1. Создаем атрибут: Type=80 (1 байт), Length=18 (1 байт), Value=16 нулей
	maAttr := make([]byte, 18)
	maAttr[0] = 80 // Message-Authenticator
	maAttr[1] = 18 // Length (2 + 16 = 18)
	// maAttr[2:18] по умолчанию забиты 0x00

	// 2. Добавляем временный атрибут с нулями в конец пакета
	pktWithMA := append(pkt, maAttr...)

	// 3. Обновляем поле Length в заголовке RADIUS (байты 2:4), увеличивая его на 18 байт
	newTotalLen := uint16(len(pktWithMA))
	binary.BigEndian.PutUint16(pktWithMA[2:4], newTotalLen)

	// 4. Вычисляем HMAC-MD5(Secret, EntirePacketWithZeroedMA)
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(pktWithMA)
	hash := mac.Sum(nil)

	// 5. Записываем рассчитанный 16-байтовый хеш поверх 16 нулей
	copy(pktWithMA[len(pktWithMA)-16:], hash)

	return pktWithMA
}

// verifyMessageAuthenticator проверяет валидность Message-Authenticator в ответе сервера
func verifyMessageAuthenticator(resp []byte, reqAuth []byte, secret string) bool {
	_, err := parseAttributes(resp)
	if err != nil {
		return false
	}

	// Ищем атрибут 80
	var maValue []byte
	var maOffset int

	// Проходим по байтам ответа и находим где лежит атрибут 80
	totalLen := int(binary.BigEndian.Uint16(resp[2:4]))
	i := 20
	for i < totalLen {
		typ := resp[i]
		length := int(resp[i+1])
		if typ == 80 && length == 18 {
			maOffset = i + 2
			maValue = make([]byte, 16)
			copy(maValue, resp[maOffset:maOffset+16])
			break
		}
		i += length
	}

	if maValue == nil {
		return true // Атрибута нет в ответе (некоторые серверы не присылают его без EAP)
	}

	// Создаем копию пакета и зануляем 16 байт Message-Authenticator
	respCopy := make([]byte, len(resp))
	copy(respCopy, resp)

	// ВАЖНО: Если проверяем ответ сервера, вместо Response Authenticator
	// в байты 4:20 нужно временно подставить оригинальный Request Authenticator!
	copy(respCopy[4:20], reqAuth)
	for j := 0; j < 16; j++ {
		respCopy[maOffset+j] = 0x00
	}

	// Считаем HMAC-MD5
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(respCopy)
	expectedHash := mac.Sum(nil)

	return bytes.Equal(maValue, expectedHash)
}
