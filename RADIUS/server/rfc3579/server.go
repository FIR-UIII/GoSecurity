package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"log"
	"sync"

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

type eapSession struct {
	username  string
	challenge []byte
	eapID     byte // ID used in the MD5-Challenge request
}

var (
	mu       sync.Mutex
	sessions = map[string]eapSession{}
	users    = map[string]string{"art": "12345"}
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
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		eapMsg := rfc2869.EAPMessage_Get(r.Packet)
		log.Printf("pkt from %v  EAP-Message len=%d", r.RemoteAddr, len(eapMsg))
		if len(eapMsg) < 5 || eapMsg[0] != eapResponse {
			log.Printf("  → reject: eapMsg=%x", eapMsg)
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		eapID := eapMsg[1]
		eapLen := int(eapMsg[2])<<8 | int(eapMsg[3])
		eapType := eapMsg[4]

		if eapLen < 5 || eapLen > len(eapMsg) {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		switch eapType {
		case eapTypeIdentity:
			// Round 1: client announces who they are
			username := string(eapMsg[5:eapLen])

			challenge := make([]byte, 16)
			rand.Read(challenge)
			state := make([]byte, 16)
			rand.Read(state)

			challengeID := eapID + 1
			mu.Lock()
			sessions[string(state)] = eapSession{username: username, challenge: challenge, eapID: challengeID}
			mu.Unlock()

			// EAP-Request/MD5-Challenge body: type | value-size | value(16)
			body := append([]byte{eapTypeMD5, 16}, challenge...)
			resp := r.Response(radius.CodeAccessChallenge)
			rfc2869.EAPMessage_Set(resp, buildEAP(eapRequest, challengeID, body))
			rfc2865.State_Set(resp, state)
			log.Printf("Sent MD5 challenge to %q (eapID=%d)", username, challengeID)
			w.Write(resp)

		case eapTypeMD5:
			// Round 2: client responds to the MD5 challenge
			state := rfc2865.State_Get(r.Packet)
			mu.Lock()
			sess, ok := sessions[string(state)]
			if ok {
				delete(sessions, string(state))
			}
			mu.Unlock()

			// eapMsg layout: [code, id, lenHi, lenLo, type=4, valueSize, value..., name...]
			if !ok || len(eapMsg) < 6 {
				w.Write(r.Response(radius.CodeAccessReject))
				return
			}
			valueSize := int(eapMsg[5])
			if len(eapMsg) < 6+valueSize {
				w.Write(r.Response(radius.CodeAccessReject))
				return
			}
			clientHash := eapMsg[6 : 6+valueSize]

			// RFC 3748 §5.4: MD5(ID || password || challenge)
			h := md5.New()
			h.Write([]byte{sess.eapID})
			h.Write([]byte(users[sess.username]))
			h.Write(sess.challenge)

			var code radius.Code
			var finalEAP byte
			if bytes.Equal(h.Sum(nil), clientHash) {
				code, finalEAP = radius.CodeAccessAccept, eapSuccess
				log.Printf("EAP-MD5 accepted: %q", sess.username)
			} else {
				code, finalEAP = radius.CodeAccessReject, eapFailure
				log.Printf("EAP-MD5 rejected: %q", sess.username)
			}

			resp := r.Response(code)
			// EAP-Success/Failure: no type field, just the 4-byte header
			rfc2869.EAPMessage_Set(resp, buildEAP(finalEAP, eapID, nil))
			w.Write(resp)

		default:
			log.Printf("Unsupported EAP type %d", eapType)
			w.Write(r.Response(radius.CodeAccessReject))
		}
	}

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(`secret`)),
	}

	log.Println("EAP-MD5 RADIUS server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
