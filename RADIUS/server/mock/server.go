package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"flag"
	"log"
	"sync"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// Message-Authenticator attribute type (RFC 3579).
const typeMsgAuth radius.Type = 80

// EAP codes (RFC 3748).
const (
	eapRequest  byte = 1
	eapResponse byte = 2
	eapSuccess  byte = 3
	eapFailure  byte = 4
)

// EAP method types.
const (
	eapTypeIdentity byte = 1
	eapTypeMD5      byte = 4
)

// users is the built-in credential store; override at startup with -user/-pass.
var users map[string]string

// cfg holds values set from flags and referenced by every handler.
var cfg struct {
	secret    []byte
	otp       string // expected OTP token for pap+otp mode
	requireMA bool   // reject requests that lack Message-Authenticator
}

// --- per-exchange session state (pap+otp and eap-md5 are two-round) ---

type otpSession struct{ username string }

type eapSession struct {
	username  string
	challenge []byte
	eapID     byte
}

var (
	mu          sync.Mutex
	otpSessions = map[string]otpSession{}
	eapSessions = map[string]eapSession{}
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func buildEAP(code, id byte, body []byte) []byte {
	p := make([]byte, 4+len(body))
	p[0] = code
	p[1] = id
	l := uint16(len(p))
	p[2] = byte(l >> 8)
	p[3] = byte(l)
	copy(p[4:], body)
	return p
}

// checkMA validates attr 80 when present.  The function temporarily zeroes the
// attribute, re-encodes the packet (safe for Access-Request whose authenticator
// is fixed), computes HMAC-MD5(packet, secret), then restores the attribute.
// Because layeh stores attributes as an ordered slice the re-encoded bytes are
// byte-identical to the original wire packet except for the zeroed MA field.
func checkMA(pkt *radius.Packet) (present, valid bool) {
	attr := pkt.Attributes.Get(typeMsgAuth)
	if attr == nil {
		return false, false
	}
	if len(attr) != 16 {
		return true, false
	}
	saved := append([]byte(nil), []byte(attr)...)

	pkt.Attributes.Set(typeMsgAuth, radius.Attribute(make([]byte, 16)))
	encoded, err := pkt.Encode()
	pkt.Attributes.Set(typeMsgAuth, radius.Attribute(saved))
	if err != nil {
		return true, false
	}

	mac := hmac.New(md5.New, cfg.secret)
	mac.Write(encoded)
	return true, hmac.Equal(mac.Sum(nil), saved)
}

// enforceMA checks MA policy and sends a reject if the check fails.
// Returns true only when the handler may continue processing.
func enforceMA(w radius.ResponseWriter, r *radius.Request) bool {
	present, valid := checkMA(r.Packet)
	switch {
	case !present && cfg.requireMA:
		log.Printf("[%s] reject: Message-Authenticator required but absent", r.RemoteAddr)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
		return false
	case present && !valid:
		log.Printf("[%s] reject: Message-Authenticator invalid", r.RemoteAddr)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
		return false
	case present && valid:
		log.Printf("[%s] Message-Authenticator OK", r.RemoteAddr)
	}
	return true
}

// ── pap ──────────────────────────────────────────────────────────────────────

func papHandler(w radius.ResponseWriter, r *radius.Request) {
	if !enforceMA(w, r) {
		return
	}
	user := rfc2865.UserName_GetString(r.Packet)
	pass := rfc2865.UserPassword_GetString(r.Packet)
	if want, ok := users[user]; ok && pass == want {
		log.Printf("[%s] PAP accept: %q", r.RemoteAddr, user)
		w.Write(r.Packet.Response(radius.CodeAccessAccept))
	} else {
		log.Printf("[%s] PAP reject: %q", r.RemoteAddr, user)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
	}
}

// ── pap+otp ──────────────────────────────────────────────────────────────────

func papOTPHandler(w radius.ResponseWriter, r *radius.Request) {
	if !enforceMA(w, r) {
		return
	}
	user := rfc2865.UserName_GetString(r.Packet)
	state := rfc2865.State_Get(r.Packet)

	if state == nil {
		// Round 1: validate primary password, issue challenge.
		pass := rfc2865.UserPassword_GetString(r.Packet)
		if want, ok := users[user]; !ok || pass != want {
			log.Printf("[%s] PAP+OTP round1 reject: %q (wrong password)", r.RemoteAddr, user)
			w.Write(r.Packet.Response(radius.CodeAccessReject))
			return
		}
		token := randBytes(16)
		mu.Lock()
		otpSessions[string(token)] = otpSession{username: user}
		mu.Unlock()

		resp := r.Packet.Response(radius.CodeAccessChallenge)
		rfc2865.State_Set(resp, token)
		rfc2865.ReplyMessage_SetString(resp, "Enter OTP: ")
		log.Printf("[%s] PAP+OTP round1 challenge: %q", r.RemoteAddr, user)
		w.Write(resp)
		return
	}

	// Round 2: validate OTP.
	mu.Lock()
	sess, ok := otpSessions[string(state)]
	if ok {
		delete(otpSessions, string(state))
	}
	mu.Unlock()

	if !ok {
		log.Printf("[%s] PAP+OTP round2 reject: unknown state", r.RemoteAddr)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
		return
	}
	submitted := rfc2865.UserPassword_GetString(r.Packet)
	if submitted == cfg.otp {
		log.Printf("[%s] PAP+OTP round2 accept: %q", r.RemoteAddr, sess.username)
		w.Write(r.Packet.Response(radius.CodeAccessAccept))
	} else {
		log.Printf("[%s] PAP+OTP round2 reject: %q (bad OTP)", r.RemoteAddr, sess.username)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
	}
}

// ── chap ─────────────────────────────────────────────────────────────────────

func chapHandler(w radius.ResponseWriter, r *radius.Request) {
	if !enforceMA(w, r) {
		return
	}
	user := rfc2865.UserName_GetString(r.Packet)

	// CHAP-Password: byte[0]=CHAP-ID, bytes[1:17]=MD5(ID||password||challenge).
	chapPwd := rfc2865.CHAPPassword_Get(r.Packet)
	if len(chapPwd) != 17 {
		log.Printf("[%s] CHAP reject: %q – CHAP-Password len %d (want 17)", r.RemoteAddr, user, len(chapPwd))
		w.Write(r.Packet.Response(radius.CodeAccessReject))
		return
	}
	chapID := chapPwd[0]
	clientHash := chapPwd[1:]

	// CHAP-Challenge: attr 60 if present, else the Request-Authenticator.
	challenge := rfc2865.CHAPChallenge_Get(r.Packet)
	if challenge == nil {
		challenge = r.Packet.Authenticator[:]
	}

	password, ok := users[user]
	if !ok {
		log.Printf("[%s] CHAP reject: unknown user %q", r.RemoteAddr, user)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
		return
	}

	h := md5.New()
	h.Write([]byte{chapID})
	h.Write([]byte(password))
	h.Write(challenge)

	if bytes.Equal(h.Sum(nil), clientHash) {
		log.Printf("[%s] CHAP accept: %q", r.RemoteAddr, user)
		w.Write(r.Packet.Response(radius.CodeAccessAccept))
	} else {
		log.Printf("[%s] CHAP reject: %q (hash mismatch)", r.RemoteAddr, user)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
	}
}

// ── eap-md5 ──────────────────────────────────────────────────────────────────

func eapMD5Handler(w radius.ResponseWriter, r *radius.Request) {
	if !enforceMA(w, r) {
		return
	}
	eapMsg := rfc2869.EAPMessage_Get(r.Packet)
	if len(eapMsg) < 5 || eapMsg[0] != eapResponse {
		log.Printf("[%s] EAP reject: bad header %x", r.RemoteAddr, eapMsg)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
		return
	}

	eapID := eapMsg[1]
	eapLen := int(eapMsg[2])<<8 | int(eapMsg[3])
	eapType := eapMsg[4]
	if eapLen < 5 || eapLen > len(eapMsg) {
		w.Write(r.Packet.Response(radius.CodeAccessReject))
		return
	}

	switch eapType {
	case eapTypeIdentity:
		// Round 1: send MD5-Challenge.
		username := string(eapMsg[5:eapLen])
		challenge := randBytes(16)
		state := randBytes(16)
		chalID := eapID + 1

		mu.Lock()
		eapSessions[string(state)] = eapSession{username: username, challenge: challenge, eapID: chalID}
		mu.Unlock()

		// EAP-Request/MD5-Challenge body: type | value-size | value(16 bytes).
		body := append([]byte{eapTypeMD5, 16}, challenge...)
		resp := r.Packet.Response(radius.CodeAccessChallenge)
		rfc2869.EAPMessage_Set(resp, buildEAP(eapRequest, chalID, body))
		rfc2865.State_Set(resp, state)
		log.Printf("[%s] EAP-MD5 challenge: %q (eapID=%d)", r.RemoteAddr, username, chalID)
		w.Write(resp)

	case eapTypeMD5:
		// Round 2: verify MD5 response.
		state := rfc2865.State_Get(r.Packet)
		mu.Lock()
		sess, ok := eapSessions[string(state)]
		if ok {
			delete(eapSessions, string(state))
		}
		mu.Unlock()

		if !ok || len(eapMsg) < 6 {
			w.Write(r.Packet.Response(radius.CodeAccessReject))
			return
		}
		valSize := int(eapMsg[5])
		if len(eapMsg) < 6+valSize {
			w.Write(r.Packet.Response(radius.CodeAccessReject))
			return
		}
		clientHash := eapMsg[6 : 6+valSize]

		// RFC 3748 §5.4: MD5(ID || password || challenge).
		h := md5.New()
		h.Write([]byte{sess.eapID})
		h.Write([]byte(users[sess.username]))
		h.Write(sess.challenge)

		var code radius.Code
		var eapFinal byte
		if bytes.Equal(h.Sum(nil), clientHash) {
			code, eapFinal = radius.CodeAccessAccept, eapSuccess
			log.Printf("[%s] EAP-MD5 accept: %q", r.RemoteAddr, sess.username)
		} else {
			code, eapFinal = radius.CodeAccessReject, eapFailure
			log.Printf("[%s] EAP-MD5 reject: %q", r.RemoteAddr, sess.username)
		}

		resp := r.Packet.Response(code)
		rfc2869.EAPMessage_Set(resp, buildEAP(eapFinal, eapID, nil))
		w.Write(resp)

	default:
		log.Printf("[%s] EAP: unsupported type %d", r.RemoteAddr, eapType)
		w.Write(r.Packet.Response(radius.CodeAccessReject))
	}
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	addr := flag.String("addr", ":1812", "listen address (host:port)")
	mode := flag.String("mode", "pap", "auth mode: pap | pap+otp | chap | eap-md5")
	secret := flag.String("secret", "secret", "shared secret")
	user := flag.String("user", "art", "valid username")
	pass := flag.String("pass", "12345", "valid password")
	otp := flag.String("otp", "999999", "expected OTP token (pap+otp mode)")
	requireMA := flag.Bool("require-ma", false, "reject Access-Request packets missing Message-Authenticator")
	flag.Parse()

	users = map[string]string{*user: *pass}
	cfg.secret = []byte(*secret)
	cfg.otp = *otp
	cfg.requireMA = *requireMA

	var handler radius.HandlerFunc
	switch *mode {
	case "pap":
		handler = papHandler
	case "pap+otp":
		handler = papOTPHandler
	case "chap":
		handler = chapHandler
	case "eap-md5":
		handler = eapMD5Handler
	default:
		log.Fatalf("unknown mode %q (supported: pap, pap+otp, chap, eap-md5)", *mode)
	}

	server := radius.PacketServer{
		Addr:         *addr,
		Handler:      handler,
		SecretSource: radius.StaticSecretSource(cfg.secret),
	}

	log.Printf("mock RADIUS server  mode=%s  addr=%s  user=%q  require-ma=%v",
		*mode, *addr, *user, *requireMA)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
