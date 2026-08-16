package main

import (
	"flag"
	"log"
	"time"
)

func main() {
	addr := flag.String("addr", "localhost:1812", "RADIUS server address")
	secret := flag.String("secret", "secret", "shared secret")
	username := flag.String("user", "art", "username")
	password := flag.String("pass", "12345", "password")
	mode := flag.String("mode", "eap-md5", "test mode: pap | eap-md5 | raw | fuzz")

	flag.Parse()

	switch *mode {
	case "pap":
		err := runPAP(*addr, *secret, *username, *password, 5*time.Second)
		if err != nil {
			log.Fatalf("PAP exchange failed: %v", err)
		}
	case "pap+otp":
		err := runPAPWithOTP(*addr, *secret, *username, *password, 5*time.Second)
		if err != nil {
			log.Fatalf("PAP+OTP exchange failed: %v", err)
		}
	default:
		panic("unknown mode: " + *mode)
	}
}
