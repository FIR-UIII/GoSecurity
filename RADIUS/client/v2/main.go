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
	mode := flag.String("mode", "eap-md5", "test mode: pap | eap-md5")
	configPath := flag.String("c", "", "path to YAML scenario config; when set, runs scenarios instead of -mode")
	flag.StringVar(configPath, "config", "", "alias for -c")

	flag.Parse()

	if *configPath != "" {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		if err := cfg.validate(); err != nil {
			log.Fatalf("invalid config: %v", err)
		}

		// Only treat -addr as an override if the user actually passed it on
		// the command line; its zero-value default is otherwise
		// indistinguishable from an explicit choice.
		addrOverride := ""
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "addr" {
				addrOverride = *addr
			}
		})

		if err := runScenarios(cfg, addrOverride); err != nil {
			log.Fatalf("one or more scenarios failed: %v", err)
		}
		return
	}

	switch *mode {
	case "pap":
		err := runPAP(*addr, *secret, *username, *password, 5*time.Second)
		if err != nil {
			log.Fatalf("PAP exchange failed: %v", err)
		}
	default:
		panic("unknown mode: " + *mode)
	}
}
