package main

import (
	"fmt"
	"log"
)

// runScenarios executes every scenario in cfg in order. It never aborts the
// whole run on a single scenario's error — for a security-probing tool, a
// scenario "failing" (unexpected code, network error, malformed response)
// is often the expected/interesting result, not a bug. Each scenario's
// outcome is logged as it finishes, and a summary is printed at the end.
// The returned error is non-nil (so main can exit non-zero) only if at
// least one scenario failed.
func runScenarios(cfg *Config, addrOverride string) error {
	var failed int
	for _, sc := range cfg.Scenarios {
		label := sc.Name
		if label == "" {
			label = sc.Type
		}
		log.Printf("[scenario %q] starting (type=%s)", label, sc.Type)
		if err := runScenario(cfg, sc, addrOverride); err != nil {
			failed++
			log.Printf("[scenario %q] FAILED: %v", label, err)
		} else {
			log.Printf("[scenario %q] OK", label)
		}
	}

	log.Printf("[summary] %d scenario(s): %d ok, %d failed", len(cfg.Scenarios), len(cfg.Scenarios)-failed, failed)
	if failed > 0 {
		return fmt.Errorf("%d of %d scenario(s) failed", failed, len(cfg.Scenarios))
	}
	return nil
}

// runScenario resolves one scenario's settings (merging top-level config
// defaults, per-scenario overrides, and an explicit -addr override) and
// dispatches on sc.Type.
func runScenario(cfg *Config, sc Scenario, addrOverride string) error {
	r, err := resolveScenario(cfg, sc)
	if err != nil {
		return fmt.Errorf("resolve settings: %w", err)
	}
	if addrOverride != "" {
		r.Addr = addrOverride
	}

	switch sc.Type {
	case "otp":
		otp, err := resolveOTP(sc)
		if err != nil {
			return fmt.Errorf("resolve otp: %w", err)
		}
		return runPAPWithOTP(r.Addr, r.Secret, sc.Username, sc.Password, otp, r.Timeout)
	case "raw":
		return runRawScenario(r.Addr, r.Timeout, sc.PacketHex)
	case "fuzz":
		return runFuzzScenario(r.Addr, r.Secret, r.Timeout, sc.Username, sc.Password, sc.FuzzFile, sc.PostResponseDatagrams)
	case "packet":
		return runPacketScenario(r.Addr, r.Secret, r.Timeout, sc)
	default:
		return fmt.Errorf("unknown scenario type %q", sc.Type)
	}
}
