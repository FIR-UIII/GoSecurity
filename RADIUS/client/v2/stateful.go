package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"
)

// stateAttrType is the RADIUS State attribute (RFC 2865 §5.24), used to
// carry an opaque session token between an Access-Challenge and the
// follow-up Access-Request that answers it.
const stateAttrType byte = 24

// knownStateChecks is the registry of one-shot State-corruption probes a
// "challenge" scenario's state_checks[] can name; see applyStateCheck.
var knownStateChecks = map[string]bool{
	"bit_flip": true,
	"truncate": true,
	"foreign":  true,
	"drop":     true,
}

func isKnownStateCheck(name string) bool {
	return knownStateChecks[name]
}

// findAttr returns the value of the first attribute of type typ in attrs,
// and whether one was found.
func findAttr(attrs []Attribute, typ byte) ([]byte, bool) {
	for _, a := range attrs {
		if a.Type == typ {
			return a.Value, true
		}
	}
	return nil, false
}

// responseFingerprint is a coarse summary of an Access-Request response
// used to notice when the server's behavior changes partway through an
// OTP brute-force run (e.g. rate-limiting/lockout kicking in).
type responseFingerprint struct {
	timedOut  bool
	code      byte
	replyText string
}

func fingerprintResponse(resp []byte, timedOut bool) responseFingerprint {
	if timedOut || len(resp) == 0 {
		return responseFingerprint{timedOut: true}
	}
	fp := responseFingerprint{code: resp[0]}
	if attrs, err := parseAttributes(resp); err == nil {
		if v, ok := findAttr(attrs, 18); ok { // Reply-Message
			fp.replyText = string(v)
		}
	}
	return fp
}

// filterOutAttrType returns a copy of attrs with every entry whose
// resolved type equals typ removed. An entry whose Type token doesn't
// resolve (a config error that will surface clearly from
// buildPacketFromSpec instead) is left in place.
func filterOutAttrType(attrs []AttrSpec, typ byte) []AttrSpec {
	out := make([]AttrSpec, 0, len(attrs))
	for _, a := range attrs {
		if t, err := resolveAttrType(a.Type); err == nil && t == typ {
			continue
		}
		out = append(out, a)
	}
	return out
}

// randomAuthenticator generates a fresh 16-byte Request Authenticator,
// the same way buildPAPPacket (raw.go) does for a normal PAP request.
// runChallengeScenario needs to generate this itself (rather than letting
// buildPacketFromSpec pick one) because the OTP guess must be PAP-
// encrypted against this exact authenticator before the packet is built.
func randomAuthenticator() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return nil, fmt.Errorf("generate authenticator: %w", err)
	}
	return b, nil
}

// buildSecondRequest builds one Access-Request attrs list for the
// challenge/OTP loop: seedAttrs with any existing otpAttrType/State
// entries stripped, plus a freshly PAP-encrypted OTP guess and the given
// state bytes (or no State attribute at all if state is nil, for the
// "drop" state_check).
func buildSecondRequestAttrs(seedAttrs []AttrSpec, otpAttrName string, otpAttrType byte, otp string, secret string, authenticator, state []byte) []AttrSpec {
	attrs := filterOutAttrType(cloneAttrs(seedAttrs), otpAttrType)
	attrs = filterOutAttrType(attrs, stateAttrType)

	encOTP := encryptPAP(otp, secret, authenticator)
	attrs = append(attrs, AttrSpec{Type: otpAttrName, Value: "hex:" + hex.EncodeToString(encOTP)})
	if state != nil {
		attrs = append(attrs, AttrSpec{Type: "State", Value: "hex:" + hex.EncodeToString(state)})
	}
	return attrs
}

// applyStateCheck returns a corrupted copy of state per one of
// knownStateChecks's names ("drop" is handled by the caller passing a nil
// state to buildSecondRequestAttrs instead, since it needs to omit the
// attribute rather than mutate its value).
func applyStateCheck(rng *rand.Rand, name string, state []byte) []byte {
	switch name {
	case "bit_flip":
		if len(state) == 0 {
			return state
		}
		out := append([]byte(nil), state...)
		out[rng.Intn(len(out))] ^= 1 << rng.Intn(8)
		return out
	case "truncate":
		return append([]byte(nil), state[:len(state)/2]...)
	case "foreign":
		out := make([]byte, len(state))
		rng.Read(out)
		return out
	default:
		return state
	}
}

// runChallengeScenario drives Code/ID/Authenticator/Attrs (sc) as a FIRST
// Access-Request that must be answered with an Access-Challenge, then
// brute-forces a numeric OTP against the returned State across up to
// sc.MaxAttempts second requests. This probes two things per the fuzzing
// methodology's stateful-challenge phase: (1) whether the server
// rate-limits/locks out repeated wrong-OTP attempts, and (2) whether a
// single State value stays valid/reusable across many of them (when
// sc.StateReuse, the default, keeps replaying the original State rather
// than whatever new one each Access-Challenge response offers). A found
// OTP is the scenario's hard-failure condition (a real, guessable
// credential), same as an unexpected Access-Accept fails type: fuzz; a
// dead/unreachable server also aborts and fails the scenario. The absence
// of an observed lockout is only logged, never treated as a failure —
// that's a judgment call for whoever reads the log.
func runChallengeScenario(addr, secret string, timeout time.Duration, sc Scenario) error {
	code, err := resolveRadiusCode(sc.Code)
	if err != nil {
		return err
	}
	var id *byte
	if sc.ID != nil {
		b := byte(*sc.ID)
		id = &b
	}

	firstPkt, err := buildPacketFromSpec(secret, code, id, sc.Authenticator, sc.Attrs)
	if err != nil {
		return fmt.Errorf("build first request: %w", err)
	}
	log.Printf("[challenge] sending first request, %d bytes: %x", len(firstPkt), firstPkt)

	firstResp, err := sendRawUDP(addr, firstPkt, timeout)
	if err != nil {
		return fmt.Errorf("network: first request: %w", err)
	}
	log.Printf("[challenge] first response %d bytes: %x", len(firstResp), firstResp)

	firstAttrs, err := parseAttributes(firstResp)
	if err != nil {
		return fmt.Errorf("first response did not parse as well-formed RADIUS attributes: %w", err)
	}
	log.Printf("[challenge] parsed first response:\n%s", formatParsedResponse(firstResp, firstAttrs))

	if len(firstResp) == 0 || firstResp[0] != 11 {
		got := byte(0)
		if len(firstResp) > 0 {
			got = firstResp[0]
		}
		return fmt.Errorf("expected Access-Challenge (11) in response to the first request, got code %d (%s) — is this user/seed actually challenge-enabled on the server?", got, radiusCodeName(got))
	}

	originalState, ok := findAttr(firstAttrs, stateAttrType)
	if !ok {
		return fmt.Errorf("first response was Access-Challenge but carried no State attribute")
	}
	currentState := append([]byte(nil), originalState...)

	otpAttrName := sc.OTPAttr
	if otpAttrName == "" {
		otpAttrName = "User-Password"
	}
	otpAttrType, err := resolveAttrType(otpAttrName)
	if err != nil {
		return fmt.Errorf("otp_attr: %w", err)
	}

	digits := sc.OTPDigits
	if digits == 0 {
		digits = len(strconv.Itoa(*sc.OTPMax))
	}

	rangeSize := *sc.OTPMax - *sc.OTPMin + 1
	attempts := sc.MaxAttempts
	random := sc.OTPOrder == "random"
	if !random && attempts > rangeSize {
		attempts = rangeSize
		log.Printf("[challenge] max_attempts (%d) exceeds the otp range (%d); capping at %d", sc.MaxAttempts, rangeSize, attempts)
	}

	seed := time.Now().UnixNano()
	if sc.Seed != nil {
		seed = *sc.Seed
	}
	rng := rand.New(rand.NewSource(seed))
	log.Printf("[challenge] seed=%d attempts=%d otp_range=[%d,%d] digits=%d order=%s state_reuse=%v",
		seed, attempts, *sc.OTPMin, *sc.OTPMax, digits, sc.OTPOrder, sc.StateReuse == nil || *sc.StateReuse)

	stateReuse := true
	if sc.StateReuse != nil {
		stateReuse = *sc.StateReuse
	}

	var delay time.Duration
	if sc.Delay != "" {
		delay, _ = time.ParseDuration(sc.Delay) // already validated in config.go
	}

	var (
		otpFound     bool
		foundOTP     string
		baseline     responseFingerprint
		haveBaseline bool
		patternNoted bool
		patternAt    int
		ran          int
	)

	for i := 0; i < attempts; i++ {
		var candidate int
		if random {
			candidate = *sc.OTPMin + rng.Intn(rangeSize)
		} else {
			candidate = *sc.OTPMin + i
		}
		otp := fmt.Sprintf("%0*d", digits, candidate)

		authenticator, err := randomAuthenticator()
		if err != nil {
			return err
		}
		attrs := buildSecondRequestAttrs(sc.Attrs, otpAttrName, otpAttrType, otp, secret, authenticator, currentState)

		pkt, err := buildPacketFromSpec(secret, 1, nil, hex.EncodeToString(authenticator), attrs)
		if err != nil {
			return fmt.Errorf("attempt %d: build request: %w", i, err)
		}

		resp, err := sendRawUDP(addr, pkt, timeout)
		ran++
		if err != nil && !isNetTimeout(err) {
			log.Printf("[challenge attempt=%d otp=%s] CRITICAL: network error, server may be unreachable: %v", i, otp, err)
			return fmt.Errorf("server became unreachable after %d attempts: %w", ran, err)
		}

		timedOut := err != nil
		fp := fingerprintResponse(resp, timedOut)
		if timedOut {
			log.Printf("[challenge attempt=%d otp=%s] timeout (no response)", i, otp)
		} else {
			log.Printf("[challenge attempt=%d otp=%s] -> code %d (%s)", i, otp, resp[0], radiusCodeName(resp[0]))
			if resp[0] == 2 {
				otpFound = true
				foundOTP = otp
				log.Printf("[challenge] FINDING: OTP %q accepted (Access-Accept) on attempt %d", otp, i)
				log.Printf("[challenge] request hex:  %x", pkt)
				log.Printf("[challenge] response hex: %x", resp)
				break
			}
			if resp[0] == 11 && !stateReuse {
				if attrs2, err := parseAttributes(resp); err == nil {
					if s, ok := findAttr(attrs2, stateAttrType); ok {
						currentState = append([]byte(nil), s...)
					}
				}
			}
		}

		if !haveBaseline {
			baseline = fp
			haveBaseline = true
		} else if !patternNoted && fp != baseline {
			patternNoted = true
			patternAt = i
			log.Printf("[challenge] NOTICE: response pattern changed at attempt %d (possible lockout/rate-limit): baseline=%+v now=%+v", i, baseline, fp)
		}

		if delay > 0 {
			time.Sleep(delay)
		}
	}

	for _, check := range sc.StateChecks {
		otp := fmt.Sprintf("%0*d", digits, *sc.OTPMin)
		authenticator, err := randomAuthenticator()
		if err != nil {
			return err
		}
		var stateArg []byte
		if check == "drop" {
			stateArg = nil
		} else {
			stateArg = applyStateCheck(rng, check, currentState)
		}
		attrs := buildSecondRequestAttrs(sc.Attrs, otpAttrName, otpAttrType, otp, secret, authenticator, stateArg)
		pkt, err := buildPacketFromSpec(secret, 1, nil, hex.EncodeToString(authenticator), attrs)
		if err != nil {
			log.Printf("[state-check %s] build error: %v", check, err)
			continue
		}
		resp, err := sendRawUDP(addr, pkt, timeout)
		if err != nil {
			log.Printf("[state-check %s] network error: %v", check, err)
			continue
		}
		log.Printf("[state-check %s] -> code %d (%s), response hex: %x", check, resp[0], radiusCodeName(resp[0]), resp)
		if resp[0] == 2 {
			log.Printf("[state-check %s] FINDING: corrupted/dropped State still produced Access-Accept", check)
		}
	}

	log.Printf("[challenge] summary: %d attempt(s) run, otp_found=%v, pattern_change_at=%v", ran, otpFound, patternNotedAttempt(patternNoted, patternAt))

	if otpFound {
		return fmt.Errorf("OTP %q was accepted after %d attempt(s)", foundOTP, ran)
	}
	return nil
}

// patternNotedAttempt renders the "no pattern change observed" case as a
// plain "none" instead of the zero value 0, which would misleadingly read
// as "changed on the very first attempt".
func patternNotedAttempt(noted bool, at int) any {
	if !noted {
		return "none"
	}
	return at
}
