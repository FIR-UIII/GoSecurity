package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"time"
)

// mutator takes a cloned attrs slice (safe to modify in place) and returns
// the mutated result plus a short human-readable description of what it
// did, for logging and findings. A mutator that has nothing to do against
// this particular seed (e.g. message_authenticator_tamper against a seed
// with no Message-Authenticator attribute) returns attrs unchanged and a
// description saying so; runFuzzScenario still sends it (a no-op mutation
// is itself a valid, if uninteresting, data point) rather than skipping
// the iteration.
type mutator func(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string)

// fuzzStrategies is the registry of structural attribute mutators for the
// "fuzz" scenario type. Each targets a different class of parser bug per
// the fuzzing methodology: length lies, duplicate/missing attributes,
// oversized/empty/truncated values, unknown types, bit-level corruption,
// and a tampered Message-Authenticator.
var fuzzStrategies = map[string]mutator{
	"length_mismatch":              mutateLengthMismatch,
	"duplicate":                    mutateDuplicate,
	"missing_required":             mutateMissingRequired,
	"oversized_value":              mutateOversizedValue,
	"empty_value":                  mutateEmptyValue,
	"unknown_type":                 mutateUnknownType,
	"bit_flip":                     mutateBitFlip,
	"truncate":                     mutateTruncate,
	"message_authenticator_tamper": mutateMessageAuthenticatorTamper,
}

// isKnownFuzzStrategy reports whether name is a registered mutator, used
// by config.go's validate() to reject a typo'd strategies[] entry early.
func isKnownFuzzStrategy(name string) bool {
	_, ok := fuzzStrategies[name]
	return ok
}

// sortedFuzzStrategyNames returns every registered strategy name, sorted,
// so the default "use all strategies" round-robin order is deterministic
// (and thus reproducible together with a fixed seed:).
func sortedFuzzStrategyNames() []string {
	names := make([]string, 0, len(fuzzStrategies))
	for n := range fuzzStrategies {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// cloneAttrs deep-copies attrs (including the *int Length pointer) so a
// mutator can never modify the scenario's own seed slice.
func cloneAttrs(attrs []AttrSpec) []AttrSpec {
	out := make([]AttrSpec, len(attrs))
	for i, a := range attrs {
		out[i] = a
		if a.Length != nil {
			l := *a.Length
			out[i].Length = &l
		}
	}
	return out
}

// decodeAttrValue returns spec.Value's raw bytes the same way
// appendAttrSpec/parseAttrValue would encode them on the wire, for
// mutators that need to work on raw bytes (bit_flip, truncate,
// oversized_value) rather than the YAML-level string.
func decodeAttrValue(spec AttrSpec) []byte {
	v, err := parseAttrValue(spec.Value)
	if err != nil {
		// spec.Value is whatever the seed scenario already validated
		// successfully once (runFuzzScenario's health-check packet), so
		// this is unreachable in practice; fall back to raw bytes.
		return []byte(spec.Value)
	}
	return v
}

func hexValue(b []byte) string {
	return "hex:" + hex.EncodeToString(b)
}

// mutateLengthMismatch overrides one random attribute's Length byte to lie
// about its actual encoded size (RFC 2865 §5 Type|Length|Value framing),
// probing for buffer over/under-read in the server's TLV walker.
func mutateLengthMismatch(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	if len(attrs) == 0 {
		return attrs, "length_mismatch: no attrs to target"
	}
	i := rng.Intn(len(attrs))
	actual := 2 + len(decodeAttrValue(attrs[i]))
	deltas := []int{-actual + 1, -5, -2, -1, 1, 2, 5, 255 - actual}
	delta := deltas[rng.Intn(len(deltas))]
	newLen := actual + delta
	if newLen < 0 {
		newLen = 0
	}
	if newLen > 255 {
		newLen = 255
	}
	attrs[i].Length = &newLen
	return attrs, fmt.Sprintf("length_mismatch: attrs[%d] (%s) actual=%d declared=%d", i, attrs[i].Type, actual, newLen)
}

// mutateDuplicate appends a second copy of one random attribute right
// after the first, probing how the server handles a repeated attribute
// type (some are legitimately repeatable, e.g. Reply-Message; others,
// like User-Password, are not supposed to be).
func mutateDuplicate(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	if len(attrs) == 0 {
		return attrs, "duplicate: no attrs to target"
	}
	i := rng.Intn(len(attrs))
	dup := attrs[i]
	if dup.Length != nil {
		l := *dup.Length
		dup.Length = &l
	}
	out := make([]AttrSpec, 0, len(attrs)+1)
	out = append(out, attrs[:i+1]...)
	out = append(out, dup)
	out = append(out, attrs[i+1:]...)
	return out, fmt.Sprintf("duplicate: attrs[%d] (%s)", i, attrs[i].Type)
}

// mutateMissingRequired removes one random attribute entirely, probing
// how the server handles a request missing something it needs (most
// interesting when it happens to drop User-Name/User-Password, but any
// attribute is worth dropping).
func mutateMissingRequired(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	if len(attrs) == 0 {
		return attrs, "missing_required: no attrs to target"
	}
	i := rng.Intn(len(attrs))
	removed := attrs[i]
	out := make([]AttrSpec, 0, len(attrs)-1)
	out = append(out, attrs[:i]...)
	out = append(out, attrs[i+1:]...)
	return out, fmt.Sprintf("missing_required: dropped attrs[%d] (%s)", i, removed.Type)
}

// mutateOversizedValue replaces one random attribute's value with 300
// random bytes — past the 253-byte max a single RADIUS attribute value
// can hold (255 - 2-byte Type|Length header) — probing truncation/
// overflow handling. appendAttr's own Length-byte wrap (see packet.go)
// still applies on top of this when no explicit length: is set.
func mutateOversizedValue(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	if len(attrs) == 0 {
		return attrs, "oversized_value: no attrs to target"
	}
	i := rng.Intn(len(attrs))
	b := make([]byte, 300)
	rng.Read(b)
	attrs[i].Value = hexValue(b)
	attrs[i].Length = nil
	return attrs, fmt.Sprintf("oversized_value: attrs[%d] (%s) -> %d random bytes", i, attrs[i].Type, len(b))
}

// mutateEmptyValue replaces one random attribute's value with zero bytes,
// probing handling of an attribute with Length == 2 (Type|Length, no
// Value at all).
func mutateEmptyValue(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	if len(attrs) == 0 {
		return attrs, "empty_value: no attrs to target"
	}
	i := rng.Intn(len(attrs))
	attrs[i].Value = ""
	attrs[i].Length = nil
	return attrs, fmt.Sprintf("empty_value: attrs[%d] (%s)", i, attrs[i].Type)
}

// mutateUnknownType changes one random attribute's Type to a numeric value
// not present in the well-known dictionary (dictionary.go), probing how
// the server handles an attribute it doesn't recognize.
func mutateUnknownType(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	if len(attrs) == 0 {
		return attrs, "unknown_type: no attrs to target"
	}
	i := rng.Intn(len(attrs))
	var t byte
	for {
		t = byte(rng.Intn(256))
		if attrName(t) == "Unknown" {
			break
		}
	}
	old := attrs[i].Type
	attrs[i].Type = fmt.Sprintf("%d", t)
	return attrs, fmt.Sprintf("unknown_type: attrs[%d] %s -> type %d", i, old, t)
}

// mutateBitFlip flips a single random bit within one random attribute's
// raw value bytes, probing generic parser robustness against bit-level
// corruption (the classic byte-fuzzing mutation, applied structurally so
// framing stays otherwise valid).
func mutateBitFlip(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	// Skip attrs with an empty value (nothing to flip); try a few times
	// before giving up on this seed entirely.
	for attempt := 0; attempt < 10; attempt++ {
		if len(attrs) == 0 {
			break
		}
		i := rng.Intn(len(attrs))
		b := decodeAttrValue(attrs[i])
		if len(b) == 0 {
			continue
		}
		byteIdx := rng.Intn(len(b))
		bitIdx := rng.Intn(8)
		b[byteIdx] ^= 1 << bitIdx
		attrs[i].Value = hexValue(b)
		attrs[i].Length = nil
		return attrs, fmt.Sprintf("bit_flip: attrs[%d] (%s) byte %d bit %d", i, attrs[i].Type, byteIdx, bitIdx)
	}
	return attrs, "bit_flip: no non-empty attr value to target"
}

// mutateTruncate shortens one random attribute's raw value to a random
// shorter length (Length byte left to the default 2+len(value), so it
// stays internally consistent — the interesting case here is the server's
// own downstream parsing of a shorter-than-expected value, e.g. a
// truncated User-Password block or NAS-IP-Address).
func mutateTruncate(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	for attempt := 0; attempt < 10; attempt++ {
		if len(attrs) == 0 {
			break
		}
		i := rng.Intn(len(attrs))
		b := decodeAttrValue(attrs[i])
		if len(b) == 0 {
			continue
		}
		newLen := rng.Intn(len(b))
		attrs[i].Value = hexValue(b[:newLen])
		attrs[i].Length = nil
		return attrs, fmt.Sprintf("truncate: attrs[%d] (%s) %d -> %d bytes", i, attrs[i].Type, len(b), newLen)
	}
	return attrs, "truncate: no non-empty attr value to target"
}

// mutateMessageAuthenticatorTamper corrupts an existing Message-
// Authenticator attribute's value (breaking its HMAC), probing whether
// the server actually validates it rather than just checking presence/
// length. A no-op (attrs returned unchanged) if the seed has no type-80
// entry — most seeds built for a server with
// require_message_authenticator = no won't.
func mutateMessageAuthenticatorTamper(rng *rand.Rand, attrs []AttrSpec) ([]AttrSpec, string) {
	for i, a := range attrs {
		t, err := resolveAttrType(a.Type)
		if err != nil || t != 80 {
			continue
		}
		b := make([]byte, 16)
		rng.Read(b)
		attrs[i].Value = hexValue(b)
		attrs[i].Length = nil
		return attrs, fmt.Sprintf("message_authenticator_tamper: attrs[%d] -> random 16 bytes", i)
	}
	return attrs, "message_authenticator_tamper: no Message-Authenticator in seed"
}

// runFuzzScenario mutates sc's seed packet (Code/ID/Authenticator/Attrs,
// same fields as type: packet) across sc.Iterations sent packets,
// round-robining through sc.Strategies (or every registered mutator, in
// sorted order, if unset). Any mutated packet that unexpectedly gets
// Access-Accept back is logged as a finding; a network error other than a
// timeout, or a failed periodic health-check against the unmutated seed,
// is treated as a sign the server has died or degraded and aborts the run
// early. Findings and an aborted-early run both make the scenario return
// an error, same as an unmet response: assertion on other scenario types.
func runFuzzScenario(addr, secret string, timeout time.Duration, sc Scenario) error {
	code, err := resolveRadiusCode(sc.Code)
	if err != nil {
		return err
	}
	var id *byte
	if sc.ID != nil {
		b := byte(*sc.ID)
		id = &b
	}

	seedPkt, err := buildPacketFromSpec(secret, code, id, sc.Authenticator, sc.Attrs)
	if err != nil {
		return fmt.Errorf("build seed packet: %w", err)
	}

	strategies := sc.Strategies
	if len(strategies) == 0 {
		strategies = sortedFuzzStrategyNames()
	}

	seed := time.Now().UnixNano()
	if sc.Seed != nil {
		seed = *sc.Seed
	}
	rng := rand.New(rand.NewSource(seed))
	log.Printf("[fuzz] seed=%d iterations=%d strategies=%v", seed, sc.Iterations, strategies)

	healthcheckEvery := sc.HealthcheckEvery
	if healthcheckEvery == 0 {
		healthcheckEvery = 20
	}
	expectNoAccept := true
	if sc.ExpectNoAccept != nil {
		expectNoAccept = *sc.ExpectNoAccept
	}

	checkHealth := func() error {
		resp, err := sendRawUDP(addr, seedPkt, timeout)
		if err != nil {
			return fmt.Errorf("seed packet: %w", err)
		}
		if len(resp) == 0 || resp[0] != 2 {
			got := "no response"
			if len(resp) > 0 {
				got = fmt.Sprintf("code %d (%s)", resp[0], radiusCodeName(resp[0]))
			}
			return fmt.Errorf("seed packet no longer accepted: got %s", got)
		}
		return nil
	}

	if err := checkHealth(); err != nil {
		return fmt.Errorf("[fuzz] baseline health-check failed before fuzzing started: %w", err)
	}

	var findings int
	ran := 0
	for i := 0; i < sc.Iterations; i++ {
		strategy := strategies[i%len(strategies)]
		mutated, desc := fuzzStrategies[strategy](rng, cloneAttrs(sc.Attrs))

		pkt, err := buildPacketFromSpec(secret, code, id, sc.Authenticator, mutated)
		if err != nil {
			log.Printf("[fuzz i=%d strategy=%s] build error (itself a valid finding, logged not counted): %v", i, strategy, err)
			ran++
			continue
		}

		resp, err := sendRawUDP(addr, pkt, timeout)
		ran++
		if err != nil {
			if isNetTimeout(err) {
				log.Printf("[fuzz i=%d strategy=%s] %s -> timeout (dropped, as expected for a malformed packet)", i, strategy, desc)
			} else {
				log.Printf("[fuzz i=%d strategy=%s] %s -> CRITICAL: network error, server may be unreachable: %v", i, strategy, desc, err)
				log.Printf("[fuzz] request hex: %x", pkt)
				log.Printf("[fuzz] aborting after %d/%d iterations", ran, sc.Iterations)
				return fmt.Errorf("server became unreachable after %d iterations: %w", ran, err)
			}
		} else {
			respCode := resp[0]
			if respCode == 2 && expectNoAccept {
				findings++
				log.Printf("[fuzz i=%d strategy=%s] %s -> FINDING: unexpected Access-Accept", i, strategy, desc)
				log.Printf("[fuzz] request hex:  %x", pkt)
				log.Printf("[fuzz] response hex: %x", resp)
			} else {
				log.Printf("[fuzz i=%d strategy=%s] %s -> code %d (%s)", i, strategy, desc, respCode, radiusCodeName(respCode))
			}
		}

		if healthcheckEvery > 0 && (i+1)%healthcheckEvery == 0 {
			if err := checkHealth(); err != nil {
				log.Printf("[fuzz] CRITICAL: health-check failed after %d/%d iterations: %v", ran, sc.Iterations, err)
				return fmt.Errorf("server degraded after %d iterations: %w", ran, err)
			}
		}
	}

	if err := checkHealth(); err != nil {
		log.Printf("[fuzz] CRITICAL: final health-check failed after %d iterations: %v", ran, err)
		return fmt.Errorf("server degraded after %d iterations: %w", ran, err)
	}

	log.Printf("[fuzz] summary: %d iteration(s) run, %d finding(s)", ran, findings)
	if findings > 0 {
		return fmt.Errorf("%d fuzz finding(s) (unexpected Access-Accept)", findings)
	}
	return nil
}
