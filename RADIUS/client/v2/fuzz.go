package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// fuzzMarkerToken marks the spot inside an attrs[].value string that the
// marked_range strategy substitutes a generated value into — e.g.
// value: "<FUZZ>" or value: "user-<FUZZ>@example.com". Modeled on the same
// FUZZ keyword convention ffuf/wfuzz use.
const fuzzMarkerToken = "<FUZZ>"

// fuzzContext carries the per-run state and configuration every mutator
// needs: rng is shared so a fixed seed: reproduces a whole run
// deterministically; from/to/digits/hasRange configure marked_range (see
// mutateMarkedRange) — every other mutator ignores them.
type fuzzContext struct {
	rng      *rand.Rand
	hasRange bool
	from, to int
	digits   int
}

// mutator takes a cloned attrs slice (safe to modify in place) and a
// target (an attribute type name/number from a strategies[] entry's
// target:, or "" to fall back to picking a random attribute — the
// original behavior). It returns the mutated result plus a short
// human-readable description for logging and findings. A mutator that
// has nothing to do against this particular seed/target (e.g.
// message_authenticator_tamper against a seed with no Message-
// Authenticator attribute, marked_range against a seed with no <FUZZ>
// marker, or a target that doesn't resolve to any attribute) returns
// attrs unchanged and a description saying so; runFuzzScenario still
// sends it (a no-op mutation is itself a valid, if uninteresting, data
// point) rather than skipping the iteration.
type mutator func(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string)

// fuzzStrategies is the registry of attribute mutators for the "fuzz"
// scenario type. Each targets a different class of bug per the fuzzing
// methodology: length lies, duplicate/missing attributes, oversized/
// empty/truncated values, unknown types, bit-level corruption, a
// tampered Message-Authenticator, and (marked_range) a targeted
// value-range sweep of a specific, explicitly marked attribute.
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
	"marked_range":                 mutateMarkedRange,
}

// targetableFuzzStrategies is the subset of fuzzStrategies whose target:
// is meaningful (picks which attribute the mutator acts on, instead of a
// random one). message_authenticator_tamper and marked_range already
// locate their own attribute (by type 80, and by the <FUZZ> marker,
// respectively), so a target: on either of those is simply ignored —
// config.go's validate() skips the "target must exist in seed" check for
// them accordingly.
var targetableFuzzStrategies = map[string]bool{
	"length_mismatch":  true,
	"duplicate":        true,
	"missing_required": true,
	"oversized_value":  true,
	"empty_value":      true,
	"unknown_type":     true,
	"bit_flip":         true,
	"truncate":         true,
}

// isKnownFuzzStrategy reports whether name is a registered mutator, used
// by config.go's validate() to reject a typo'd strategies[] entry early.
func isKnownFuzzStrategy(name string) bool {
	_, ok := fuzzStrategies[name]
	return ok
}

// isTargetableFuzzStrategy reports whether name's target: is meaningful
// (see targetableFuzzStrategies).
func isTargetableFuzzStrategy(name string) bool {
	return targetableFuzzStrategies[name]
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

// targetIndex resolves which attrs[] index a mutator should act on: with
// no target, a random index (the original, unchanged default behavior);
// with a target, the first attribute whose resolved type matches it.
// config.go's validate() already guarantees a match exists in the seed
// for every targetable strategy that names one, so a missing match here
// is defensive (e.g. attrs somehow differs from what was validated), not
// the expected path.
func targetIndex(rng *rand.Rand, attrs []AttrSpec, target string) (idx int, ok bool) {
	if target == "" {
		if len(attrs) == 0 {
			return -1, false
		}
		return rng.Intn(len(attrs)), true
	}
	wantType, err := resolveAttrType(target)
	if err != nil {
		return -1, false
	}
	for i, a := range attrs {
		if t, terr := resolveAttrType(a.Type); terr == nil && t == wantType {
			return i, true
		}
	}
	return -1, false
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
func mutateLengthMismatch(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string) {
	i, ok := targetIndex(ctx.rng, attrs, target)
	if !ok {
		return attrs, "length_mismatch: no attrs to target"
	}
	actual := 2 + len(decodeAttrValue(attrs[i]))
	deltas := []int{-actual + 1, -5, -2, -1, 1, 2, 5, 255 - actual}
	delta := deltas[ctx.rng.Intn(len(deltas))]
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
func mutateDuplicate(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string) {
	i, ok := targetIndex(ctx.rng, attrs, target)
	if !ok {
		return attrs, "duplicate: no attrs to target"
	}
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
func mutateMissingRequired(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string) {
	i, ok := targetIndex(ctx.rng, attrs, target)
	if !ok {
		return attrs, "missing_required: no attrs to target"
	}
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
func mutateOversizedValue(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string) {
	i, ok := targetIndex(ctx.rng, attrs, target)
	if !ok {
		return attrs, "oversized_value: no attrs to target"
	}
	b := make([]byte, 300)
	ctx.rng.Read(b)
	attrs[i].Value = hexValue(b)
	attrs[i].Length = nil
	return attrs, fmt.Sprintf("oversized_value: attrs[%d] (%s) -> %d random bytes", i, attrs[i].Type, len(b))
}

// mutateEmptyValue replaces one random attribute's value with zero bytes,
// probing handling of an attribute with Length == 2 (Type|Length, no
// Value at all). Uses an explicit "hex:" (rather than a bare "") so this
// stays a truly empty attribute even when it lands on User-Password,
// which would otherwise auto-PAP-encrypt a bare "" into a 16-byte padded
// block instead (see appendAttrSpec in packet.go) — the hex: prefix
// always means "these exact raw bytes", bypassing that.
func mutateEmptyValue(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string) {
	i, ok := targetIndex(ctx.rng, attrs, target)
	if !ok {
		return attrs, "empty_value: no attrs to target"
	}
	attrs[i].Value = "hex:"
	attrs[i].Length = nil
	return attrs, fmt.Sprintf("empty_value: attrs[%d] (%s)", i, attrs[i].Type)
}

// mutateUnknownType changes one random attribute's Type to a numeric value
// not present in the well-known dictionary (dictionary.go), probing how
// the server handles an attribute it doesn't recognize.
func mutateUnknownType(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string) {
	i, ok := targetIndex(ctx.rng, attrs, target)
	if !ok {
		return attrs, "unknown_type: no attrs to target"
	}
	var t byte
	for {
		t = byte(ctx.rng.Intn(256))
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
func mutateBitFlip(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string) {
	if target != "" {
		i, ok := targetIndex(ctx.rng, attrs, target)
		if !ok {
			return attrs, "bit_flip: no attrs to target"
		}
		b := decodeAttrValue(attrs[i])
		if len(b) == 0 {
			return attrs, fmt.Sprintf("bit_flip: attrs[%d] (%s) has an empty value, nothing to flip", i, attrs[i].Type)
		}
		byteIdx := ctx.rng.Intn(len(b))
		bitIdx := ctx.rng.Intn(8)
		b[byteIdx] ^= 1 << bitIdx
		attrs[i].Value = hexValue(b)
		attrs[i].Length = nil
		return attrs, fmt.Sprintf("bit_flip: attrs[%d] (%s) byte %d bit %d", i, attrs[i].Type, byteIdx, bitIdx)
	}
	// No target: keep the original random-with-retry behavior — try a
	// few random attrs before giving up, since a randomly picked one
	// might happen to have an empty value (nothing to flip).
	for attempt := 0; attempt < 10; attempt++ {
		if len(attrs) == 0 {
			break
		}
		i := ctx.rng.Intn(len(attrs))
		b := decodeAttrValue(attrs[i])
		if len(b) == 0 {
			continue
		}
		byteIdx := ctx.rng.Intn(len(b))
		bitIdx := ctx.rng.Intn(8)
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
func mutateTruncate(ctx *fuzzContext, attrs []AttrSpec, target string) ([]AttrSpec, string) {
	if target != "" {
		i, ok := targetIndex(ctx.rng, attrs, target)
		if !ok {
			return attrs, "truncate: no attrs to target"
		}
		b := decodeAttrValue(attrs[i])
		if len(b) == 0 {
			return attrs, fmt.Sprintf("truncate: attrs[%d] (%s) has an empty value, nothing to truncate", i, attrs[i].Type)
		}
		newLen := ctx.rng.Intn(len(b))
		attrs[i].Value = hexValue(b[:newLen])
		attrs[i].Length = nil
		return attrs, fmt.Sprintf("truncate: attrs[%d] (%s) %d -> %d bytes", i, attrs[i].Type, len(b), newLen)
	}
	for attempt := 0; attempt < 10; attempt++ {
		if len(attrs) == 0 {
			break
		}
		i := ctx.rng.Intn(len(attrs))
		b := decodeAttrValue(attrs[i])
		if len(b) == 0 {
			continue
		}
		newLen := ctx.rng.Intn(len(b))
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
func mutateMessageAuthenticatorTamper(ctx *fuzzContext, attrs []AttrSpec, _ string) ([]AttrSpec, string) {
	for i, a := range attrs {
		t, err := resolveAttrType(a.Type)
		if err != nil || t != 80 {
			continue
		}
		b := make([]byte, 16)
		ctx.rng.Read(b)
		attrs[i].Value = hexValue(b)
		attrs[i].Length = nil
		return attrs, fmt.Sprintf("message_authenticator_tamper: attrs[%d] -> random 16 bytes", i)
	}
	return attrs, "message_authenticator_tamper: no Message-Authenticator in seed"
}

// mutateMarkedRange targets the first attrs[] entry whose value contains
// the literal fuzzMarkerToken ("<FUZZ>") and substitutes it with a number
// drawn from [ctx.from, ctx.to] (inclusive), formatted as a plain decimal
// string — zero-padded to ctx.digits if set. This is the targeted
// counterpart to the other, randomly-targeted structural mutators: it
// lets a scenario aim a value-range sweep (e.g. a numeric OTP/PIN space,
// or any other bounded value) at one specific attribute instead of
// leaving the target to chance. A plain (non-hex:) substitution into
// User-Password is PAP-encrypted automatically, same as any other
// plain User-Password value (see appendAttrSpec in packet.go).
//
// A no-op (attrs unchanged) if ctx has no configured range (from/to
// unset) or the seed has no <FUZZ> marker in any attribute — same
// no-op convention as mutateMessageAuthenticatorTamper, so this strategy
// is safe to leave in the default "all strategies" rotation even for a
// seed that isn't using it.
func mutateMarkedRange(ctx *fuzzContext, attrs []AttrSpec, _ string) ([]AttrSpec, string) {
	if !ctx.hasRange {
		return attrs, "marked_range: no from/to range configured"
	}
	idx := -1
	for i, a := range attrs {
		if strings.Contains(a.Value, fuzzMarkerToken) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return attrs, "marked_range: no " + fuzzMarkerToken + " marker in seed"
	}

	span := ctx.to - ctx.from + 1
	candidate := ctx.from + ctx.rng.Intn(span)
	replacement := fmt.Sprintf("%d", candidate)
	if ctx.digits > 0 {
		replacement = fmt.Sprintf("%0*d", ctx.digits, candidate)
	}

	attrs[idx].Value = strings.ReplaceAll(attrs[idx].Value, fuzzMarkerToken, replacement)
	attrs[idx].Length = nil
	return attrs, fmt.Sprintf("marked_range: attrs[%d] (%s) %s -> %s", idx, attrs[idx].Type, fuzzMarkerToken, replacement)
}

// formatStrategies renders a []StrategySpec for the startup log line,
// e.g. "length_mismatch(target=User-Password), bit_flip".
func formatStrategies(specs []StrategySpec) string {
	parts := make([]string, len(specs))
	for i, s := range specs {
		if s.Target == "" {
			parts[i] = s.Strategy
		} else {
			parts[i] = fmt.Sprintf("%s(target=%s)", s.Strategy, s.Target)
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
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
		for _, name := range sortedFuzzStrategyNames() {
			strategies = append(strategies, StrategySpec{Strategy: name})
		}
	}

	seed := time.Now().UnixNano()
	if sc.Seed != nil {
		seed = *sc.Seed
	}
	ctx := &fuzzContext{rng: rand.New(rand.NewSource(seed))}
	if sc.From != nil && sc.To != nil {
		ctx.hasRange = true
		ctx.from = *sc.From
		ctx.to = *sc.To
		ctx.digits = sc.FuzzDigits
	}

	// The health-check (initial, periodic, and final) requires the
	// unmutated seed to keep getting this exact code back. Defaults to
	// Access-Accept, but a server that always challenges a valid first
	// request (OTP-only flow, no direct single-shot Accept) needs this
	// set to Challenge — otherwise the health-check fails immediately on
	// a perfectly valid seed. This is independent of expectNoAccept
	// below, which is about MUTATED packets, not the seed.
	baselineCode := byte(2)
	if sc.BaselineResponse != "" {
		baselineCode, err = resolveRadiusCode(sc.BaselineResponse)
		if err != nil {
			return err
		}
	}
	log.Printf("[fuzz] seed=%d iterations=%d strategies=%s baseline_response=%d (%s)",
		seed, sc.Iterations, formatStrategies(strategies), baselineCode, radiusCodeName(baselineCode))

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
		if len(resp) == 0 || resp[0] != baselineCode {
			got := "no response"
			if len(resp) > 0 {
				got = fmt.Sprintf("code %d (%s)", resp[0], radiusCodeName(resp[0]))
			}
			return fmt.Errorf("seed packet no longer accepted: expected code %d (%s), got %s", baselineCode, radiusCodeName(baselineCode), got)
		}
		return nil
	}

	if err := checkHealth(); err != nil {
		return fmt.Errorf("[fuzz] baseline health-check failed before fuzzing started: %w", err)
	}

	var findings int
	ran := 0
	for i := 0; i < sc.Iterations; i++ {
		spec := strategies[i%len(strategies)]
		strategy := spec.Strategy
		mutated, desc := fuzzStrategies[spec.Strategy](ctx, cloneAttrs(sc.Attrs), spec.Target)

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
