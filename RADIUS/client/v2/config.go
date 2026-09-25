package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML scenario-config file (-c / -config).
type Config struct {
	Addr      string     `yaml:"addr"`
	Secret    string     `yaml:"secret"`
	Timeout   string     `yaml:"timeout"`
	Scenarios []Scenario `yaml:"scenarios"`
}

// Scenario is one entry in the scenarios list. Not every field applies to
// every Type; see loadConfig/validate for which fields are required per
// type.
type Scenario struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"` // "raw" | "packet"
	Addr    string `yaml:"addr"`
	Secret  string `yaml:"secret"`
	Timeout string `yaml:"timeout"`

	// Response, if set, is the outcome this scenario must get to count as
	// a pass. It's either the RADIUS response code (numeric, a full name
	// like "Access-Accept", or a short alias: "Accept" | "Reject" |
	// "Challenge") the scenario must get back, or the special value
	// "Timeout" asserting the opposite — that the server must NOT respond
	// at all within the configured timeout (e.g. a malformed packet a
	// well-behaved server should silently drop). Applies to raw and
	// packet. Left empty, no assertion is made and the scenario passes as
	// long as it ran without a network/protocol error (today's default
	// behavior).
	Response string `yaml:"response"`

	// raw
	PacketHex string `yaml:"packet_hex"`

	// packet: builds one RADIUS packet entirely from these explicit
	// fields — nothing is added automatically beyond what Attrs lists.
	// Use this for full manual control over framing, e.g. testing how a
	// server handles a request missing something the normal encoder would
	// otherwise always include. A Message-Authenticator entry in Attrs
	// that gives neither value nor length is computed automatically
	// (RFC 2869 HMAC-MD5 over the whole packet); give it an explicit
	// value/length for full manual control instead. Well-known IPv4
	// attributes (NAS-IP-Address, Framed-IP-Address, Framed-IP-Netmask,
	// Login-IP-Host) similarly auto-encode a dotted-quad value string as
	// its 4 raw octets rather than literal ASCII text. If Authenticator
	// is left empty and Code is Accounting-Request or Status-Server, the
	// Request Authenticator is also computed automatically per RFC 5997
	// §3 / RFC 2866 §3 (MD5 of the header+attributes+secret) instead of
	// being random — required by some servers (though this repo's own
	// FreeRADIUS test config happens not to enforce it).
	Code          string     `yaml:"code"`          // RADIUS code, numeric or name (e.g. "Access-Request"); default Access-Request
	ID            *int       `yaml:"id"`            // Identifier byte (0-255); omitted = random
	Authenticator string     `yaml:"authenticator"` // 16-byte Request Authenticator, hex; omitted = random
	Attrs         []AttrSpec `yaml:"attrs"`

	// fuzz: mutates the Code/ID/Authenticator/Attrs seed packet above
	// (same fields as type: packet) across Iterations sent packets,
	// applying one of Strategies (round-robin) each time. See fuzz.go for
	// the mutator registry and runFuzzScenario for the finding/
	// health-check logic.
	Iterations       int            `yaml:"iterations"`        // required (> 0): number of mutated packets to send
	Seed             *int64         `yaml:"seed"`              // optional PRNG seed for a reproducible run; random (and logged) if omitted
	Strategies       []StrategySpec `yaml:"strategies"`        // optional subset of mutator names, each optionally pinned to a target: attribute (see StrategySpec); default: all registered mutators, each with a random target
	HealthcheckEvery int            `yaml:"healthcheck_every"` // optional: resend the unmutated seed every N iterations to detect server death/hang; default 20
	ExpectNoAccept   *bool          `yaml:"expect_no_accept"`  // optional: flag any mutated packet that gets Access-Accept as a finding; default true
	BaselineResponse string         `yaml:"baseline_response"` // optional: the code the unmutated seed itself must get back for the health-check to pass; default Access-Accept. Set to e.g. "Challenge" for a server that always challenges a valid first request (OTP-only flow) — the unmutated seed there never gets a plain Accept, so the default would otherwise fail the health-check immediately. Cannot be "Timeout" (the health-check needs an actual response).

	// fuzz, marked_range strategy only: sweeps values read from a file into
	// whichever attrs[].value contains the literal "<FUZZ>" marker (e.g.
	// value: "<FUZZ>" or value: "user-<FUZZ>@example.com"), substituting the
	// next line from FuzzList each time this strategy runs — cycling back to
	// the first line once the list is exhausted (a no-op if unset, or if no
	// attrs[] value has the marker). See mutateMarkedRange in fuzz.go.
	FuzzList string `yaml:"fuzzlist"` // path to a file with one substitution value per line

	// challenge: drives Code/ID/Authenticator/Attrs above as the FIRST
	// Access-Request (must get an Access-Challenge back), then
	// brute-forces a numeric OTP in OTPAttr against the returned State
	// across up to MaxAttempts second requests, checking rate-limiting/
	// lockout behavior and whether State stays valid/reusable across many
	// wrong guesses. See stateful.go.
	OTPAttr     string   `yaml:"otp_attr"`     // attribute carrying the OTP guess; default User-Password
	OTPMin      *int     `yaml:"otp_min"`      // numeric OTP range start (required)
	OTPMax      *int     `yaml:"otp_max"`      // numeric OTP range end (required)
	OTPDigits   int      `yaml:"otp_digits"`   // zero-padded width; default = digit count of otp_max
	OTPOrder    string   `yaml:"otp_order"`    // "sequential" | "random"; default sequential
	MaxAttempts int      `yaml:"max_attempts"` // required (> 0): hard cap on attempts sent — mandatory safety bound
	StateReuse  *bool    `yaml:"state_reuse"`  // default true: replay the ORIGINAL State every attempt (tests reuse/lockout)
	Delay       string   `yaml:"delay"`        // optional Go duration between attempts; default 0
	StateChecks []string `yaml:"state_checks"` // optional one-shot probes after the loop: bit_flip | truncate | foreign | drop
}

// AttrSpec is one explicit attribute in a "packet" scenario's Attrs list.
type AttrSpec struct {
	Type   string `yaml:"type"`   // numeric RADIUS type (0-255) or a known name (see dictionary.go)
	Length *int   `yaml:"length"` // explicit Length byte override; omitted = 2+len(value) (with the same oversized-value wrap as appendAttr's default encoding)
	Value  string `yaml:"value"`  // literal UTF-8 string, or hex:<hexstring>
}

// StrategySpec is one entry in a "fuzz" scenario's Strategies list. It
// accepts two YAML forms:
//
//	strategies: [length_mismatch, bit_flip]         # bare name: no Target (random attribute, the original behavior)
//	strategies:
//	  - strategy: length_mismatch
//	    target: User-Password                       # pin this strategy to a specific attribute
//
// Target is a numeric RADIUS type or a known name (see dictionary.go),
// same as AttrSpec.Type. It's ignored by message_authenticator_tamper and
// marked_range, which already locate their own attribute; every other
// registered mutator uses it in place of picking a random attribute, and
// config.go's validate() requires that attribute to actually be present
// in the scenario's seed Attrs when Target is set.
type StrategySpec struct {
	Strategy string `yaml:"strategy"`
	Target   string `yaml:"target"`
}

// UnmarshalYAML implements the two accepted forms described on
// StrategySpec: a bare scalar name, or a {strategy, target} mapping.
func (s *StrategySpec) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		s.Target = ""
		return value.Decode(&s.Strategy)
	}
	type strategySpecAlias StrategySpec // avoid recursing back into this method
	var aux strategySpecAlias
	if err := value.Decode(&aux); err != nil {
		return fmt.Errorf("strategies[]: must be a strategy name or a {strategy, target} mapping: %w", err)
	}
	*s = StrategySpec(aux)
	return nil
}

// loadConfig reads and parses the YAML file at path.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

// validate checks required fields per scenario Type, rejects unknown Type
// values and duplicate scenario names.
func (c *Config) validate() error {
	if len(c.Scenarios) == 0 {
		return fmt.Errorf("config has no scenarios")
	}
	seen := make(map[string]bool, len(c.Scenarios))
	for i, sc := range c.Scenarios {
		label := sc.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		if sc.Name != "" {
			if seen[sc.Name] {
				return fmt.Errorf("scenario %s: duplicate name", label)
			}
			seen[sc.Name] = true
		}

		if sc.Response != "" && !isTimeoutResponse(sc.Response) {
			if _, err := resolveExpectedResponse(sc.Response); err != nil {
				return fmt.Errorf("scenario %s: response: %w", label, err)
			}
		}

		switch sc.Type {
		case "raw":
			if sc.PacketHex == "" {
				return fmt.Errorf("scenario %s: type raw requires packet_hex", label)
			}
		case "packet":
			if len(sc.Attrs) == 0 {
				return fmt.Errorf("scenario %s: type packet requires at least one entry in attrs", label)
			}
			if err := validateSeedPacket(sc); err != nil {
				return fmt.Errorf("scenario %s: %w", label, err)
			}
		case "fuzz":
			if len(sc.Attrs) == 0 {
				return fmt.Errorf("scenario %s: type fuzz requires at least one entry in attrs (the seed packet)", label)
			}
			if err := validateSeedPacket(sc); err != nil {
				return fmt.Errorf("scenario %s: %w", label, err)
			}
			if sc.Iterations <= 0 {
				return fmt.Errorf("scenario %s: type fuzz requires iterations > 0", label)
			}
			if sc.HealthcheckEvery < 0 {
				return fmt.Errorf("scenario %s: healthcheck_every must be >= 0", label)
			}
			for i, s := range sc.Strategies {
				if !isKnownFuzzStrategy(s.Strategy) {
					return fmt.Errorf("scenario %s: unknown fuzz strategy %q", label, s.Strategy)
				}
				if s.Target != "" && isTargetableFuzzStrategy(s.Strategy) {
					t, err := resolveAttrType(s.Target)
					if err != nil {
						return fmt.Errorf("scenario %s: strategies[%d]: target: %w", label, i, err)
					}
					found := false
					for _, a := range sc.Attrs {
						if at, aerr := resolveAttrType(a.Type); aerr == nil && at == t {
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("scenario %s: strategies[%d]: target %q not present in seed attrs", label, i, s.Target)
					}
				}
			}
			if sc.BaselineResponse != "" {
				if isTimeoutResponse(sc.BaselineResponse) {
					return fmt.Errorf("scenario %s: baseline_response cannot be Timeout (the health-check needs an actual response code)", label)
				}
				if _, err := resolveExpectedResponse(sc.BaselineResponse); err != nil {
					return fmt.Errorf("scenario %s: baseline_response: %w", label, err)
				}
			}
			if sc.FuzzList != "" {
				if _, err := os.Stat(sc.FuzzList); err != nil {
					return fmt.Errorf("scenario %s: fuzzlist: %w", label, err)
				}
			}
		case "challenge":
			if len(sc.Attrs) == 0 {
				return fmt.Errorf("scenario %s: type challenge requires at least one entry in attrs (the first Access-Request)", label)
			}
			if err := validateSeedPacket(sc); err != nil {
				return fmt.Errorf("scenario %s: %w", label, err)
			}
			if sc.OTPMin == nil || sc.OTPMax == nil {
				return fmt.Errorf("scenario %s: type challenge requires otp_min and otp_max", label)
			}
			if *sc.OTPMin < 0 || *sc.OTPMax < *sc.OTPMin {
				return fmt.Errorf("scenario %s: otp_min/otp_max must satisfy 0 <= otp_min <= otp_max", label)
			}
			if sc.MaxAttempts <= 0 {
				return fmt.Errorf("scenario %s: type challenge requires max_attempts > 0", label)
			}
			switch sc.OTPOrder {
			case "", "sequential", "random":
			default:
				return fmt.Errorf("scenario %s: otp_order must be \"sequential\" or \"random\"", label)
			}
			if sc.Delay != "" {
				if _, err := time.ParseDuration(sc.Delay); err != nil {
					return fmt.Errorf("scenario %s: invalid delay %q: %w", label, sc.Delay, err)
				}
			}
			for _, s := range sc.StateChecks {
				if !isKnownStateCheck(s) {
					return fmt.Errorf("scenario %s: unknown state_checks entry %q", label, s)
				}
			}
		case "":
			return fmt.Errorf("scenario %s: missing type", label)
		default:
			return fmt.Errorf("scenario %s: unknown type %q (want raw, packet, fuzz, or challenge)", label, sc.Type)
		}
	}
	return nil
}

// validateSeedPacket checks the id/authenticator/attrs fields shared by
// the packet, fuzz, and challenge scenario types (all of which build at
// least one packet from Code/ID/Authenticator/Attrs).
func validateSeedPacket(sc Scenario) error {
	if sc.ID != nil && (*sc.ID < 0 || *sc.ID > 255) {
		return fmt.Errorf("id must be 0-255")
	}
	if sc.Authenticator != "" {
		b, err := hex.DecodeString(sc.Authenticator)
		if err != nil || len(b) != 16 {
			return fmt.Errorf("authenticator must be exactly 16 bytes of hex")
		}
	}
	for i, a := range sc.Attrs {
		if a.Type == "" {
			return fmt.Errorf("attrs[%d]: missing type", i)
		}
		if a.Length != nil && (*a.Length < 0 || *a.Length > 255) {
			return fmt.Errorf("attrs[%d]: length must be 0-255", i)
		}
	}
	return nil
}

// resolved holds the fully-merged (defaults-applied, duration-parsed)
// runtime settings for one scenario run.
type resolved struct {
	Addr    string
	Secret  string
	Timeout time.Duration
}

// resolveScenario merges cfg's top-level defaults with sc's per-scenario
// overrides (empty override = inherit default) and parses the timeout
// duration string.
func resolveScenario(cfg *Config, sc Scenario) (resolved, error) {
	r := resolved{
		Addr:   firstNonEmpty(sc.Addr, cfg.Addr),
		Secret: firstNonEmpty(sc.Secret, cfg.Secret),
	}
	timeoutStr := firstNonEmpty(sc.Timeout, cfg.Timeout)
	if timeoutStr == "" {
		r.Timeout = 5 * time.Second
	} else {
		d, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return resolved{}, fmt.Errorf("invalid timeout %q: %w", timeoutStr, err)
		}
		r.Timeout = d
	}
	if r.Addr == "" {
		return resolved{}, fmt.Errorf("no addr configured (set addr at top level or on the scenario)")
	}
	return r, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
