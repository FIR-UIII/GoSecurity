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
	Type    string `yaml:"type"` // "raw" | "fuzz" | "otp" | "packet"
	Addr    string `yaml:"addr"`
	Secret  string `yaml:"secret"`
	Timeout string `yaml:"timeout"`

	// Response, if set, is the RADIUS response code this scenario must get
	// back to count as a pass (numeric, a full name like "Access-Accept",
	// or a short alias: "Accept" | "Reject" | "Challenge"). Applies to
	// otp, raw, fuzz, and packet. Left empty, no assertion is made and the
	// scenario passes as long as it ran without a network/protocol error
	// (today's default behavior). For "fuzz", every case in the wordlist
	// is checked against it, not just the last one.
	Response string `yaml:"response"`

	// otp
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	OTP      string `yaml:"otp"`
	OTPEnv   string `yaml:"otp_env"`

	// raw
	PacketHex string `yaml:"packet_hex"`

	// fuzz
	FuzzFile              string `yaml:"fuzz_file"`
	PostResponseDatagrams int    `yaml:"post_response_datagrams"`

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
	// its 4 raw octets rather than literal ASCII text.
	Code          string     `yaml:"code"`          // RADIUS code, numeric or name (e.g. "Access-Request"); default Access-Request
	ID            *int       `yaml:"id"`             // Identifier byte (0-255); omitted = random
	Authenticator string     `yaml:"authenticator"`  // 16-byte Request Authenticator, hex; omitted = random
	Attrs         []AttrSpec `yaml:"attrs"`
}

// AttrSpec is one explicit attribute in a "packet" scenario's Attrs list.
type AttrSpec struct {
	Type   string `yaml:"type"`   // numeric RADIUS type (0-255) or a known name (see dictionary.go)
	Length *int   `yaml:"length"` // explicit Length byte override; omitted = 2+len(value) (with the same oversized-value wrap as fuzz mode)
	Value  string `yaml:"value"`  // literal UTF-8 string, or hex:<hexstring>
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
// values and duplicate scenario names, and enforces the otp/otp_env
// mutual-exclusivity rule.
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

		if sc.Response != "" {
			if _, err := resolveExpectedResponse(sc.Response); err != nil {
				return fmt.Errorf("scenario %s: response: %w", label, err)
			}
		}

		switch sc.Type {
		case "otp":
			if sc.Username == "" || sc.Password == "" {
				return fmt.Errorf("scenario %s: type otp requires username and password", label)
			}
			if sc.OTP == "" && sc.OTPEnv == "" {
				return fmt.Errorf("scenario %s: type otp requires exactly one of otp or otp_env", label)
			}
			if sc.OTP != "" && sc.OTPEnv != "" {
				return fmt.Errorf("scenario %s: otp and otp_env are mutually exclusive", label)
			}
		case "raw":
			if sc.PacketHex == "" {
				return fmt.Errorf("scenario %s: type raw requires packet_hex", label)
			}
		case "fuzz":
			if sc.FuzzFile == "" {
				return fmt.Errorf("scenario %s: type fuzz requires fuzz_file", label)
			}
			if sc.Username == "" || sc.Password == "" {
				return fmt.Errorf("scenario %s: type fuzz requires username and password (seed credentials)", label)
			}
			if sc.PostResponseDatagrams < 0 {
				return fmt.Errorf("scenario %s: post_response_datagrams must be >= 0", label)
			}
		case "packet":
			if len(sc.Attrs) == 0 {
				return fmt.Errorf("scenario %s: type packet requires at least one entry in attrs", label)
			}
			if sc.ID != nil && (*sc.ID < 0 || *sc.ID > 255) {
				return fmt.Errorf("scenario %s: id must be 0-255", label)
			}
			if sc.Authenticator != "" {
				b, err := hex.DecodeString(sc.Authenticator)
				if err != nil || len(b) != 16 {
					return fmt.Errorf("scenario %s: authenticator must be exactly 16 bytes of hex", label)
				}
			}
			for i, a := range sc.Attrs {
				if a.Type == "" {
					return fmt.Errorf("scenario %s: attrs[%d]: missing type", label, i)
				}
				if a.Length != nil && (*a.Length < 0 || *a.Length > 255) {
					return fmt.Errorf("scenario %s: attrs[%d]: length must be 0-255", label, i)
				}
			}
		case "":
			return fmt.Errorf("scenario %s: missing type", label)
		default:
			return fmt.Errorf("scenario %s: unknown type %q (want raw, fuzz, otp, or packet)", label, sc.Type)
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

// resolveOTP returns sc.OTP if set, else the value of the environment
// variable named by sc.OTPEnv. validate() already guarantees exactly one of
// the two is set, and this also errors if otp_env names an unset/empty var.
func resolveOTP(sc Scenario) (string, error) {
	if sc.OTP != "" {
		return sc.OTP, nil
	}
	v, ok := os.LookupEnv(sc.OTPEnv)
	if !ok || v == "" {
		return "", fmt.Errorf("otp_env %q is unset or empty", sc.OTPEnv)
	}
	return v, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
