package main

import (
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
	Type    string `yaml:"type"` // "raw" | "fuzz" | "otp"
	Addr    string `yaml:"addr"`
	Secret  string `yaml:"secret"`
	Timeout string `yaml:"timeout"`

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
		case "":
			return fmt.Errorf("scenario %s: missing type", label)
		default:
			return fmt.Errorf("scenario %s: unknown type %q (want raw, fuzz, or otp)", label, sc.Type)
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
