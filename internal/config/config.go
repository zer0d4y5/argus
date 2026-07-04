// Package config loads and validates the appsec.yml configuration.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the scan configuration.
type Config struct {
	Scanners     []string     `yaml:"scanners"`         // subset to run; empty = all
	Profile      string       `yaml:"profile"`          // fast|standard|max; "" = default (standard)
	SemgrepRules []string     `yaml:"semgrep_rulesets"` // explicit semgrep pack override; empty = profile default
	FailSeverity string       `yaml:"fail_severity"`    // critical|high|medium|low|info|none
	IgnorePaths  []string     `yaml:"ignore_paths"`     // glob patterns to skip
	IgnoreRules  []string     `yaml:"ignore_rules"`     // rule IDs to suppress
	Format       string       `yaml:"format"`           // sarif|markdown|json
	TimeoutSec   int          `yaml:"timeout"`          // per-scanner timeout, seconds
	Triage       TriageConfig `yaml:"triage"`           // AI triage configuration
}

// TriageConfig holds the AI-triage configuration.
type TriageConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Provider         string `yaml:"provider"` // "ollama" | "anthropic"
	Model            string `yaml:"model"`
	Endpoint         string `yaml:"endpoint"`           // ollama base URL
	TimeoutSec       int    `yaml:"timeout"`            // per-LLM-request seconds
	Concurrency      int    `yaml:"concurrency"`        // parallel LLM calls
	MaxFindings      int    `yaml:"max_findings"`       // cap on LLM-triaged findings per run; 0 = unlimited
	ExcludeFP        bool   `yaml:"exclude_fp"`         // drop LLM-marked false positives from report+gate
	AllowSecretCloud bool   `yaml:"allow_secret_cloud"` // permit SECRET findings to be sent to non-local providers
}

// Default returns a Config with sensible default values.
func Default() Config {
	return Config{
		FailSeverity: "high",
		Format:       "markdown",
		TimeoutSec:   600,
		Triage: TriageConfig{
			Enabled:          false,
			Provider:         "ollama",
			Model:            "qwen3.6:35b-a3b",
			Endpoint:         "http://localhost:11434",
			TimeoutSec:       90,
			Concurrency:      4,
			MaxFindings:      200,
			ExcludeFP:        false,
			AllowSecretCloud: false,
		},
	}
}

// Load reads configuration from path. An empty path means "appsec.yml in the
// CWD if present": a missing default file yields Default() silently, but a
// missing EXPLICIT path is an error — silently ignoring a config the user
// asked for would apply the wrong severity gate.
func Load(path string) (Config, error) {
	cfg := Default()
	explicit := path != ""
	if !explicit {
		path = "appsec.yml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config: read %s: %w", path, err)
	}

	// Unmarshal over the defaults so unspecified fields keep default values.
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the configuration for validity.
func (c Config) Validate() error {
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true,
		"low": true, "info": true, "none": true,
	}
	if !validSeverities[c.FailSeverity] {
		return fmt.Errorf("config: invalid fail_severity %q; must be one of critical, high, medium, low, info, none", c.FailSeverity)
	}

	validFormats := map[string]bool{"sarif": true, "markdown": true, "json": true}
	if !validFormats[c.Format] {
		return fmt.Errorf("config: invalid format %q; must be one of sarif, markdown, json", c.Format)
	}

	if c.TimeoutSec <= 0 {
		return fmt.Errorf("config: timeout must be greater than 0")
	}

	if c.Triage.Enabled {
		if c.Triage.Provider != "ollama" && c.Triage.Provider != "anthropic" {
			return fmt.Errorf("config: invalid triage provider %q; must be one of ollama, anthropic", c.Triage.Provider)
		}
		if c.Triage.Model == "" {
			return fmt.Errorf("config: triage model must not be empty")
		}
		if c.Triage.TimeoutSec <= 0 {
			return fmt.Errorf("config: triage timeout must be greater than 0")
		}
		if c.Triage.Concurrency < 1 || c.Triage.Concurrency > 32 {
			return fmt.Errorf("config: triage concurrency must be between 1 and 32 inclusive")
		}
		if c.Triage.MaxFindings < 0 {
			return fmt.Errorf("config: triage max_findings must be >= 0")
		}
	}

	return nil
}
