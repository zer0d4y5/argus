// Package config loads and validates the appsec.yml configuration.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the scan configuration.
type Config struct {
	Scanners     []string `yaml:"scanners"`      // subset to run; empty = all
	FailSeverity string   `yaml:"fail_severity"` // critical|high|medium|low|info|none
	IgnorePaths  []string `yaml:"ignore_paths"`  // glob patterns to skip
	IgnoreRules  []string `yaml:"ignore_rules"`  // rule IDs to suppress
	Format       string   `yaml:"format"`        // sarif|markdown|json
	TimeoutSec   int      `yaml:"timeout"`       // per-scanner timeout, seconds
}

// Default returns a Config with sensible default values.
func Default() Config {
	return Config{
		FailSeverity: "high",
		Format:       "markdown",
		TimeoutSec:   600,
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
	return nil
}
