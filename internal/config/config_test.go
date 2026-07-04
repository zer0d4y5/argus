package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsWhenNoFile(t *testing.T) {
	t.Chdir(t.TempDir()) // no appsec.yml here
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") with no file: %v", err)
	}
	if cfg.FailSeverity != "high" || cfg.Format != "markdown" || cfg.TimeoutSec != 600 {
		t.Errorf("defaults wrong: %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("defaults must validate: %v", err)
	}
}

func TestLoadExplicitMissingPathIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yml")); err == nil {
		t.Error("an explicitly named missing config file must be an error, not silent defaults")
	}
}

func TestLoadMergesOverDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appsec.yml")
	content := "fail_severity: critical\nignore_paths:\n  - vendor/**\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailSeverity != "critical" {
		t.Errorf("FailSeverity = %q, want critical", cfg.FailSeverity)
	}
	if cfg.Format != "markdown" || cfg.TimeoutSec != 600 {
		t.Errorf("unspecified fields must keep defaults: %+v", cfg)
	}
	if len(cfg.IgnorePaths) != 1 || cfg.IgnorePaths[0] != "vendor/**" {
		t.Errorf("IgnorePaths = %v", cfg.IgnorePaths)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.FailSeverity = "severe" },
		func(c *Config) { c.Format = "xml" },
		func(c *Config) { c.TimeoutSec = 0 },
	} {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate must reject %+v", cfg)
		}
	}
}
