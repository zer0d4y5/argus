package server

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/scanner"
)

// Console-managed settings. The admin panel edits these and they persist to
// <dir>/.appsec/settings.json, overlaying the served repo's appsec.yml so the
// static file stays a valid fallback (and the CLI keeps using it unchanged).
// Secrets are NEVER here — the GitHub token and the Anthropic key are
// referenced by env-var name and read at call time. OIDC has its own store;
// this covers integrations and scanning.

const settingsStoreFile = "settings.json"

// ConsoleSettings is the JSON envelope of console-managed overrides. A nil
// pointer / empty field means "not managed here — use appsec.yml".
type ConsoleSettings struct {
	GitHub             *config.GitHubConfig `json:"github,omitempty"`
	Triage             *TriageSettings      `json:"triage,omitempty"`
	ScanProfile        string               `json:"scanProfile,omitempty"`  // fast|standard|max
	FailSeverity       string               `json:"failSeverity,omitempty"` // critical|high|medium|low|info|none
	RemediationEnabled *bool                `json:"remediationEnabled,omitempty"`

	// Custom semgrep rulesets: registry packs, the argus/curated sentinel, or
	// local rule file/dir paths. SemgrepRulesetsAdditive true (the console
	// default) adds them to the profile packs; false replaces the profile
	// packs entirely. Empty = not managed here (appsec.yml wins).
	SemgrepRulesets         []string `json:"semgrepRulesets,omitempty"`
	SemgrepRulesetsAdditive *bool    `json:"semgrepRulesetsAdditive,omitempty"`
}

// TriageSettings is the UI-editable subset of the triage config. The Anthropic
// key stays in ANTHROPIC_API_KEY (env), never here.
type TriageSettings struct {
	Enabled     bool   `json:"enabled"`
	Provider    string `json:"provider"` // ollama | anthropic
	Model       string `json:"model"`
	Endpoint    string `json:"endpoint"`
	MaxFindings int    `json:"maxFindings"`
	ExcludeFP   bool   `json:"excludeFp"`
}

func settingsStorePath(dir string) string {
	return filepath.Join(dir, ".appsec", settingsStoreFile)
}

// loadConsoleSettings reads the console settings store (empty when absent).
func loadConsoleSettings(dir string) (ConsoleSettings, error) {
	data, err := os.ReadFile(settingsStorePath(dir))
	if os.IsNotExist(err) {
		return ConsoleSettings{}, nil
	}
	if err != nil {
		return ConsoleSettings{}, err
	}
	var cs ConsoleSettings
	if err := json.Unmarshal(data, &cs); err != nil {
		return ConsoleSettings{}, err
	}
	return cs, nil
}

func saveConsoleSettings(dir string, cs ConsoleSettings) error {
	if err := os.MkdirAll(filepath.Join(dir, ".appsec"), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	path := settingsStorePath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// applyConsoleSettings overlays the store onto a base config in place. Only the
// fields the store manages are touched; everything else keeps its appsec.yml
// value. This is what makes a UI change take effect without editing the file.
func applyConsoleSettings(cfg *config.Config, cs ConsoleSettings) {
	if cs.GitHub != nil {
		cfg.Ticketing.GitHub = *cs.GitHub
	}
	if cs.Triage != nil {
		cfg.Triage.Enabled = cs.Triage.Enabled
		cfg.Triage.Provider = cs.Triage.Provider
		cfg.Triage.Model = cs.Triage.Model
		cfg.Triage.Endpoint = cs.Triage.Endpoint
		cfg.Triage.MaxFindings = cs.Triage.MaxFindings
		cfg.Triage.ExcludeFP = cs.Triage.ExcludeFP
	}
	if cs.ScanProfile != "" {
		cfg.Profile = cs.ScanProfile
	}
	if cs.FailSeverity != "" {
		cfg.FailSeverity = cs.FailSeverity
	}
	if len(cs.SemgrepRulesets) > 0 {
		// The store holds a plain entry list plus an additive flag; the config
		// layer expresses additive as a leading marker, so translate here and
		// keep ResolveSemgrepRulesets the single implementation of the
		// replace-vs-add decision. Additive defaults on when the flag is unset.
		additive := cs.SemgrepRulesetsAdditive == nil || *cs.SemgrepRulesetsAdditive
		if additive {
			cfg.SemgrepRules = append([]string{scanner.AdditiveMarker}, cs.SemgrepRulesets...)
		} else {
			cfg.SemgrepRules = append([]string{}, cs.SemgrepRulesets...)
		}
	}
	if cs.RemediationEnabled != nil {
		cfg.Remediation.Enabled = *cs.RemediationEnabled
	}
}

// effectiveConfig returns the config for root, overlaying the console settings
// store when root is the served repo (or empty). Per-target roots are read
// straight from their own tree — the console store never leaks across targets.
func (s *Server) effectiveConfig(root string) config.Config {
	cfg, err := repoConfig(root)
	if err != nil {
		cfg = config.Default()
	}
	if root == "" || root == s.dir {
		if cs, err := loadConsoleSettings(s.dir); err == nil {
			applyConsoleSettings(&cfg, cs)
		}
	}
	return cfg
}
