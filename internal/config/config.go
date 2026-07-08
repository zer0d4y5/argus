// Package config loads and validates the appsec.yml configuration.
package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config holds the scan configuration.
type Config struct {
	Scanners     []string          `yaml:"scanners"`         // subset to run; empty = all
	Profile      string            `yaml:"profile"`          // fast|standard|max; "" = default (standard)
	SemgrepRules []string          `yaml:"semgrep_rulesets"` // explicit semgrep pack override; empty = profile default
	FailSeverity string            `yaml:"fail_severity"`    // critical|high|medium|low|info|none
	IgnorePaths  []string          `yaml:"ignore_paths"`     // glob patterns to skip
	IgnoreRules  []string          `yaml:"ignore_rules"`     // rule IDs to suppress
	Format       string            `yaml:"format"`           // sarif|markdown|json
	TimeoutSec   int               `yaml:"timeout"`          // per-scanner timeout, seconds
	Triage       TriageConfig      `yaml:"triage"`           // AI triage configuration
	Cloud        CloudConfig       `yaml:"cloud"`            // cloud posture scan configuration
	Ticketing    TicketingConfig   `yaml:"ticketing"`        // external issue-tracker sync (off unless configured)
	Auth         AuthConfig        `yaml:"auth"`             // console authentication (SSO; off unless configured)
	Remediation  RemediationConfig `yaml:"remediation"`      // approved cloud remediation (off unless enabled)
	Exploit      ExploitConfig     `yaml:"exploit"`          // KEV/EPSS exploitation enrichment of risk scores
	Offline      OfflineConfig     `yaml:"offline"`          // air-gapped mode: use only local rules (see `argus rules sync`)
}

// OfflineConfig makes a scan use only local rule sources: the embedded curated
// rules, packs cached by `argus rules sync`, and any local BYO rules, and
// never fetch a registry pack or touch the network. Opt-in (default off): the
// default behaviour still resolves registry packs at scan time. A scan is
// air-gapped from the very first run even with an empty cache, because the
// curated rules are embedded in the binary.
type OfflineConfig struct {
	Enabled  *bool  `yaml:"enabled" json:"enabled"`     // nil/false = normal; true = offline
	CacheDir string `yaml:"cache_dir" json:"cacheDir"` // pack cache dir; default <user-cache>/argus/rules
}

// On reports whether offline mode is active (default: no).
func (o OfflineConfig) On() bool { return o.Enabled != nil && *o.Enabled }

// ExploitConfig controls exploitation-evidence enrichment of the risk score.
// The CISA KEV catalog is embedded and version-pinned, so enrichment is on by
// default and works fully offline; EPSS is a large daily dataset supplied as an
// optional local file (network-free either way).
type ExploitConfig struct {
	Enabled  *bool  `yaml:"enabled" json:"enabled"`     // nil = on; set false to disable KEV/EPSS enrichment
	EPSSFile string `yaml:"epss_file" json:"epssFile"` // optional path to a FIRST EPSS scores CSV
}

// On reports whether exploitation enrichment should run (default: yes).
func (e ExploitConfig) On() bool { return e.Enabled == nil || *e.Enabled }

// RemediationConfig gates approved cloud remediation. Off by default: a
// deliberate opt-in, since applying runs changes against a cloud account. Even
// when enabled, every apply is an explicit admin action over the CURATED
// catalog with a validated write profile — never an LLM-authored command.
type RemediationConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"` // allow executing curated remediations (dry-run + apply)
}

// AuthConfig configures console authentication. Absent means password-only
// (the default). OIDC is opt-in and additive: it never disables local login.
type AuthConfig struct {
	OIDC OIDCConfig `yaml:"oidc"`
}

// OIDCConfig configures single sign-on via OpenID Connect (Google Workspace,
// Microsoft Entra ID, Okta, Auth0, …). The client secret is REFERENCED by
// env-var name and read at flow time — never stored in config, sessions, or
// logs, the same discipline as the GitHub token.
// OIDCConfig carries both yaml (appsec.yml) and json (the console-managed
// .appsec/oidc.json store) tags so the same shape serves the static file and
// the UI-editable store.
type OIDCConfig struct {
	Issuer          string            `yaml:"issuer" json:"issuer"`                     // provider issuer URL; empty = SSO disabled
	ClientID        string            `yaml:"client_id" json:"clientId"`                // public client id
	ClientSecretEnv string            `yaml:"client_secret_env" json:"clientSecretEnv"` // env var holding the secret; default ARGUS_OIDC_SECRET
	RedirectURL     string            `yaml:"redirect_url" json:"redirectUrl"`          // absolute callback URL
	AllowedDomains  []string          `yaml:"allowed_domains" json:"allowedDomains"`    // JIT guard: only these email domains auto-provision; empty = deny JIT
	DefaultRole     string            `yaml:"default_role" json:"defaultRole"`          // role for a JIT-created user; default viewer
	GroupClaim      string            `yaml:"group_claim" json:"groupClaim"`            // optional claim carrying IdP groups
	RoleMap         map[string]string `yaml:"role_map" json:"roleMap"`                  // optional: IdP group -> console role
}

// Enabled reports whether SSO is configured (issuer, client id, redirect).
func (o OIDCConfig) Enabled() bool {
	return o.Issuer != "" && o.ClientID != "" && o.RedirectURL != ""
}

// SecretEnv returns the env var name holding the client secret.
func (o OIDCConfig) SecretEnv() string {
	if o.ClientSecretEnv != "" {
		return o.ClientSecretEnv
	}
	return "ARGUS_OIDC_SECRET"
}

// EffectiveDefaultRole returns the JIT default role, defaulting to viewer.
func (o OIDCConfig) EffectiveDefaultRole() string {
	if o.DefaultRole != "" {
		return o.DefaultRole
	}
	return "viewer"
}

// OIDCEnabled reports whether SSO is configured (issuer, client id, redirect).
func (c Config) OIDCEnabled() bool { return c.Auth.OIDC.Enabled() }

// OIDCSecretEnv returns the env var name holding the client secret.
func (c Config) OIDCSecretEnv() string { return c.Auth.OIDC.SecretEnv() }

// OIDCDefaultRole returns the JIT default role, defaulting to viewer.
func (c Config) OIDCDefaultRole() string { return c.Auth.OIDC.EffectiveDefaultRole() }

// TicketingConfig gates external issue-tracker sync. Absent (the default)
// means fully off: no button, no network call, nothing to leak. The token is
// REFERENCED by env-var name and read at call time — never stored in config,
// tickets, audit records, or logs.
type TicketingConfig struct {
	GitHub GitHubConfig `yaml:"github"`
}

// GitHubConfig configures create-or-link of GitHub issues from tickets.
type GitHubConfig struct {
	Repo     string `yaml:"repo"`      // "owner/name"; empty = sync disabled
	TokenEnv string `yaml:"token_env"` // env var holding the token; default GITHUB_TOKEN
}

// githubRepoPattern is the closed grammar for a repo reference.
var githubRepoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// GitHubEnabled reports whether GitHub sync is configured, after validation.
func (c Config) GitHubEnabled() bool {
	return c.Ticketing.GitHub.Repo != "" && githubRepoPattern.MatchString(c.Ticketing.GitHub.Repo)
}

// GitHubTokenEnv returns the env var name holding the token (never the value).
func (c Config) GitHubTokenEnv() string {
	if v := c.Ticketing.GitHub.TokenEnv; v != "" {
		return v
	}
	return "GITHUB_TOKEN"
}

// CloudConfig holds cloud posture scan settings (schema 2.1.0). Credentials
// are NEVER configured here — only a per-provider run timeout. The profile
// reference is a CLI flag or a registered console target, validated against
// the local config's closed list at run time.
type CloudConfig struct {
	TimeoutSec int `yaml:"timeout"` // whole-scan timeout, seconds (prowler runs are long)
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
		Cloud: CloudConfig{
			TimeoutSec: 1800, // prowler full-account scans routinely take many minutes
		},
	}
}

// DefaultConfigNames are the config filenames Load looks for in the CWD when
// no explicit path is given, in preference order: the Argus name first, the
// legacy appsec name second (accepted for compatibility). The docs use
// argus.yml.
var DefaultConfigNames = []string{"argus.yml", "appsec.yml"}

// Load reads configuration from path. An empty path means "the default config
// file in the CWD if present" (argus.yml, then appsec.yml): a missing
// default file yields Default() silently, but a missing EXPLICIT path is an
// error — silently ignoring a config the user asked for would apply the wrong
// severity gate.
func Load(path string) (Config, error) {
	cfg := Default()
	explicit := path != ""
	if !explicit {
		for _, name := range DefaultConfigNames {
			if _, err := os.Stat(name); err == nil {
				path = name
				break
			}
		}
		if path == "" {
			return cfg, nil // no default config present — use defaults
		}
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
