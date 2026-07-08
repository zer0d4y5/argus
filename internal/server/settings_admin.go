package server

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/scanner"
)

// Admin console-settings endpoint (admin-only, audited). GET returns the
// effective integration + scanning config the UI edits, plus read-only status
// (which env vars are set, where each value comes from). PUT writes the
// console-managed store and takes effect immediately. Secrets are never
// accepted here — only env-var names.

// SettingsView is the admin GET payload.
type SettingsView struct {
	// GitHub issue sync.
	GitHubRepo     string `json:"githubRepo"`
	GitHubTokenEnv string `json:"githubTokenEnv"`
	GitHubTokenSet bool   `json:"githubTokenSet"`

	// Triage (LLM). The Anthropic key is env-only, reported as set/unset.
	Triage          TriageSettings `json:"triage"`
	AnthropicKeySet bool           `json:"anthropicKeySet"`

	// Scan defaults.
	ScanProfile  string `json:"scanProfile"`
	FailSeverity string `json:"failSeverity"`

	// Custom semgrep rulesets (packs, argus/curated, or local rule paths) and
	// whether they add to (true) or replace (false) the profile packs.
	SemgrepRulesets         []string `json:"semgrepRulesets"`
	SemgrepRulesetsAdditive bool     `json:"semgrepRulesetsAdditive"`

	// Whether curated cloud remediation is enabled.
	RemediationEnabled bool `json:"remediationEnabled"`
}

func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getAdminSettings(w, r)
	case http.MethodPut:
		s.putAdminSettings(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) getAdminSettings(w http.ResponseWriter, _ *http.Request) {
	cfg := s.effectiveConfig(s.dir)
	// Custom rulesets are reported from the console store (the raw entry list
	// plus the additive flag), not from the effective config, so the panel
	// round-trips exactly what the admin set rather than the "+"-marked form.
	cs, _ := loadConsoleSettings(s.dir)
	additive := cs.SemgrepRulesetsAdditive == nil || *cs.SemgrepRulesetsAdditive
	writeJSON(w, http.StatusOK, SettingsView{
		GitHubRepo:     cfg.Ticketing.GitHub.Repo,
		GitHubTokenEnv: cfg.GitHubTokenEnv(),
		GitHubTokenSet: os.Getenv(cfg.GitHubTokenEnv()) != "",
		Triage: TriageSettings{
			Enabled:     cfg.Triage.Enabled,
			Provider:    cfg.Triage.Provider,
			Model:       cfg.Triage.Model,
			Endpoint:    cfg.Triage.Endpoint,
			MaxFindings: cfg.Triage.MaxFindings,
			ExcludeFP:   cfg.Triage.ExcludeFP,
		},
		AnthropicKeySet:         os.Getenv("ANTHROPIC_API_KEY") != "",
		ScanProfile:             cfg.Profile,
		FailSeverity:            cfg.FailSeverity,
		SemgrepRulesets:         cs.SemgrepRulesets,
		SemgrepRulesetsAdditive: additive,
		RemediationEnabled:      cfg.Remediation.Enabled,
	})
}

// SettingsRequest is the admin PUT body. Any section left nil is not managed by
// the console (falls back to appsec.yml). No secret values — only env names.
type SettingsRequest struct {
	GitHubRepo              *string         `json:"githubRepo"`
	GitHubTokenEnv          *string         `json:"githubTokenEnv"`
	Triage                  *TriageSettings `json:"triage"`
	ScanProfile             *string         `json:"scanProfile"`
	FailSeverity            *string         `json:"failSeverity"`
	SemgrepRulesets         *[]string       `json:"semgrepRulesets"`
	SemgrepRulesetsAdditive *bool           `json:"semgrepRulesetsAdditive"`
	RemediationEnabled      *bool           `json:"remediationEnabled"`
}

// maxCustomRulesets bounds the ruleset list so a single admin edit cannot
// queue an unbounded number of semgrep --validate subprocesses.
const maxCustomRulesets = 50

var validProfiles = map[string]bool{"": true, "fast": true, "standard": true, "max": true}
var validProviders = map[string]bool{"": true, "ollama": true, "anthropic": true}

func (s *Server) putAdminSettings(w http.ResponseWriter, r *http.Request) {
	var req SettingsRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Start from the currently-stored console settings so a partial PUT only
	// changes the sections it names.
	cs, _ := loadConsoleSettings(s.dir)

	if req.GitHubRepo != nil || req.GitHubTokenEnv != nil {
		gh := config.GitHubConfig{}
		if cs.GitHub != nil {
			gh = *cs.GitHub
		}
		if req.GitHubRepo != nil {
			gh.Repo = strings.TrimSpace(*req.GitHubRepo)
		}
		if req.GitHubTokenEnv != nil {
			gh.TokenEnv = strings.TrimSpace(*req.GitHubTokenEnv)
		}
		if gh.Repo != "" && !githubRepoOK(gh.Repo) {
			writeErr(w, http.StatusBadRequest, "GitHub repo must look like owner/name")
			return
		}
		cs.GitHub = &gh
	}
	if req.Triage != nil {
		t := *req.Triage
		t.Provider = strings.TrimSpace(strings.ToLower(t.Provider))
		if !validProviders[t.Provider] {
			writeErr(w, http.StatusBadRequest, "triage provider must be ollama or anthropic")
			return
		}
		if t.MaxFindings < 0 {
			writeErr(w, http.StatusBadRequest, "max findings cannot be negative")
			return
		}
		cs.Triage = &t
	}
	if req.ScanProfile != nil {
		p := strings.TrimSpace(*req.ScanProfile)
		if !validProfiles[p] {
			writeErr(w, http.StatusBadRequest, "scan profile must be fast, standard, or max")
			return
		}
		cs.ScanProfile = p
	}
	if req.FailSeverity != nil {
		fs := strings.TrimSpace(*req.FailSeverity)
		if fs != "" && fs != "none" {
			if _, err := model.ParseGate(fs); err != nil {
				writeErr(w, http.StatusBadRequest, "fail severity must be critical, high, medium, low, info, or none")
				return
			}
		}
		cs.FailSeverity = fs
	}
	if req.SemgrepRulesetsAdditive != nil {
		cs.SemgrepRulesetsAdditive = req.SemgrepRulesetsAdditive
	}
	if req.SemgrepRulesets != nil {
		cleaned := cleanRulesetList(*req.SemgrepRulesets)
		if len(cleaned) > maxCustomRulesets {
			writeErr(w, http.StatusBadRequest, "too many custom rulesets")
			return
		}
		// Reject a list that references a missing or malformed rule BEFORE it is
		// persisted, so a bad rule surfaces as a clear error here rather than
		// silently degrading every future scan. Registry packs resolve at scan
		// time and are not network-checked here.
		if len(cleaned) > 0 {
			statuses := scanner.ValidateRulesets(r.Context(), cleaned, s.dir)
			if bad := scanner.FirstInvalid(statuses); bad != nil {
				writeErr(w, http.StatusBadRequest, bad.Message)
				return
			}
		}
		cs.SemgrepRulesets = cleaned
	}
	if req.RemediationEnabled != nil {
		cs.RemediationEnabled = req.RemediationEnabled
	}

	if err := saveConsoleSettings(s.dir, cs); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save settings")
		return
	}
	s.audit(audit.EventConfigChange, actorFrom(r), map[string]string{"area": "settings"})
	s.getAdminSettings(w, r)
}

func githubRepoOK(repo string) bool {
	c := config.Config{}
	c.Ticketing.GitHub.Repo = repo
	return c.GitHubEnabled()
}

// cleanRulesetList trims entries, drops blanks and the additive marker (the
// additive flag carries that intent), and preserves order. The marker is
// stripped so a stray "+" in the textarea can never be stored as a rule.
func cleanRulesetList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" || e == scanner.AdditiveMarker {
			continue
		}
		out = append(out, e)
	}
	return out
}

// RulesetsValidateRequest asks to validate a candidate ruleset list without
// saving it: the "check my rules" button.
type RulesetsValidateRequest struct {
	SemgrepRulesets []string `json:"semgrepRulesets"`
}

// handleValidateRulesets runs the ruleset validator over a candidate list and
// returns per-entry results. Admin-only (registered behind the admin mux),
// read-only (nothing is saved), and bounded by maxCustomRulesets so it cannot
// be used to spawn unbounded semgrep processes.
func (s *Server) handleValidateRulesets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req RulesetsValidateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cleaned := cleanRulesetList(req.SemgrepRulesets)
	if len(cleaned) > maxCustomRulesets {
		writeErr(w, http.StatusBadRequest, "too many custom rulesets")
		return
	}
	statuses := scanner.ValidateRulesets(r.Context(), cleaned, s.dir)
	if statuses == nil {
		statuses = []scanner.RulesetStatus{}
	}
	s.audit(audit.EventConfigChange, actorFrom(r), map[string]string{"area": "settings", "action": "validate-rulesets"})
	writeJSON(w, http.StatusOK, map[string]any{"results": statuses})
}
