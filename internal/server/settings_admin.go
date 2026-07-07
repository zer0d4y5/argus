package server

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/leaky-hub/argus/internal/audit"
	"github.com/leaky-hub/argus/internal/config"
	"github.com/leaky-hub/argus/internal/model"
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
		AnthropicKeySet:    os.Getenv("ANTHROPIC_API_KEY") != "",
		ScanProfile:        cfg.Profile,
		FailSeverity:       cfg.FailSeverity,
		RemediationEnabled: cfg.Remediation.Enabled,
	})
}

// SettingsRequest is the admin PUT body. Any section left nil is not managed by
// the console (falls back to appsec.yml). No secret values — only env names.
type SettingsRequest struct {
	GitHubRepo         *string         `json:"githubRepo"`
	GitHubTokenEnv     *string         `json:"githubTokenEnv"`
	Triage             *TriageSettings `json:"triage"`
	ScanProfile        *string         `json:"scanProfile"`
	FailSeverity       *string         `json:"failSeverity"`
	RemediationEnabled *bool           `json:"remediationEnabled"`
}

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
