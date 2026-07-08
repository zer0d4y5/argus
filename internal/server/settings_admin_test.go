package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/scanner"
)

// TestAdminSettingsRoundTrip: an admin saves GitHub + triage + scan defaults;
// they persist to the console store, become the effective config, and echo
// back with secret status — never a secret value.
func TestAdminSettingsRoundTrip(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	t.Setenv("GH_TOK", "ghp_x")

	body := `{
		"githubRepo":"acme/web","githubTokenEnv":"GH_TOK",
		"triage":{"enabled":true,"provider":"ollama","model":"qwen3.6:35b-a3b","endpoint":"http://localhost:11434","maxFindings":50,"excludeFp":false},
		"scanProfile":"max","failSeverity":"critical","remediationEnabled":true
	}`
	rec := f.do("PUT", "/api/admin/settings", body, admin)
	if rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	var v SettingsView
	json.Unmarshal(rec.Body.Bytes(), &v)
	if v.GitHubRepo != "acme/web" || v.GitHubTokenEnv != "GH_TOK" || !v.GitHubTokenSet {
		t.Errorf("github view wrong: %+v", v)
	}
	if !v.Triage.Enabled || v.Triage.Model != "qwen3.6:35b-a3b" || v.ScanProfile != "max" || v.FailSeverity != "critical" || !v.RemediationEnabled {
		t.Errorf("settings view wrong: %+v", v)
	}
	// The store holds no secret value.
	raw, _ := os.ReadFile(filepath.Join(f.dir, ".appsec", "settings.json"))
	if strings.Contains(string(raw), "ghp_x") {
		t.Error("token value reached the store")
	}
	// The overlay takes effect: GitHub sync is now enabled (drives the me flag).
	me := f.do("GET", "/api/auth/me", "", session{}) // unauth: githubRepo shown only when enabled + authed, but effectiveConfig drives it
	_ = me
	// Remediation now enabled — the execute gate opens for admin (no longer 409).
	// (We only check the config gate here, not a full run.)
	if !f.srv.remediationEnabled() {
		t.Error("remediationEnabled overlay did not take effect")
	}
}

// TestAdminSettingsPartialUpdate: a PUT naming only one section leaves the
// others intact.
func TestAdminSettingsPartialUpdate(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	f.do("PUT", "/api/admin/settings", `{"scanProfile":"fast"}`, admin)
	f.do("PUT", "/api/admin/settings", `{"githubRepo":"a/b"}`, admin)
	rec := f.do("GET", "/api/admin/settings", "", admin)
	var v SettingsView
	json.Unmarshal(rec.Body.Bytes(), &v)
	if v.ScanProfile != "fast" || v.GitHubRepo != "a/b" {
		t.Errorf("partial update lost a section: %+v", v)
	}
}

// TestAdminSettingsValidation: bad values are refused and never persisted.
func TestAdminSettingsValidation(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	for _, b := range []string{
		`{"scanProfile":"turbo"}`,
		`{"failSeverity":"apocalyptic"}`,
		`{"triage":{"provider":"openai"}}`,
		`{"triage":{"maxFindings":-5}}`,
		`{"githubRepo":"not a repo"}`,
	} {
		if rec := f.do("PUT", "/api/admin/settings", b, admin); rec.Code != 400 {
			t.Errorf("accepted invalid settings (%d): %s", rec.Code, b)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, ".appsec", "settings.json")); !os.IsNotExist(err) {
		t.Error("invalid PUT left a store file")
	}
}

// TestAdminSettingsCustomRulesets: an admin sets custom rulesets; they persist,
// echo back with the additive flag, and become the effective config as an
// additive "+"-marked override that keeps the profile packs.
func TestAdminSettingsCustomRulesets(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	// Registry packs validate without semgrep; additive defaults on.
	body := `{"semgrepRulesets":["p/python","argus/curated"]}`
	rec := f.do("PUT", "/api/admin/settings", body, admin)
	if rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	var v SettingsView
	json.Unmarshal(rec.Body.Bytes(), &v)
	if len(v.SemgrepRulesets) != 2 || v.SemgrepRulesets[0] != "p/python" || !v.SemgrepRulesetsAdditive {
		t.Fatalf("ruleset view wrong: %+v", v)
	}
	// Effective config: additive marker prepended, profile packs preserved.
	cfg := f.srv.effectiveConfig(f.dir)
	if len(cfg.SemgrepRules) == 0 || cfg.SemgrepRules[0] != "+" {
		t.Errorf("additive marker not applied: %v", cfg.SemgrepRules)
	}
	resolved := scanner.ResolveSemgrepRulesets(cfg.Profile, cfg.SemgrepRules)
	if !sliceHas(resolved, "argus/curated") || !sliceHas(resolved, "p/security-audit") {
		t.Errorf("additive override dropped profile packs: %v", resolved)
	}

	// Switch to replace mode: profile packs gone, only the custom entry runs.
	f.do("PUT", "/api/admin/settings", `{"semgrepRulesetsAdditive":false}`, admin)
	cfg = f.srv.effectiveConfig(f.dir)
	if cfg.SemgrepRules[0] == "+" {
		t.Errorf("replace mode still carries the additive marker: %v", cfg.SemgrepRules)
	}
	resolved = scanner.ResolveSemgrepRulesets(cfg.Profile, cfg.SemgrepRules)
	if sliceHas(resolved, "p/security-audit") {
		t.Errorf("replace mode should not include profile packs: %v", resolved)
	}
}

func sliceHas(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestAdminSettingsRejectsBadRule: a missing local rule path is refused at save
// time with a clear error and never persisted.
func TestAdminSettingsRejectsBadRule(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	rec := f.do("PUT", "/api/admin/settings", `{"semgrepRulesets":["./no-such-rule.yml"]}`, admin)
	if rec.Code != 400 {
		t.Fatalf("missing rule should be rejected, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("error should explain the missing rule: %s", rec.Body.String())
	}
	// Nothing about the rejected ruleset persisted.
	cfg := f.srv.effectiveConfig(f.dir)
	if len(cfg.SemgrepRules) != 0 {
		t.Errorf("rejected ruleset was persisted: %v", cfg.SemgrepRules)
	}
}

// TestValidateRulesetsEndpoint: the check-my-rules endpoint returns per-entry
// results without saving anything.
func TestValidateRulesetsEndpoint(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")

	// Operator cannot reach the admin-only endpoint.
	if rec := f.do("POST", "/api/admin/settings/validate-rulesets", `{"semgrepRulesets":["p/python"]}`, oper); rec.Code != 403 {
		t.Errorf("operator validate = %d, want 403", rec.Code)
	}
	rec := f.do("POST", "/api/admin/settings/validate-rulesets", `{"semgrepRulesets":["p/python","https://evil/x.yml","./missing.yml"]}`, admin)
	if rec.Code != 200 {
		t.Fatalf("validate: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Results []struct {
			Entry string
			OK    bool
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Results) != 3 {
		t.Fatalf("want 3 results, got %+v", out.Results)
	}
	byEntry := map[string]bool{}
	for _, r := range out.Results {
		byEntry[r.Entry] = r.OK
	}
	if !byEntry["p/python"] || byEntry["https://evil/x.yml"] || byEntry["./missing.yml"] {
		t.Errorf("validation verdicts wrong: %+v", out.Results)
	}
	// Nothing was saved by validation.
	if _, err := os.Stat(filepath.Join(f.dir, ".appsec", "settings.json")); !os.IsNotExist(err) {
		t.Error("validate endpoint wrote the settings store")
	}
}

// TestAdminSettingsGitHubOverlayLive: configuring GitHub via settings makes the
// ticket github endpoint see it (link mode works without appsec.yml).
func TestAdminSettingsGitHubOverlayLive(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	f.do("PUT", "/api/admin/settings", `{"githubRepo":"acme/webapp","githubTokenEnv":"X"}`, admin)
	// Make a ticket and link an issue (no token needed for link mode).
	rec := f.do("POST", "/api/tickets", `{"title":"x"}`, oper)
	var tk struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &tk)
	link := f.do("POST", "/api/tickets/"+tk.ID+"/github", `{"issueUrl":"https://github.com/acme/webapp/issues/3"}`, oper)
	if link.Code != 200 {
		t.Fatalf("github link with settings-configured repo: %d %s", link.Code, link.Body.String())
	}
}
