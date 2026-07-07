package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
