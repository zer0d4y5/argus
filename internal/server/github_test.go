package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGitHubConfig points the served repo's appsec.yml at a sync repo.
func writeGitHubConfig(t *testing.T, f *consoleFixture) {
	t.Helper()
	writeFile(t, f.dir, "appsec.yml", "ticketing:\n  github:\n    repo: acme/webapp\n    token_env: ARGUS_TEST_GH_TOKEN\n")
}

func makeTicket(t *testing.T, f *consoleFixture, s session) string {
	t.Helper()
	rec := f.do("POST", "/api/tickets", `{"title":"Fix the SQLi","description":"details here"}`, s)
	if rec.Code != 201 {
		t.Fatalf("create ticket: %d %s", rec.Code, rec.Body.String())
	}
	var tk struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &tk)
	return tk.ID
}

// TestGitHubSyncDisabledByDefault: without config the endpoint refuses and
// names the config key; nothing leaves the machine.
func TestGitHubSyncDisabledByDefault(t *testing.T) {
	f := newConsole(t, nil)
	oper := f.mustLogin("oscar")
	id := makeTicket(t, f, oper)
	rec := f.do("POST", "/api/tickets/"+id+"/github", "{}", oper)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "not configured") {
		t.Errorf("unconfigured sync = %d %s, want 400 naming the config", rec.Code, rec.Body.String())
	}
}

// TestGitHubSyncCreate drives the create path against a fake GitHub API and
// pins the token hygiene: the token reaches the outbound Authorization header
// and nowhere else — not the ticket, not the audit log, not the response.
func TestGitHubSyncCreate(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody []byte
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"html_url":"https://github.com/acme/webapp/issues/42","number":42}`))
	}))
	defer fake.Close()

	f := newConsole(t, nil)
	writeGitHubConfig(t, f)
	f.srv.githubAPIBase = fake.URL
	t.Setenv("ARGUS_TEST_GH_TOKEN", "ghp_secret_token_value")
	oper := f.mustLogin("oscar")
	id := makeTicket(t, f, oper)

	rec := f.do("POST", "/api/tickets/"+id+"/github", "{}", oper)
	if rec.Code != 200 {
		t.Fatalf("create issue: %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ ExternalUrl, ExternalId string }
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.ExternalUrl != "https://github.com/acme/webapp/issues/42" || out.ExternalId != "42" {
		t.Errorf("stored reference wrong: %+v", out)
	}
	if gotAuth != "Bearer ghp_secret_token_value" {
		t.Errorf("outbound auth header wrong: %q", gotAuth)
	}
	if gotPath != "/repos/acme/webapp/issues" {
		t.Errorf("outbound path wrong: %q", gotPath)
	}
	if !strings.Contains(string(gotBody), "Fix the SQLi") {
		t.Errorf("outbound body missing the ticket title: %s", gotBody)
	}

	// The reference persists on the ticket; the timeline records the event.
	det := f.do("GET", "/api/tickets/"+id, "", oper)
	if !strings.Contains(det.Body.String(), "issues/42") || !strings.Contains(det.Body.String(), "created GitHub issue #42") {
		t.Errorf("ticket detail missing the reference/event: %s", det.Body.String())
	}
	// Token hygiene: never in the ticket payload, never in the audit log.
	if strings.Contains(det.Body.String(), "ghp_secret") {
		t.Fatal("token leaked into the ticket payload")
	}
	auditRaw, _ := os.ReadFile(filepath.Join(f.dir, ".appsec", "audit.jsonl"))
	if strings.Contains(string(auditRaw), "ghp_secret") {
		t.Fatal("token leaked into the audit log")
	}
}

// TestGitHubSyncNoToken: configured repo but no token in the env → an honest
// 503 naming the env var, no outbound call.
func TestGitHubSyncNoToken(t *testing.T) {
	f := newConsole(t, nil)
	writeGitHubConfig(t, f)
	t.Setenv("ARGUS_TEST_GH_TOKEN", "")
	oper := f.mustLogin("oscar")
	id := makeTicket(t, f, oper)
	rec := f.do("POST", "/api/tickets/"+id+"/github", "{}", oper)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "ARGUS_TEST_GH_TOKEN") {
		t.Errorf("no-token = %d %s, want 503 naming the env var", rec.Code, rec.Body.String())
	}
}

// TestGitHubSyncLinkMode: linking an existing issue validates the URL shape
// and needs no token and no network.
func TestGitHubSyncLinkMode(t *testing.T) {
	f := newConsole(t, nil)
	writeGitHubConfig(t, f)
	oper := f.mustLogin("oscar")
	id := makeTicket(t, f, oper)

	for _, bad := range []string{
		"https://github.com.evil.example/acme/webapp/issues/1",
		"https://github.com/acme/webapp/pulls/1",
		"http://github.com/acme/webapp/issues/1",
		"https://github.com/acme/webapp/issues/1x",
		"javascript:alert(1)",
	} {
		rec := f.do("POST", "/api/tickets/"+id+"/github", `{"issueUrl":"`+bad+`"}`, oper)
		if rec.Code != 400 {
			t.Errorf("bad url %q accepted: %d", bad, rec.Code)
		}
	}
	rec := f.do("POST", "/api/tickets/"+id+"/github", `{"issueUrl":"https://github.com/other/repo/issues/7"}`, oper)
	if rec.Code != 200 {
		t.Fatalf("link: %d %s", rec.Code, rec.Body.String())
	}
	det := f.do("GET", "/api/tickets/"+id, "", oper)
	if !strings.Contains(det.Body.String(), "linked GitHub issue #7") {
		t.Errorf("timeline missing link event: %s", det.Body.String())
	}
}

// TestGitHubSyncAPIFailure: a non-201 from GitHub is a bounded 502 that never
// echoes response bodies or the token.
func TestGitHubSyncAPIFailure(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials, token ghp_echoed"}`))
	}))
	defer fake.Close()
	f := newConsole(t, nil)
	writeGitHubConfig(t, f)
	f.srv.githubAPIBase = fake.URL
	t.Setenv("ARGUS_TEST_GH_TOKEN", "tok")
	oper := f.mustLogin("oscar")
	id := makeTicket(t, f, oper)
	rec := f.do("POST", "/api/tickets/"+id+"/github", "{}", oper)
	if rec.Code != 502 {
		t.Fatalf("api failure = %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "ghp_echoed") {
		t.Fatal("GitHub error body echoed to the client")
	}
	if !strings.Contains(rec.Body.String(), "HTTP 401") {
		t.Errorf("error should carry the status code: %s", rec.Body.String())
	}
}
