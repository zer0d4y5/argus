package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/jobs"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/server/auth"
	"github.com/zer0d4y5/argus/internal/store"
	"github.com/zer0d4y5/argus/internal/targets"
	"github.com/zer0d4y5/argus/internal/threatmodel"
	"github.com/zer0d4y5/argus/internal/ticket"
)

// Console-ops security tests. These pin docs/console-ops.md §9: the authz
// matrix, CSRF, the login rate limit and oracle, last-admin protection,
// target validation, queue behavior over the API, hash leakage, and the
// zero-users compatibility mode. All httptest, no network.

type consoleFixture struct {
	t        *testing.T
	srv      *Server
	handler  http.Handler
	users    *auth.Store
	registry *targets.Registry
	queue    *jobs.Queue
	tickets  *ticket.Store
	dir      string // served repo (users/targets/audit/runs)
	scanDir  string // a registered, scannable directory
	targetID string // the pre-registered target's opaque ID
}

// newConsole builds a fully-wired server with three users (one per role)
// and one registered target. exec defaults to an instant success.
func newConsole(t *testing.T, exec jobs.ExecFunc) *consoleFixture {
	t.Helper()
	dir := t.TempDir()
	users := auth.ForRepo(dir)
	for _, u := range []struct {
		name string
		role auth.Role
	}{{"alice", auth.RoleAdmin}, {"oscar", auth.RoleOperator}, {"vera", auth.RoleViewer}} {
		if _, err := users.Add(u.name, "password-"+u.name, u.role); err != nil {
			t.Fatal(err)
		}
	}
	registry := targets.ForRepo(dir)
	scanDir := t.TempDir()
	tgt, err := registry.Add("fixture", scanDir, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if exec == nil {
		exec = func(ctx context.Context, job jobs.Job, progress func(string)) (jobs.Result, error) {
			progress("==> running gitleaks (SECRET)\n")
			return jobs.Result{RunID: "run-ok"}, nil
		}
	}
	queue := jobs.New(exec)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	queue.Start(ctx)

	db, err := store.Open(filepath.Join(dir, ".appsec"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	tickets := ticket.NewStore(db)

	srv := New(Options{
		Store:    runstore.Store{Dir: filepath.Join(dir, ".appsec", "runs")},
		GateName: "high",
		Static:   os.DirFS(dir),
		Users:    users,
		Sessions: auth.NewSessions(),
		Limiter:  auth.NewLoginLimiter(),
		Targets:  registry,
		Audit:    audit.ForRepo(dir),
		Queue:    queue,
		Tickets:  tickets,
		Threats:  threatmodel.NewStore(db),
	})
	f := &consoleFixture{t: t, srv: srv, handler: srv.Handler(), users: users, registry: registry, queue: queue, tickets: tickets, dir: dir, scanDir: scanDir}
	f.targetID = tgt.ID
	return f
}

type session struct {
	cookie *http.Cookie
	csrf   string
}

func (f *consoleFixture) login(username, password string) (session, *httptest.ResponseRecorder) {
	f.t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return session{}, rec
	}
	var resp LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		f.t.Fatalf("decode login: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return session{cookie: c, csrf: resp.CSRFToken}, rec
		}
	}
	f.t.Fatal("login succeeded but set no session cookie")
	return session{}, rec
}

func (f *consoleFixture) mustLogin(username string) session {
	f.t.Helper()
	s, rec := f.login(username, "password-"+username)
	if s.cookie == nil {
		f.t.Fatalf("login %s failed: %d %s", username, rec.Code, rec.Body.String())
	}
	return s
}

// do issues a request; a zero session means anonymous; csrf "" omits the header.
func (f *consoleFixture) do(method, path, body string, s session) *httptest.ResponseRecorder {
	f.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if s.cookie != nil {
		req.AddCookie(s.cookie)
	}
	if s.csrf != "" {
		req.Header.Set("X-CSRF-Token", s.csrf)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// pass marks "authz allowed" in the matrix: the request got PAST the gate,
// whatever the handler then thought of its (often empty) body.
const pass = 0

// TestAuthzMatrix walks every route in the policy table against every
// authentication state. Expected values: pass (anything but 401/403), or the
// exact denial status.
func TestAuthzMatrix(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	view := f.mustLogin("vera")

	cases := []struct {
		method, path                  string
		anon, viewer, operator, admin int
	}{
		{"GET", "/api/health", pass, pass, pass, pass},
		{"GET", "/api/auth/me", pass, pass, pass, pass},
		{"POST", "/api/auth/logout", 401, pass, pass, pass},
		{"GET", "/api/auth/oidc/start", pass, pass, pass, pass},    // SSO: own logic (redirects); gate lets it through
		{"GET", "/api/auth/oidc/callback", pass, pass, pass, pass}, // SSO: own logic (redirects)

		{"GET", "/api/summary", 401, pass, pass, pass},
		{"GET", "/api/runs", 401, pass, pass, pass},
		{"GET", "/api/runs/2026-01-01T00-00-00Z", 401, pass, pass, pass},

		{"GET", "/api/frameworks", 401, pass, pass, pass},
		{"GET", "/api/mitigations", 401, pass, pass, pass},

		{"DELETE", "/api/runs/2026-01-01T00-00-00Z", 401, 403, 403, pass}, // prune a run: admin

		// LLM seams and finding-workflow mutations: operator+, audited.
		{"POST", "/api/remediate", 401, 403, pass, pass},
		{"POST", "/api/validate", 401, 403, pass, pass},
		{"POST", "/api/cloud/posture-summary", 401, 403, pass, pass},
		{"POST", "/api/cloud/remediations", 401, 403, pass, pass}, // list fixes: operator
		{"POST", "/api/cloud/remediate", 401, 403, 403, pass},     // execute: admin
		{"POST", "/api/dispositions", 401, 403, pass, pass},
		{"POST", "/api/dispositions/bulk", 401, 403, pass, pass},
		{"DELETE", "/api/dispositions/deadbeef", 401, 403, pass, pass},
		{"GET", "/api/cloud/profiles", 401, 403, 403, pass}, // admin-only registration form

		{"GET", "/api/tickets", 401, pass, pass, pass},
		{"POST", "/api/tickets", 401, 403, pass, pass},
		{"GET", "/api/tickets/tk-1", 401, pass, pass, pass},
		{"PATCH", "/api/tickets/tk-1", 401, 403, pass, pass},
		{"POST", "/api/tickets/tk-1/comments", 401, 403, pass, pass},
		{"POST", "/api/tickets/tk-1/links", 401, 403, pass, pass},
		{"POST", "/api/tickets/tk-1/close-fixed", 401, 403, pass, pass}, // writes dispositions (operator, like /api/dispositions)
		{"POST", "/api/tickets/tk-1/github", 401, 403, pass, pass},      // external sync (config-gated in the handler)
		{"DELETE", "/api/tickets/tk-1", 401, 403, 403, pass},            // delete is admin-only

		{"GET", "/api/threat-library", 401, pass, pass, pass},
		{"GET", "/api/threat-models", 401, pass, pass, pass},
		{"POST", "/api/threat-models", 401, 403, pass, pass},
		{"GET", "/api/threat-models/tm-1", 401, pass, pass, pass},
		{"POST", "/api/threat-models/from-target", 401, 403, pass, pass}, // scans a target's IaC
		{"POST", "/api/threat-models/tm-1/components", 401, 403, pass, pass},
		{"POST", "/api/threat-models/tm-1/enumerate", 401, 403, pass, pass},
		{"POST", "/api/threat-models/tm-1/threats", 401, 403, pass, pass},
		{"POST", "/api/threat-models/tm-1/threat-status", 401, 403, pass, pass},
		{"POST", "/api/threat-models/tm-1/links", 401, 403, pass, pass},
		{"POST", "/api/threat-models/tm-1/positions", 401, 403, pass, pass},          // canvas layout
		{"POST", "/api/threat-models/tm-1/flows", 401, 403, pass, pass},              // data flows
		{"POST", "/api/threat-models/tm-1/suggest", 401, 403, pass, pass},            // LLM seam (operator, like explain)
		{"POST", "/api/threat-models/tm-1/suggest-components", 401, 403, pass, pass}, // LLM seam
		{"DELETE", "/api/threat-models/tm-1", 401, 403, 403, pass},                   // delete is admin-only

		{"GET", "/api/targets", 401, pass, pass, pass},
		{"POST", "/api/targets", 401, 403, 403, pass},
		{"PATCH", "/api/targets/t-000000", 401, 403, 403, pass},
		{"DELETE", "/api/targets/t-000000", 401, 403, 403, pass},

		{"GET", "/api/scans", 401, pass, pass, pass},
		{"GET", "/api/scans/j-000000", 401, pass, pass, pass},
		{"POST", "/api/scans", 401, 403, pass, pass},
		{"POST", "/api/explain", 401, 403, pass, pass},

		{"GET", "/api/users/names", 401, 403, pass, pass}, // usernames only: operator
		{"GET", "/api/work-summary", 401, pass, pass, pass},
		{"GET", "/api/users", 401, 403, 403, pass},
		{"POST", "/api/users", 401, 403, 403, pass},
		{"PATCH", "/api/users/u-000000", 401, 403, 403, pass},
		{"DELETE", "/api/users/u-000000", 401, 403, 403, pass},

		{"GET", "/api/admin/oidc", 401, 403, 403, pass},
		{"PUT", "/api/admin/oidc", 401, 403, 403, pass},
		{"GET", "/api/admin/settings", 401, 403, 403, pass},
		{"PUT", "/api/admin/settings", 401, 403, 403, pass},
		{"POST", "/api/admin/settings/validate-rulesets", 401, 403, 403, pass}, // check custom rules: admin
		{"GET", "/api/admin/rules", 401, 403, 403, pass},                       // list saved custom rules: admin
		{"POST", "/api/admin/rules", 401, 403, 403, pass},                      // save a custom rule: admin
		{"POST", "/api/admin/rules/draft", 401, 403, 403, pass},                // AI draft: admin
		{"POST", "/api/admin/rules/test", 401, 403, 403, pass},                 // validate/test: admin
		{"DELETE", "/api/admin/rules/somename", 401, 403, 403, pass},           // delete a rule: admin
		{"GET", "/api/admin/rule-catalog", 401, 403, 403, pass},                // rule-pack menu: admin
		{"POST", "/api/admin/rulesets/toggle", 401, 403, 403, pass},            // enable/disable a pack or rule: admin
		{"GET", "/api/audit", 401, 403, 403, pass},

		// Unlisted routes fail closed: mutating verbs need admin.
		{"PUT", "/api/summary", 401, 403, 403, pass},
		{"POST", "/api/made-up", 401, 403, 403, pass},
	}

	check := func(who string, got *httptest.ResponseRecorder, want int) {
		t.Helper()
		if want == pass {
			if got.Code == http.StatusUnauthorized || got.Code == http.StatusForbidden {
				t.Errorf("%s: denied with %d, want pass: %s", who, got.Code, got.Body.String())
			}
			return
		}
		if got.Code != want {
			t.Errorf("%s: status %d, want %d (%s)", who, got.Code, want, got.Body.String())
		}
	}

	for _, c := range cases {
		name := c.method + " " + c.path
		// Logout would kill the session; use throwaway logins for it.
		v, o, a := view, oper, admin
		if c.path == "/api/auth/logout" {
			v, o, a = f.mustLogin("vera"), f.mustLogin("oscar"), f.mustLogin("alice")
		}
		check(name+" anon", f.do(c.method, c.path, "", session{}), c.anon)
		check(name+" viewer", f.do(c.method, c.path, "", v), c.viewer)
		check(name+" operator", f.do(c.method, c.path, "", o), c.operator)
		check(name+" admin", f.do(c.method, c.path, "", a), c.admin)
	}
}

// TestZeroUsersMode pins T8: with no users on disk the console behaves
// exactly like the pre-auth read-only viewer, and every ops route answers
// 403 naming the bootstrap command.
func TestZeroUsersMode(t *testing.T) {
	dir := t.TempDir()
	srv := New(Options{
		Store:    runstore.Store{Dir: filepath.Join(dir, ".appsec", "runs")},
		GateName: "high",
		Static:   os.DirFS(dir),
		Users:    auth.ForRepo(dir),
		Sessions: auth.NewSessions(),
		Limiter:  auth.NewLoginLimiter(),
		Targets:  targets.ForRepo(dir),
		Audit:    audit.ForRepo(dir),
		Queue:    jobs.New(func(context.Context, jobs.Job, func(string)) (jobs.Result, error) { return jobs.Result{}, nil }),
	})
	h := srv.Handler()

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	// Reads are open, exactly like today.
	for _, p := range []string{"/api/summary", "/api/runs", "/api/health", "/api/targets", "/api/scans"} {
		if rec := get(p); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d in zero-users mode, want 200", p, rec.Code)
		}
	}
	var me MeResponse
	if err := json.Unmarshal(get("/api/auth/me").Body.Bytes(), &me); err != nil || me.AuthRequired {
		t.Errorf("me in zero-users mode: %+v err=%v, want authRequired=false", me, err)
	}

	// Ops are refused with the bootstrap hint.
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/scans"}, {"POST", "/api/targets"}, {"POST", "/api/users"},
		{"GET", "/api/users"}, {"GET", "/api/audit"}, {"POST", "/api/auth/login"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, strings.NewReader("{}")))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d in zero-users mode, want 403", c.method, c.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "argus user add") {
			t.Errorf("%s %s body lacks bootstrap hint: %s", c.method, c.path, rec.Body.String())
		}
	}
}

// TestCSRF pins T3: any non-GET without the session's CSRF token is refused.
func TestCSRF(t *testing.T) {
	f := newConsole(t, nil)
	s := f.mustLogin("oscar")
	body := fmt.Sprintf(`{"targetId":%q}`, f.targetID)

	noCSRF := session{cookie: s.cookie}
	if rec := f.do("POST", "/api/scans", body, noCSRF); rec.Code != http.StatusForbidden {
		t.Errorf("missing CSRF: %d, want 403", rec.Code)
	}
	wrong := session{cookie: s.cookie, csrf: "wrong-token"}
	if rec := f.do("POST", "/api/scans", body, wrong); rec.Code != http.StatusForbidden {
		t.Errorf("wrong CSRF: %d, want 403", rec.Code)
	}
	if rec := f.do("POST", "/api/scans", body, s); rec.Code != http.StatusAccepted {
		t.Errorf("correct CSRF: %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
}

// TestLoginRateLimitAndOracle pins T4.
func TestLoginRateLimitAndOracle(t *testing.T) {
	f := newConsole(t, nil)

	// Unknown user and wrong password must be indistinguishable.
	_, recUnknown := f.login("who-is-this", "password-nope")
	_, recWrong := f.login("vera", "password-nope")
	if recUnknown.Code != http.StatusUnauthorized || recWrong.Code != http.StatusUnauthorized {
		t.Fatalf("statuses: unknown=%d wrong=%d, want 401/401", recUnknown.Code, recWrong.Code)
	}
	if recUnknown.Body.String() != recWrong.Body.String() {
		t.Errorf("oracle: bodies differ: %q vs %q", recUnknown.Body, recWrong.Body)
	}

	// 5 failures lock the account key; the correct password now gets 429.
	for i := 0; i < 3; i++ { // 2 failures already burned above on "vera"... make it explicit:
		f.login("vera", "password-nope")
	}
	if _, rec := f.login("vera", "password-vera"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("locked account: %d, want 429 (%s)", rec.Code, rec.Body.String())
	}
}

// TestLastAdminProtection pins T5 at the API level.
func TestLastAdminProtection(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	var users UsersResponse
	if err := json.Unmarshal(f.do("GET", "/api/users", "", admin).Body.Bytes(), &users); err != nil {
		t.Fatal(err)
	}
	var aliceID string
	for _, u := range users.Users {
		if u.Username == "alice" {
			aliceID = u.ID
		}
	}

	if rec := f.do("DELETE", "/api/users/"+aliceID, "", admin); rec.Code != http.StatusConflict {
		t.Errorf("deleting last admin: %d, want 409", rec.Code)
	}
	if rec := f.do("PATCH", "/api/users/"+aliceID, `{"role":"viewer"}`, admin); rec.Code != http.StatusConflict {
		t.Errorf("demoting last admin: %d, want 409", rec.Code)
	}
	// Promote oscar, then demoting alice is fine.
	var oscarID string
	for _, u := range users.Users {
		if u.Username == "oscar" {
			oscarID = u.ID
		}
	}
	if rec := f.do("PATCH", "/api/users/"+oscarID, `{"role":"admin"}`, admin); rec.Code != http.StatusOK {
		t.Fatalf("promoting oscar: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("PATCH", "/api/users/"+aliceID, `{"role":"viewer"}`, admin); rec.Code != http.StatusOK {
		t.Errorf("demoting alice with second admin present: %d %s", rec.Code, rec.Body.String())
	}
	// Alice is now a viewer: her live session must lose admin power immediately.
	if rec := f.do("GET", "/api/users", "", admin); rec.Code != http.StatusForbidden {
		t.Errorf("demoted admin still reads /api/users: %d, want 403", rec.Code)
	}
}

// TestNoHashInAnyResponse pins T6 on raw JSON bytes.
func TestNoHashInAnyResponse(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	bodies := map[string]string{}
	_, loginRec := f.login("vera", "password-vera")
	bodies["login"] = loginRec.Body.String()
	bodies["users"] = f.do("GET", "/api/users", "", admin).Body.String()
	bodies["me"] = f.do("GET", "/api/auth/me", "", admin).Body.String()
	bodies["audit"] = f.do("GET", "/api/audit", "", admin).Body.String()

	for name, body := range bodies {
		for _, needle := range []string{"$argon2", "\"hash\"", "hashAtLogin", "HashAtLogin", "password-"} {
			if strings.Contains(body, needle) {
				t.Errorf("%s response leaks %q: %s", name, needle, body)
			}
		}
	}
	if !strings.Contains(bodies["users"], "\"username\"") {
		t.Error("users response looks empty — leak assertions vacuous")
	}
}

// TestScanLaunchValidation pins T1/T2 over the API: unknown target IDs 404,
// off-registry scanners and profiles 400, path registration is validated.
func TestScanLaunchValidation(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")

	if rec := f.do("POST", "/api/scans", `{"targetId":"t-does-not-exist"}`, oper); rec.Code != http.StatusNotFound {
		t.Errorf("unknown target: %d, want 404", rec.Code)
	}
	body := fmt.Sprintf(`{"targetId":%q,"options":{"scanners":["nmap"]}}`, f.targetID)
	if rec := f.do("POST", "/api/scans", body, oper); rec.Code != http.StatusBadRequest {
		t.Errorf("off-enum scanner: %d, want 400", rec.Code)
	}
	body = fmt.Sprintf(`{"targetId":%q,"options":{"profile":"--config=/etc/evil"}}`, f.targetID)
	if rec := f.do("POST", "/api/scans", body, oper); rec.Code != http.StatusBadRequest {
		t.Errorf("off-enum profile: %d, want 400", rec.Code)
	}

	// Registration-time path validation over the API (admin).
	for _, path := range []string{"relative/path", "/", f.scanDir + "/../..", "/does/not/exist"} {
		body := fmt.Sprintf(`{"name":"bad","path":%q}`, path)
		if rec := f.do("POST", "/api/targets", body, admin); rec.Code != http.StatusBadRequest {
			t.Errorf("registering %q: %d, want 400 (%s)", path, rec.Code, rec.Body.String())
		}
	}
}

// TestScanJobLifecycleAndSerialityOverAPI launches two scans through the
// API against a deliberately slow executor and observes strictly serial
// execution and the queued->running->done progression.
func TestScanJobLifecycleAndSerialityOverAPI(t *testing.T) {
	release := make(chan struct{})
	exec := func(ctx context.Context, job jobs.Job, progress func(string)) (jobs.Result, error) {
		progress("==> running gitleaks (SECRET)\n")
		<-release
		return jobs.Result{RunID: "run-" + job.ID}, nil
	}
	f := newConsole(t, exec)
	oper := f.mustLogin("oscar")
	body := fmt.Sprintf(`{"targetId":%q,"options":{"triage":false}}`, f.targetID)

	var j1, j2 jobs.Job
	rec := f.do("POST", "/api/scans", body, oper)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("launch 1: %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &j1); err != nil {
		t.Fatal(err)
	}
	rec = f.do("POST", "/api/scans", body, oper)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("launch 2: %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &j2); err != nil {
		t.Fatal(err)
	}

	// Wait for job 1 to be running, then job 2 must still be queued.
	waitStatus := func(id, want string) jobs.Job {
		t.Helper()
		deadline := time.After(2 * time.Second)
		for {
			var j jobs.Job
			rec := f.do("GET", "/api/scans/"+id, "", oper)
			if rec.Code != http.StatusOK {
				t.Fatalf("job %s: %d", id, rec.Code)
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil {
				t.Fatal(err)
			}
			if j.Status == want {
				return j
			}
			select {
			case <-deadline:
				t.Fatalf("job %s stuck in %q, want %q", id, j.Status, want)
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	waitStatus(j1.ID, jobs.StatusRunning)
	if j := waitStatus(j2.ID, jobs.StatusQueued); j.Status != jobs.StatusQueued {
		t.Fatalf("job 2 not queued while job 1 runs")
	}
	close(release)
	done1 := waitStatus(j1.ID, jobs.StatusDone)
	done2 := waitStatus(j2.ID, jobs.StatusDone)
	if done1.RunID == "" || done2.RunID == "" {
		t.Errorf("run IDs missing: %q %q", done1.RunID, done2.RunID)
	}
	if done1.LaunchedBy != "oscar" {
		t.Errorf("launchedBy = %q, want oscar", done1.LaunchedBy)
	}

	// The audit log recorded the launches (admin view).
	admin := f.mustLogin("alice")
	auditBody := f.do("GET", "/api/audit", "", admin).Body.String()
	if !strings.Contains(auditBody, audit.EventScanLaunch) || !strings.Contains(auditBody, "login.success") {
		t.Errorf("audit log missing expected events: %s", auditBody)
	}
}

// TestSessionRevocationOnPasswordChange: changing a password (as the API
// would) kills the user's live sessions on their next request.
func TestSessionRevocationOnPasswordChange(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	vera := f.mustLogin("vera")

	if rec := f.do("GET", "/api/summary", "", vera); rec.Code != http.StatusOK {
		t.Fatalf("vera pre-change: %d", rec.Code)
	}
	var users UsersResponse
	json.Unmarshal(f.do("GET", "/api/users", "", admin).Body.Bytes(), &users)
	var veraID string
	for _, u := range users.Users {
		if u.Username == "vera" {
			veraID = u.ID
		}
	}
	if rec := f.do("PATCH", "/api/users/"+veraID, `{"password":"new-password-9"}`, admin); rec.Code != http.StatusOK {
		t.Fatalf("password change: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("GET", "/api/summary", "", vera); rec.Code != http.StatusUnauthorized {
		t.Errorf("vera post-change: %d, want 401 (session must die with old password)", rec.Code)
	}
}

// TestQueueFullOverAPI: with the worker wedged, the 11th pending POST is 429.
func TestQueueFullOverAPI(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	f := newConsole(t, func(ctx context.Context, job jobs.Job, progress func(string)) (jobs.Result, error) {
		<-block
		return jobs.Result{}, nil
	})
	oper := f.mustLogin("oscar")
	body := fmt.Sprintf(`{"targetId":%q}`, f.targetID)

	accepted := 0
	var last *httptest.ResponseRecorder
	for i := 0; i < 12; i++ {
		last = f.do("POST", "/api/scans", body, oper)
		if last.Code == http.StatusAccepted {
			accepted++
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Errorf("12th launch: %d, want 429", last.Code)
	}
	if accepted > 11 { // 10 pending + possibly 1 already picked up by the worker
		t.Errorf("accepted %d launches, queue bound not enforced", accepted)
	}
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
