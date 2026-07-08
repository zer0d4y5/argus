package server

// Scan Studio API tests (docs/console-ops.md S1–S6): launch-time scope and
// framework validation, console-managed config with audited suppressions,
// per-target run reads, and the explain endpoint's cache/persistence/secret
// rules. The authz rows for the new routes live in TestAuthzMatrix.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/jobs"
	"github.com/zer0d4y5/argus/internal/llm"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/snippet"
	"github.com/zer0d4y5/argus/internal/targets"
)

func TestScanLaunchScopeValidation(t *testing.T) {
	f := newConsole(t, nil)
	if err := os.MkdirAll(filepath.Join(f.scanDir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	oper := f.mustLogin("oscar")

	launch := func(scope string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"targetId":%q,"options":{"scope":%q}}`, f.targetID, scope)
		return f.do("POST", "/api/scans", body, oper)
	}

	for _, bad := range []string{"../", "/etc", ".git/config", ".appsec/runs", "no/such/dir"} {
		if rec := launch(bad); rec.Code != http.StatusBadRequest {
			t.Errorf("scope %q: %d, want 400 (%s)", bad, rec.Code, rec.Body.String())
		}
	}
	if rec := launch("src"); rec.Code != http.StatusAccepted {
		t.Errorf("valid scope: %d %s", rec.Code, rec.Body.String())
	}
}

func TestScanLaunchFrameworkValidation(t *testing.T) {
	f := newConsole(t, nil)
	oper := f.mustLogin("oscar")

	launch := func(body string) int {
		return f.do("POST", "/api/scans", body, oper).Code
	}

	// Unknown framework → 400 (closed enum).
	if code := launch(fmt.Sprintf(`{"targetId":%q,"options":{"frameworks":["SOC2"]}}`, f.targetID)); code != http.StatusBadRequest {
		t.Errorf("unknown framework: %d, want 400", code)
	}
	// Empty intersection: gitleaks-only scan focused on an IAC benchmark.
	if code := launch(fmt.Sprintf(`{"targetId":%q,"options":{"scanners":["gitleaks"],"frameworks":["CIS-AWS"]}}`, f.targetID)); code != http.StatusBadRequest {
		t.Errorf("empty intersection: %d, want 400", code)
	}
	// Compatible pair is accepted.
	if code := launch(fmt.Sprintf(`{"targetId":%q,"options":{"scanners":["gitleaks"],"frameworks":["ASVS"]}}`, f.targetID)); code != http.StatusAccepted {
		t.Errorf("valid frameworks launch: %d, want 202", code)
	}
}

func TestFrameworksEndpoint(t *testing.T) {
	f := newConsole(t, nil)
	view := f.mustLogin("vera")
	rec := f.do("GET", "/api/frameworks", "", view)
	if rec.Code != http.StatusOK {
		t.Fatalf("frameworks: %d %s", rec.Code, rec.Body.String())
	}
	var resp FrameworksResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, fw := range resp.Frameworks {
		ids[fw.ID] = true
		if len(fw.Scanners) == 0 {
			t.Errorf("framework %s advertises no relevant scanners", fw.ID)
		}
	}
	for _, want := range []string{"ASVS", "PCI-DSS", "CIS-AWS"} {
		if !ids[want] {
			t.Errorf("framework list missing %s", want)
		}
	}
}

func TestTargetConfigPatchAndAudit(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	// Out-of-bounds config → 400.
	rec := f.do("PATCH", "/api/targets/"+f.targetID, `{"config":{"timeoutSec":5}}`, admin)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad timeout: %d, want 400", rec.Code)
	}

	// Valid patch applies and the audit line carries the suppression text.
	body := `{"profile":"fast","config":{"timeoutSec":120,"ignorePaths":["vendor/**"],"ignoreRules":["RULE-7"]}}`
	rec = f.do("PATCH", "/api/targets/"+f.targetID, body, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	var tg targets.Target
	if err := json.Unmarshal(rec.Body.Bytes(), &tg); err != nil {
		t.Fatal(err)
	}
	if tg.Profile != "fast" || tg.Config == nil || tg.Config.TimeoutSec != 120 {
		t.Fatalf("patch not applied: %+v", tg)
	}

	auditRaw, err := os.ReadFile(filepath.Join(f.dir, ".appsec", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(auditRaw), "target.update") ||
		!strings.Contains(string(auditRaw), "vendor/**") ||
		!strings.Contains(string(auditRaw), "RULE-7") {
		t.Errorf("target.update audit line lacks the suppression text:\n%s", auditRaw)
	}

	// Identity fields are not patchable: unknown JSON keys are ignored and
	// the target still points where it pointed.
	rec = f.do("PATCH", "/api/targets/"+f.targetID, `{"path":"/etc","url":"https://evil/x.git"}`, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("identity patch attempt: %d", rec.Code)
	}
	got, _ := f.registry.Get(f.targetID)
	if got.Path != f.scanDir || got.URL != "" {
		t.Fatalf("identity mutated via PATCH: %+v", got)
	}
}

func TestGitTargetRegistrationOverAPI(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	// S1 rejects non-https shapes at the API boundary.
	for _, bad := range []string{
		`{"name":"r1","url":"ssh://git@github.com/o/r.git"}`,
		`{"name":"r2","url":"file:///etc"}`,
		`{"name":"r3","url":"https://user:tok@github.com/o/r.git"}`,
		`{"name":"r4","url":"https://github.com/o/r.git","path":"/tmp"}`, // both
	} {
		if rec := f.do("POST", "/api/targets", bad, admin); rec.Code != http.StatusBadRequest {
			t.Errorf("register %s: %d, want 400", bad, rec.Code)
		}
	}

	rec := f.do("POST", "/api/targets", `{"name":"remote","url":"https://github.com/org/repo.git","branch":"main"}`, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("git register: %d %s", rec.Code, rec.Body.String())
	}
	var tg targets.Target
	_ = json.Unmarshal(rec.Body.Bytes(), &tg)
	if tg.Kind() != targets.TypeGit || tg.URL == "" || tg.Branch != "main" {
		t.Fatalf("git target shape: %+v", tg)
	}
}

// seedRun writes a run with one SAST finding (with snippet) and one SECRET
// finding into root's store and returns the run ID and finding IDs.
func seedRun(t *testing.T, root string) (runID, sastID, secretID string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "db.py"), []byte("l1\nl2\ncur.execute(uid)\nl4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := []model.Finding{
		{
			Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "sqli", Title: "SQL injection", Severity: model.SeverityHigh,
			Location: model.Location{File: filepath.Join(root, "db.py"), StartLine: 3, EndLine: 3},
		},
		{
			Tool: "gitleaks", Tools: []string{"gitleaks"}, Category: model.CategorySecret,
			RuleID: "aws-key", Title: "AWS key", Severity: model.SeverityHigh,
			Location: model.Location{File: filepath.Join(root, "db.py"), StartLine: 1, EndLine: 1},
		},
		{
			// History-mode secret (schema 2.0.0): the file no longer exists in
			// the worktree. S4 must hold for it exactly like any SECRET.
			Tool: "gitleaks", Tools: []string{"gitleaks"}, Category: model.CategorySecret,
			RuleID: "github-pat", Title: "GitHub personal access token", Severity: model.SeverityHigh,
			Location: model.Location{File: filepath.Join(root, "deleted.env"), StartLine: 2, EndLine: 2},
			Meta:     map[string]string{"gitHistory": "true", "commit": "abc123abc123"},
		},
	}
	for i := range findings {
		findings[i].ID = model.Fingerprint(findings[i])
	}
	snippet.Capture(root, findings)
	meta, err := runstore.ForRepo(root).Save(findings, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return meta.ID, findings[0].ID, findings[1].ID
}

// TestSecretFindingHasNoSnippetInRawRunFile pins S4 on the raw bytes.
func TestSecretFindingHasNoSnippetInRawRunFile(t *testing.T) {
	root := t.TempDir()
	runID, _, _ := seedRun(t, root)
	raw, err := os.ReadFile(filepath.Join(root, ".appsec", "runs", runID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		Findings      []struct {
			Category string `json:"category"`
			Location struct {
				Snippet *json.RawMessage `json:"snippet"`
			} `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != model.SchemaVersion {
		t.Errorf("schemaVersion = %s, want %s", doc.SchemaVersion, model.SchemaVersion)
	}
	for _, f := range doc.Findings {
		if f.Category == model.CategorySecret && f.Location.Snippet != nil {
			t.Fatal("SECRET finding carries a snippet in the raw run file")
		}
		if f.Category == model.CategorySAST && f.Location.Snippet == nil {
			t.Error("SAST finding lost its snippet")
		}
	}
}

func TestExplainEndpoint(t *testing.T) {
	f := newConsole(t, nil)
	runID, sastID, secretID := seedRun(t, f.dir)

	calls := 0
	f.srv.llmFactory = func(config.Config) llm.Client {
		return &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) {
			calls++
			return `{"explanation":"The query interpolates input.","remediation":"Parameterize."}`, nil
		}}
	}
	oper := f.mustLogin("oscar")

	runFile := filepath.Join(f.dir, ".appsec", "runs", runID+".json")
	before, _ := os.ReadFile(runFile)

	body := fmt.Sprintf(`{"runId":%q,"findingId":%q}`, runID, sastID)
	rec := f.do("POST", "/api/explain", body, oper)
	if rec.Code != http.StatusOK {
		t.Fatalf("explain: %d %s", rec.Code, rec.Body.String())
	}
	var resp ExplainResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Explanation == "" || resp.Cached {
		t.Fatalf("first explain: %+v", resp)
	}

	// Second call: served from cache, no new model call.
	rec = f.do("POST", "/api/explain", body, oper)
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Cached || calls != 1 {
		t.Errorf("cache: cached=%v calls=%d, want true/1", resp.Cached, calls)
	}

	// Ephemeral: the run file bytes are untouched and contain no explanation.
	after, _ := os.ReadFile(runFile)
	if string(before) != string(after) {
		t.Fatal("explain mutated the run file")
	}
	if strings.Contains(string(after), "interpolates input") {
		t.Fatal("explanation text persisted into the run file")
	}

	// The audit records the request, never the content.
	auditRaw, _ := os.ReadFile(filepath.Join(f.dir, ".appsec", "audit.jsonl"))
	if !strings.Contains(string(auditRaw), "scan.explain") {
		t.Error("scan.explain audit event missing")
	}
	if strings.Contains(string(auditRaw), "interpolates input") {
		t.Error("explanation content leaked into the audit log")
	}

	// SECRET + cloud provider without opt-in → 409.
	f.srv.llmFactory = func(config.Config) llm.Client {
		return &llm.Fake{IsLocal: false, Respond: func(llm.Request) (string, error) {
			return `{"explanation":"x"}`, nil
		}}
	}
	rec = f.do("POST", "/api/explain", fmt.Sprintf(`{"runId":%q,"findingId":%q}`, runID, secretID), oper)
	if rec.Code != http.StatusConflict {
		t.Errorf("secret+cloud explain: %d, want 409 (%s)", rec.Code, rec.Body.String())
	}

	// Unknown run / finding → 404.
	if rec := f.do("POST", "/api/explain", `{"runId":"2026-01-01T00-00-00Z","findingId":"x"}`, oper); rec.Code != http.StatusNotFound {
		t.Errorf("unknown run: %d, want 404", rec.Code)
	}
	if rec := f.do("POST", "/api/explain", fmt.Sprintf(`{"runId":%q,"findingId":"nope"}`, runID), oper); rec.Code != http.StatusNotFound {
		t.Errorf("unknown finding: %d, want 404", rec.Code)
	}
}

func TestRunsReadByTargetID(t *testing.T) {
	f := newConsole(t, nil)
	// Seed a run in the REGISTERED TARGET's own store (not the served repo).
	runID, _, _ := seedRun(t, f.scanDir)
	view := f.mustLogin("vera")

	// Default read: the served repo has no runs.
	var list RunsResponse
	rec := f.do("GET", "/api/runs", "", view)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Runs) != 0 {
		t.Fatalf("served repo runs = %d, want 0", len(list.Runs))
	}

	// Target-scoped read resolves through the registry by opaque ID.
	rec = f.do("GET", "/api/runs?target="+f.targetID, "", view)
	if rec.Code != http.StatusOK {
		t.Fatalf("target runs: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Runs) != 1 || list.Runs[0].ID != runID {
		t.Fatalf("target runs = %+v", list.Runs)
	}
	rec = f.do("GET", "/api/runs/"+runID+"?target="+f.targetID, "", view)
	if rec.Code != http.StatusOK {
		t.Fatalf("target run detail: %d", rec.Code)
	}

	// An unknown or crafted target parameter is a 404, never a path.
	if rec := f.do("GET", "/api/runs?target=../../etc", "", view); rec.Code != http.StatusNotFound {
		t.Errorf("crafted target param: %d, want 404", rec.Code)
	}
}

// TestMergeConfigPrecedence pins the S3 layering chain on every field.
func TestMergeConfigPrecedence(t *testing.T) {
	root := t.TempDir()
	// Layer 1: the repo's own appsec.yml.
	repoYAML := "scanners: [semgrep, gitleaks]\nprofile: standard\ntimeout: 500\nignore_paths: [vendor/**]\ntriage:\n  enabled: false\n"
	if err := os.WriteFile(filepath.Join(root, "appsec.yml"), []byte(repoYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	trueV, falseV := true, false

	base := targets.Target{ID: "t-1", Name: "x", Type: targets.TypeDir, Path: root}

	cases := []struct {
		name string
		tgt  func() targets.Target
		opts jobs.Options
		want func(t *testing.T, cfg config.Config)
	}{
		{
			name: "repo yaml alone",
			tgt:  func() targets.Target { return base },
			want: func(t *testing.T, cfg config.Config) {
				if len(cfg.Scanners) != 2 || cfg.Profile != "standard" || cfg.TimeoutSec != 500 || cfg.Triage.Enabled {
					t.Errorf("repo layer wrong: %+v", cfg)
				}
			},
		},
		{
			name: "registry overrides repo",
			tgt: func() targets.Target {
				tg := base
				tg.Scanners = []string{"gitleaks"}
				tg.Profile = "fast"
				tg.Config = &targets.Config{TimeoutSec: 120, Triage: &trueV, IgnorePaths: []string{"testdata/**"}, IgnoreRules: []string{"R1"}}
				return tg
			},
			want: func(t *testing.T, cfg config.Config) {
				if strings.Join(cfg.Scanners, ",") != "gitleaks" || cfg.Profile != "fast" || cfg.TimeoutSec != 120 || !cfg.Triage.Enabled {
					t.Errorf("registry layer wrong: %+v", cfg)
				}
				// Ignore lists are ADDITIVE: repo suppressions survive.
				if strings.Join(cfg.IgnorePaths, ",") != "vendor/**,testdata/**" || strings.Join(cfg.IgnoreRules, ",") != "R1" {
					t.Errorf("ignore lists: paths=%v rules=%v", cfg.IgnorePaths, cfg.IgnoreRules)
				}
			},
		},
		{
			name: "launch overrides registry",
			tgt: func() targets.Target {
				tg := base
				tg.Scanners = []string{"gitleaks"}
				tg.Profile = "fast"
				tg.Config = &targets.Config{Triage: &trueV}
				return tg
			},
			opts: jobs.Options{Scanners: []string{"semgrep"}, Profile: "max", Triage: &falseV},
			want: func(t *testing.T, cfg config.Config) {
				if strings.Join(cfg.Scanners, ",") != "semgrep" || cfg.Profile != "max" || cfg.Triage.Enabled {
					t.Errorf("launch layer wrong: %+v", cfg)
				}
			},
		},
		{
			name: "frameworks narrow the merged set",
			tgt:  func() targets.Target { return base },
			opts: jobs.Options{Frameworks: []string{"ASVS"}},
			want: func(t *testing.T, cfg config.Config) {
				if strings.Join(cfg.Scanners, ",") != "semgrep,gitleaks" {
					t.Errorf("narrowed = %v", cfg.Scanners)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := mergeConfig(c.tgt(), root, c.opts, "")
			if err != nil {
				t.Fatal(err)
			}
			c.want(t, cfg)
		})
	}

	// A git target always ignores its own .appsec bookkeeping — anchored to
	// the scan root as scanners report paths. A bare ".appsec/**" once
	// suppressed EVERY finding when the serve dir was relative (the
	// workspace prefix ".appsec/workspace/…" matched); pin the anchored
	// form for both root shapes.
	git := targets.Target{ID: "t-2", Name: "g", Type: targets.TypeGit, URL: "https://x/y.git"}
	for _, gitRoot := range []string{root, ".appsec/workspace/t-2"} {
		cfg, err := mergeConfig(git, gitRoot, jobs.Options{}, "")
		if err != nil {
			t.Fatal(err)
		}
		want := path.Join(filepath.ToSlash(gitRoot), ".appsec") + "/**"
		found := false
		for _, p := range cfg.IgnorePaths {
			if p == want {
				found = true
			}
			if p == ".appsec/**" {
				t.Fatalf("unanchored .appsec/** ignore is the finding-suppression regression: %v", cfg.IgnorePaths)
			}
		}
		if !found {
			t.Errorf("git target (root %q) lacks the anchored ignore %q: %v", gitRoot, want, cfg.IgnorePaths)
		}
	}

	// Framework focus that empties the set is an executor error too.
	if _, err := mergeConfig(base, root, jobs.Options{Scanners: []string{"gitleaks"}, Frameworks: []string{"CIS-AWS"}}, ""); err == nil {
		t.Error("empty narrowed set accepted at merge time")
	}
}
