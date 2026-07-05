package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/runstore"
)

// testServer builds a Server over a temp store seeded with two runs, the second
// containing a deliberately hostile finding (XSS payload in the title).
func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	store := runstore.Store{Dir: dir}

	risk := func(v float64) *float64 { return &v }
	tp := &model.Triage{Verdict: model.VerdictTruePositive}
	fp := &model.Triage{Verdict: model.VerdictFalsePositive}

	// Run 1 (older): one finding.
	run1 := []model.Finding{
		{ID: "keep1", Tool: "semgrep", Category: model.CategorySAST, RuleID: "r1",
			Title: "SQL injection", Severity: model.SeverityHigh, CWEs: []string{"CWE-89"},
			RiskScore: risk(8.2), Triage: tp},
		{ID: "gone1", Tool: "semgrep", Category: model.CategorySAST, RuleID: "r2",
			Title: "old finding", Severity: model.SeverityMedium, CWEs: []string{"CWE-79"},
			RiskScore: risk(5.0), Triage: fp},
	}
	if _, err := store.Save(run1, time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}

	// Run 2 (newer): keep1 unchanged, a new hostile finding.
	run2 := []model.Finding{
		{ID: "keep1", Tool: "semgrep", Category: model.CategorySAST, RuleID: "r1",
			Title: "SQL injection", Severity: model.SeverityHigh, CWEs: []string{"CWE-89"},
			RiskScore: risk(8.2), Triage: tp},
		{ID: "xss1", Tool: "semgrep", Category: model.CategorySAST, RuleID: "r3",
			Title:       `<script>alert('pwned')</script>`,
			Description: `</script><img src=x onerror=alert(1)>`,
			Severity:    model.SeverityCritical, CWEs: []string{"CWE-79"}, RiskScore: risk(9.5)},
	}
	if _, err := store.Save(run2, time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}

	gate, _ := model.ParseGate("high")
	// A tiny static FS so the "/" route has something to serve.
	static := os.DirFS(dir) // reuse temp dir; index.html absent → SPA fallback tested separately
	return New(Options{Store: store, Gate: gate, GateName: "high", Static: static})
}

func do(t *testing.T, s *Server, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Result()
}

func TestSecurityHeadersOnAPI(t *testing.T) {
	s := testServer(t)
	resp := do(t, s, "/api/summary")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	// script-src must be same-origin only, with no unsafe-inline anywhere in the
	// script directive — that is the XSS boundary.
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP missing default-src 'none': %q", csp)
	}
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("script-src must be 'self' with no unsafe-inline: %q", csp)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing X-Frame-Options DENY")
	}
}

// TestHostileFindingRenderedInert is the required XSS guard: a finding title
// containing a <script> payload must never appear as raw HTML in the API body.
// The JSON encoder escapes <, >, & to < etc., so the browser's JSON parse
// yields a plain string that React then escapes again on render.
func TestHostileFindingRenderedInert(t *testing.T) {
	s := testServer(t)
	resp := do(t, s, "/api/runs/2026-07-04T12-00-00Z")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	raw := string(body)

	if strings.Contains(raw, "<script>") {
		t.Error("raw <script> present in API body — hostile finding not escaped")
	}
	if !strings.Contains(raw, "\\u003cscript") {
		t.Error("expected escaped \\u003cscript in body (SetEscapeHTML)")
	}
	// And it must still decode back to the exact original string (data integrity).
	var detail struct {
		Findings []model.Finding `json:"findings"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var found bool
	for _, f := range detail.Findings {
		if f.ID == "xss1" {
			found = true
			if f.Title != `<script>alert('pwned')</script>` {
				t.Errorf("title corrupted on round-trip: %q", f.Title)
			}
		}
	}
	if !found {
		t.Error("xss1 finding missing from run detail")
	}
}

func TestSummaryTrendAndPosture(t *testing.T) {
	s := testServer(t)
	resp := do(t, s, "/api/summary")
	body, _ := io.ReadAll(resp.Body)
	var sum SummaryResponse
	if err := json.Unmarshal(body, &sum); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sum.RunCount != 2 {
		t.Errorf("runCount = %d, want 2", sum.RunCount)
	}
	if len(sum.Trend) != 2 {
		t.Errorf("trend points = %d, want 2", len(sum.Trend))
	}
	if len(sum.OWASP) != 10 {
		t.Errorf("owasp rows = %d, want 10", len(sum.OWASP))
	}
	// Latest run has a critical finding → gate (high) must fail.
	if !sum.Gate.Failed {
		t.Error("gate should fail on latest run with a critical finding")
	}
	if sum.Total != 2 {
		t.Errorf("latest total = %d, want 2", sum.Total)
	}
}

func TestRunsListDeltaAndOrder(t *testing.T) {
	s := testServer(t)
	resp := do(t, s, "/api/runs")
	body, _ := io.ReadAll(resp.Body)
	var runs RunsResponse
	if err := json.Unmarshal(body, &runs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(runs.Runs) != 2 {
		t.Fatalf("runs = %d, want 2", len(runs.Runs))
	}
	// Newest first.
	newest := runs.Runs[0]
	if newest.ID != "2026-07-04T12-00-00Z" {
		t.Errorf("newest id = %q", newest.ID)
	}
	// Newest vs previous: xss1 new, gone1 resolved, keep1 unchanged.
	if newest.Delta.New != 1 || newest.Delta.Resolved != 1 || newest.Delta.Unchanged != 1 {
		t.Errorf("delta = %+v, want new1 resolved1 unchanged1", newest.Delta)
	}
	// Oldest run is the first ever → all new.
	oldest := runs.Runs[1]
	if oldest.Delta.New != 2 || oldest.Delta.Resolved != 0 {
		t.Errorf("oldest delta = %+v, want new2 resolved0", oldest.Delta)
	}
}

func TestRunDetailNewIDs(t *testing.T) {
	s := testServer(t)
	resp := do(t, s, "/api/runs/2026-07-04T12-00-00Z")
	body, _ := io.ReadAll(resp.Body)
	var d RunDetail
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(d.NewIDs) != 1 || d.NewIDs[0] != "xss1" {
		t.Errorf("newIds = %v, want [xss1]", d.NewIDs)
	}
	if len(d.ResolvedIDs) != 1 || d.ResolvedIDs[0] != "gone1" {
		t.Errorf("resolvedIds = %v, want [gone1]", d.ResolvedIDs)
	}
	if d.Verdicts.TruePositive != 1 {
		t.Errorf("verdicts.truePositive = %d, want 1", d.Verdicts.TruePositive)
	}
}

func TestBadRunID(t *testing.T) {
	s := testServer(t)
	for _, p := range []string{"/api/runs/not-a-timestamp", "/api/runs/..%2f..%2fetc"} {
		resp := do(t, s, p)
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s returned 200, want error", p)
		}
	}
}

func TestEmptyStore(t *testing.T) {
	s := New(Options{Store: runstore.Store{Dir: t.TempDir()}, GateName: "high"})
	resp := do(t, s, "/api/summary")
	body, _ := io.ReadAll(resp.Body)
	var sum SummaryResponse
	if err := json.Unmarshal(body, &sum); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sum.RunCount != 0 || len(sum.OWASP) != 10 {
		t.Errorf("empty store summary malformed: runCount=%d owaspRows=%d", sum.RunCount, len(sum.OWASP))
	}
}

// The compliance rollup rides the summary and run-detail payloads, and stored
// findings are enriched with control chips at read time (pre-1.2.0 runs too).
func TestComplianceInAPI(t *testing.T) {
	s := testServer(t)

	var sum SummaryResponse
	body, _ := io.ReadAll(do(t, s, "/api/summary").Body)
	if err := json.Unmarshal(body, &sum); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(sum.Compliance) != 5 {
		t.Fatalf("compliance frameworks = %d, want 5", len(sum.Compliance))
	}
	byID := map[string]int{}
	for _, fw := range sum.Compliance {
		byID[fw.ID] = fw.ViolatedControls
	}
	// Latest run: CWE-89 + CWE-79 findings → ASVS and PCI-DSS must show violations.
	if byID["ASVS"] == 0 || byID["PCI-DSS"] == 0 {
		t.Errorf("ASVS/PCI-DSS violated counts = %d/%d, want > 0", byID["ASVS"], byID["PCI-DSS"])
	}

	var detail RunDetail
	body, _ = io.ReadAll(do(t, s, "/api/runs/"+sum.LatestID).Body)
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if len(detail.Compliance) != 5 {
		t.Errorf("detail compliance frameworks = %d, want 5", len(detail.Compliance))
	}
	// The stored findings carry no complianceControls (pre-1.2.0 save);
	// the API must enrich them at read time.
	for _, f := range detail.Findings {
		if f.ID == "keep1" && len(f.ComplianceControls) == 0 {
			t.Error("finding keep1 (CWE-89) not enriched with complianceControls at read time")
		}
	}
}
