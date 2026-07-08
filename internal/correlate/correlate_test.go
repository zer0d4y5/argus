package correlate

import (
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func TestCorrelateSCASameCVE(t *testing.T) {
	in := []model.Finding{
		{Tool: "trivy", Tools: []string{"trivy"}, Category: model.CategorySCA,
			RuleID: "CVE-2020-14343", CVE: "CVE-2020-14343", Package: "PyYAML@5.3.1",
			Severity: model.SeverityHigh},
		{Tool: "othersca", Tools: []string{"othersca"}, Category: model.CategorySCA,
			RuleID: "PYSEC-123", CVE: "CVE-2020-14343", Package: "PyYAML@5.3.1",
			Severity: model.SeverityCritical},
	}
	out := Correlate(in)
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1 (same CVE + package must merge)", len(out))
	}
	if out[0].Severity != model.SeverityCritical {
		t.Error("merge must keep the maximum severity")
	}
	if len(out[0].Tools) != 2 {
		t.Errorf("merged tools = %v, want both", out[0].Tools)
	}
}

func TestCorrelateSCADifferentPackagesStaySeparate(t *testing.T) {
	in := []model.Finding{
		{Category: model.CategorySCA, CVE: "CVE-2020-14343", Package: "PyYAML@5.3.1",
			Tool: "trivy", Tools: []string{"trivy"}},
		{Category: model.CategorySCA, CVE: "CVE-2020-14343", Package: "PyYAML@5.1",
			Tool: "trivy", Tools: []string{"trivy"}},
	}
	if out := Correlate(in); len(out) != 2 {
		t.Errorf("same CVE in different package versions must stay separate, got %d", len(out))
	}
}

func TestCorrelateExactDuplicate(t *testing.T) {
	f := model.Finding{Tool: "semgrep", Tools: []string{"semgrep"},
		Category: model.CategorySAST, RuleID: "r.sqli",
		Location: model.Location{File: "app.py", StartLine: 10, EndLine: 10}}
	if out := Correlate([]model.Finding{f, f}); len(out) != 1 {
		t.Errorf("identical findings must dedup, got %d", len(out))
	}
}

// TestCorrelateCloudResourcesStayDistinct: two failures of the same prowler
// check on different resources must not collapse. Cloud findings carry no file,
// so the exact key falls back to the resource UID.
func TestCorrelateCloudResourcesStayDistinct(t *testing.T) {
	mk := func(res string) model.Finding {
		return model.Finding{Tool: "prowler", Tools: []string{"prowler"},
			Category: model.CategoryCloud, RuleID: "s3_bucket_public_read",
			Location: model.Location{Resource: res}}
	}
	in := []model.Finding{mk("arn:aws:s3:::bucket-a"), mk("arn:aws:s3:::bucket-b")}
	if out := Correlate(in); len(out) != 2 {
		t.Errorf("distinct cloud resources collapsed: got %d, want 2", len(out))
	}
	// The same resource is still a true duplicate.
	if out := Correlate([]model.Finding{mk("arn:aws:s3:::bucket-a"), mk("arn:aws:s3:::bucket-a")}); len(out) != 1 {
		t.Errorf("identical cloud finding must dedup, got %d", len(out))
	}
}

func TestCorrelateCrossToolCWEOverlap(t *testing.T) {
	in := []model.Finding{
		{Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "python.sqli", CWEs: []string{"CWE-89"},
			Location: model.Location{File: "app.py", StartLine: 10, EndLine: 12},
			Severity: model.SeverityHigh},
		{Tool: "codeql", Tools: []string{"codeql"}, Category: model.CategorySAST,
			RuleID: "py/sql-injection", CWEs: []string{"CWE-89"},
			Location: model.Location{File: "app.py", StartLine: 11, EndLine: 11},
			Severity: model.SeverityMedium},
	}
	out := Correlate(in)
	if len(out) != 1 {
		t.Fatalf("cross-tool same-CWE overlapping findings must merge, got %d", len(out))
	}
	if out[0].Location.StartLine != 10 || out[0].Location.EndLine != 12 {
		t.Errorf("merged location = %+v, want widened 10-12", out[0].Location)
	}
}

// TestCorrelateNeverMergesDifferentIssues is the adversarial guard on the
// noise collapse: every pair here is two DIFFERENT issues that must survive
// correlation separately. A failure means a real finding silently vanished —
// the worst failure this tool can have.
func TestCorrelateNeverMergesDifferentIssues(t *testing.T) {
	in := []model.Finding{
		// Same tool, same line, different rules, DIFFERENT CWEs: an SQLi and
		// an XSS on one line are two real findings, not noise.
		{Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "rule.sqli", CWEs: []string{"CWE-89"},
			Location: model.Location{File: "app.py", StartLine: 10}},
		{Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "rule.xss", CWEs: []string{"CWE-79"},
			Location: model.Location{File: "app.py", StartLine: 10}},
		// Different category on the same line: secret != SAST.
		{Tool: "gitleaks", Tools: []string{"gitleaks"}, Category: model.CategorySecret,
			RuleID: "aws-key", Location: model.Location{File: "app.py", StartLine: 10}},
		// Cross-tool overlap but no CWEs: never fuzzy-merge.
		{Tool: "codeql", Tools: []string{"codeql"}, Category: model.CategorySAST,
			RuleID: "rule.c", Location: model.Location{File: "app.py", StartLine: 10}},
	}
	if out := Correlate(in); len(out) != 4 {
		t.Errorf("distinct issues must never merge, got %d findings from 4", len(out))
	}
}

// TestCollapseNeverMergesAdversarialPairs exhausts the near-miss shapes of
// the same-tool collapse: each case fails exactly one collapse condition and
// must stay two findings.
func TestCollapseNeverMergesAdversarialPairs(t *testing.T) {
	base := func(rule string, cwes []string, start, end int) model.Finding {
		return model.Finding{Tool: "semgrep", Tools: []string{"semgrep"},
			Category: model.CategorySAST, RuleID: rule, CWEs: cwes,
			Location: model.Location{File: "app.py", StartLine: start, EndLine: end}}
	}
	cases := []struct {
		name string
		a, b model.Finding
	}{
		{"different CWE", base("r.a", []string{"CWE-89"}, 10, 10), base("r.b", []string{"CWE-78"}, 10, 10)},
		{"no CWE on one side", base("r.a", []string{"CWE-89"}, 10, 10), base("r.b", nil, 10, 10)},
		{"no CWE on either side", base("r.a", nil, 10, 10), base("r.b", nil, 10, 10)},
		{"non-overlapping ranges", base("r.a", []string{"CWE-89"}, 10, 12), base("r.b", []string{"CWE-89"}, 13, 15)},
		{"different file", base("r.a", []string{"CWE-89"}, 10, 10),
			func() model.Finding {
				f := base("r.b", []string{"CWE-89"}, 10, 10)
				f.Location.File = "other.py"
				return f
			}()},
		{"different tool same category", base("r.a", []string{"CWE-89"}, 10, 10),
			func() model.Finding {
				// Disjoint CWEs so the existing cross-tool CWE-overlap path
				// cannot merge this pair — isolates the same-tool condition.
				f := base("r.b", []string{"CWE-78"}, 10, 10)
				f.Tool = "codeql"
				f.Tools = []string{"codeql"}
				return f
			}()},
	}
	for _, tc := range cases {
		if out := Correlate([]model.Finding{tc.a, tc.b}); len(out) != 2 {
			t.Errorf("%s: got %d findings, want 2 — collapse merged two different issues", tc.name, len(out))
		}
	}
}

// TestCollapseNeverTouchesNonSAST: same-tool different-rule duplicates in
// SECRET and IAC stay separate even with shared CWEs — a second gitleaks rule
// is a different credential claim, two checkov rules are two controls.
func TestCollapseNeverTouchesNonSAST(t *testing.T) {
	for _, cat := range []string{model.CategorySecret, model.CategoryIaC} {
		in := []model.Finding{
			{Tool: "t", Tools: []string{"t"}, Category: cat, RuleID: "r.a",
				CWEs:     []string{"CWE-798"},
				Location: model.Location{File: "Dockerfile", StartLine: 3}},
			{Tool: "t", Tools: []string{"t"}, Category: cat, RuleID: "r.b",
				CWEs:     []string{"CWE-798"},
				Location: model.Location{File: "Dockerfile", StartLine: 3}},
		}
		if out := Correlate(in); len(out) != 2 {
			t.Errorf("%s: same-tool collapse must be SAST-only, got %d findings", cat, len(out))
		}
	}
}

// TestCollapseSameToolSharedCWE pins locked decision 1: the same tool
// flagging one weakness at one place via different rule IDs collapses to one
// finding that unions the evidence — highest toolSeverity, most specific
// title, absorbed rule IDs in meta.alsoRuleIds, survivor fingerprint intact.
func TestCollapseSameToolSharedCWE(t *testing.T) {
	low, high := model.SeverityLow, model.SeverityHigh
	a := model.Finding{ID: "id-a", Tool: "semgrep", Tools: []string{"semgrep"},
		Category: model.CategorySAST, RuleID: "python.sqli.generic",
		Title:    "SQL injection", // shorter: absorbed
		Severity: high, ToolSeverity: &high, RawSeverity: "ERROR",
		CWEs:     []string{"CWE-89"},
		Location: model.Location{File: "app.py", StartLine: 10, EndLine: 12}}
	b := model.Finding{ID: "id-b", Tool: "semgrep", Tools: []string{"semgrep"},
		Category: model.CategorySAST, RuleID: "python.flask.tainted-sql-string",
		Title:    "Tainted data flows into a SQL string", // longest: survivor
		Severity: low, ToolSeverity: &low, RawSeverity: "WARNING",
		CWEs:     []string{"CWE-89", "CWE-707"},
		Location: model.Location{File: "app.py", StartLine: 11, EndLine: 11}}

	out := Correlate([]model.Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1 (same-tool shared-CWE duplicates must collapse)", len(out))
	}
	f := out[0]
	if f.ID != "id-b" || f.RuleID != "python.flask.tainted-sql-string" {
		t.Errorf("survivor must be the most specific title's finding with identity intact; got rule %q id %q", f.RuleID, f.ID)
	}
	if f.Title != "Tainted data flows into a SQL string" {
		t.Errorf("collapse must keep the most specific title, got %q", f.Title)
	}
	if f.Severity != high || f.ToolSeverity == nil || *f.ToolSeverity != high || f.RawSeverity != "ERROR" {
		t.Errorf("collapse must keep the highest toolSeverity (+raw), got %v/%v/%q", f.Severity, f.ToolSeverity, f.RawSeverity)
	}
	if got := f.Meta["alsoRuleIds"]; got != "python.sqli.generic" {
		t.Errorf("meta.alsoRuleIds = %q, want absorbed rule recorded", got)
	}
	if len(f.CWEs) != 2 {
		t.Errorf("collapse must union CWEs, got %v", f.CWEs)
	}
	if f.Location.StartLine != 10 || f.Location.EndLine != 12 {
		t.Errorf("collapse must widen location, got %+v", f.Location)
	}
}

// TestCollapseThreeWay: three rules on one line fold into one finding with
// both absorbed rule IDs recorded, sorted and comma-joined, regardless of
// arrival order.
func TestCollapseThreeWay(t *testing.T) {
	mk := func(rule, title string) model.Finding {
		return model.Finding{Tool: "semgrep", Tools: []string{"semgrep"},
			Category: model.CategorySAST, RuleID: rule, Title: title,
			CWEs:     []string{"CWE-78"},
			Location: model.Location{File: "cmd.go", StartLine: 5, EndLine: 5}}
	}
	in := []model.Finding{
		mk("z.rule", "Command injection here"),                    // mid length
		mk("a.rule", "Cmd injection"),                             // shortest
		mk("m.rule", "OS command injection from tainted request"), // longest: survivor
	}
	out := Correlate(in)
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	if out[0].RuleID != "m.rule" {
		t.Errorf("survivor = %q, want m.rule (longest title)", out[0].RuleID)
	}
	if got, want := out[0].Meta["alsoRuleIds"], "a.rule,z.rule"; got != want {
		t.Errorf("alsoRuleIds = %q, want %q (sorted, comma-joined)", got, want)
	}
}

// TestCollapseDeterministicAcrossOrder: survivor choice and alsoRuleIds must
// not depend on input order, or run deltas would churn.
func TestCollapseDeterministicAcrossOrder(t *testing.T) {
	mk := func(rule, title string) model.Finding {
		return model.Finding{Tool: "semgrep", Tools: []string{"semgrep"},
			Category: model.CategorySAST, RuleID: rule, Title: title,
			CWEs:     []string{"CWE-89"},
			Location: model.Location{File: "db.py", StartLine: 7, EndLine: 7}}
	}
	a, b := mk("r.aaa", "Same length title!"), mk("r.bbb", "Same length titleX")
	fwd := Correlate([]model.Finding{a, b})
	rev := Correlate([]model.Finding{b, a})
	if len(fwd) != 1 || len(rev) != 1 {
		t.Fatalf("want 1 finding each order, got %d/%d", len(fwd), len(rev))
	}
	if fwd[0].RuleID != rev[0].RuleID || fwd[0].Meta["alsoRuleIds"] != rev[0].Meta["alsoRuleIds"] {
		t.Errorf("collapse is order-dependent: %q/%q vs %q/%q",
			fwd[0].RuleID, fwd[0].Meta["alsoRuleIds"], rev[0].RuleID, rev[0].Meta["alsoRuleIds"])
	}
	// Equal-length titles: the smaller rule ID must win in both orders.
	if fwd[0].RuleID != "r.aaa" {
		t.Errorf("tie-break survivor = %q, want r.aaa (smallest rule ID)", fwd[0].RuleID)
	}
}

// TestCollapseDoesNotMutateInputMeta: collapse must copy-on-write the Meta
// map — adapters share Meta with their RawFinding records.
func TestCollapseDoesNotMutateInputMeta(t *testing.T) {
	meta := map[string]string{"k": "v"}
	long := model.Finding{Tool: "semgrep", Tools: []string{"semgrep"},
		Category: model.CategorySAST, RuleID: "r.long",
		Title: "The much longer, more specific title", Meta: meta,
		CWEs:     []string{"CWE-89"},
		Location: model.Location{File: "a.py", StartLine: 1, EndLine: 1}}
	short := model.Finding{Tool: "semgrep", Tools: []string{"semgrep"},
		Category: model.CategorySAST, RuleID: "r.short", Title: "Short",
		CWEs:     []string{"CWE-89"},
		Location: model.Location{File: "a.py", StartLine: 1, EndLine: 1}}
	out := Correlate([]model.Finding{long, short})
	if len(out) != 1 {
		t.Fatalf("want collapse, got %d", len(out))
	}
	if _, leaked := meta["alsoRuleIds"]; leaked {
		t.Error("collapse mutated the input Meta map — must copy-on-write")
	}
	if out[0].Meta["k"] != "v" {
		t.Error("collapse must carry existing meta keys through the copy")
	}
}

func TestCorrelateCountNeverIncreasesAndNothingLost(t *testing.T) {
	in := []model.Finding{
		{Tool: "a", Tools: []string{"a"}, Category: model.CategorySAST, RuleID: "r1",
			Location: model.Location{File: "x.py", StartLine: 1}},
		{Tool: "b", Tools: []string{"b"}, Category: model.CategorySCA, CVE: "CVE-1",
			Package: "p@1"},
	}
	out := Correlate(in)
	if len(out) != 2 {
		t.Errorf("unrelated findings must pass through, got %d", len(out))
	}
}

// TestCorrelationKeysIgnoreTitleAndSeverity proves (not asserts) that the
// correlation identity is title- and severity-free: two findings differing in
// every presentation field still merge, and the merge keeps toolSeverity in
// step with the max-severity rule. Schema 2.0.0 (banded severity, human
// titles) depends on this.
func TestCorrelationKeysIgnoreTitleAndSeverity(t *testing.T) {
	low, high := model.SeverityLow, model.SeverityHigh
	in := []model.Finding{
		{Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "r.sqli", Title: "tainted-sql-string",
			Severity: low, ToolSeverity: &low, RawSeverity: "WARNING",
			Location: model.Location{File: "app.py", StartLine: 10, EndLine: 10}},
		{Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "r.sqli", Title: "SQL injection from tainted string",
			Severity: high, ToolSeverity: &high, RawSeverity: "ERROR",
			Location: model.Location{File: "app.py", StartLine: 10, EndLine: 10}},
	}
	out := Correlate(in)
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1 (title/severity must not affect the key)", len(out))
	}
	if out[0].Severity != high {
		t.Error("merge must keep the maximum severity")
	}
	if out[0].ToolSeverity == nil || *out[0].ToolSeverity != high {
		t.Error("merge must keep toolSeverity in step with the max severity")
	}
	if out[0].RawSeverity != "ERROR" {
		t.Error("merge must carry the raw severity of the max-severity source")
	}
}
