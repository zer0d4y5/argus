package correlate

import (
	"testing"

	"github.com/leaky-hub/appsec/internal/model"
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

func TestCorrelateNeverMergesDifferentIssues(t *testing.T) {
	in := []model.Finding{
		// Same tool, same file+line, different rules: two real findings.
		{Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "rule.a", CWEs: []string{"CWE-89"},
			Location: model.Location{File: "app.py", StartLine: 10}},
		{Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "rule.b", CWEs: []string{"CWE-89"},
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
