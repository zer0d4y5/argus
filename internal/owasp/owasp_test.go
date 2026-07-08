package owasp

import (
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func f(cat string, cwes ...string) model.Finding {
	return model.Finding{Category: cat, CWEs: cwes}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		finding model.Finding
		wantID  string
	}{
		{f(model.CategorySAST, "CWE-89"), "A03"},    // SQLi → Injection
		{f(model.CategorySAST, "CWE-78"), "A03"},    // command injection
		{f(model.CategorySAST, "CWE-79"), "A03"},    // XSS
		{f(model.CategorySAST, "CWE-502"), "A08"},   // deserialization → integrity
		{f(model.CategorySAST, "CWE-327"), "A02"},   // weak crypto
		{f(model.CategorySAST, "CWE-22"), "A01"},    // path traversal → access control
		{f(model.CategorySAST, "CWE-918"), "A10"},   // SSRF
		{f(model.CategorySAST, "CWE-99999"), "A04"}, // unmapped → Insecure Design
		{f(model.CategorySAST), "A04"},              // no CWE → Insecure Design
		{f(model.CategorySCA, "CWE-89"), "A06"},     // SCA always → components, ignoring CWE
		{f(model.CategorySecret), "A04"},            // secret, no CWE → default
		{f(model.CategoryIaC), "A05"},               // IaC → Security Misconfiguration
		{f(model.CategoryIaC, "CWE-89"), "A05"},     // IaC always → A05, ignoring CWE
	}
	for _, c := range cases {
		if got := Classify(c.finding); got.ID != c.wantID {
			t.Errorf("Classify(%v) = %s, want %s", c.finding, got.ID, c.wantID)
		}
	}
}

func TestRollupSumsToTotalAndIsTenRows(t *testing.T) {
	findings := []model.Finding{
		f(model.CategorySAST, "CWE-89"),
		f(model.CategorySAST, "CWE-79"),
		f(model.CategorySAST, "CWE-502"),
		f(model.CategorySCA, "CWE-1104"),
		f(model.CategorySAST, "CWE-99999"),
	}
	buckets := Rollup(findings)
	if len(buckets) != 10 {
		t.Fatalf("expected 10 rows, got %d", len(buckets))
	}
	total := 0
	for _, b := range buckets {
		total += b.Count
	}
	if total != len(findings) {
		t.Errorf("bucket counts sum to %d, want %d (a finding was dropped)", total, len(findings))
	}
	// A03 should have 2 (SQLi + XSS).
	for _, b := range buckets {
		if b.Category.ID == "A03" && b.Count != 2 {
			t.Errorf("A03 count = %d, want 2", b.Count)
		}
	}
}

func TestTopNonEmptySortedDesc(t *testing.T) {
	findings := []model.Finding{
		f(model.CategorySAST, "CWE-89"),
		f(model.CategorySAST, "CWE-78"),
		f(model.CategorySAST, "CWE-94"),
		f(model.CategorySAST, "CWE-327"),
	}
	top := TopNonEmpty(findings)
	if len(top) != 2 {
		t.Fatalf("expected 2 non-empty categories, got %d", len(top))
	}
	if top[0].Category.ID != "A03" || top[0].Count != 3 {
		t.Errorf("top bucket = %+v, want A03 count 3", top[0])
	}
	if top[1].Count > top[0].Count {
		t.Error("TopNonEmpty not sorted descending")
	}
}
