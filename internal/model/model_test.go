package model

import (
	"testing"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		tool, raw string
		want      Severity
	}{
		{"semgrep", "ERROR", SeverityHigh},
		{"semgrep", "WARNING", SeverityMedium},
		{"semgrep", "INFO", SeverityInfo},
		{"semgrep", "bogus", SeverityMedium}, // unknown fails toward medium
		{"gitleaks", "HIGH", SeverityHigh},
		{"gitleaks", "", SeverityHigh}, // secrets are always high
		{"trivy", "CRITICAL", SeverityCritical},
		{"trivy", "HIGH", SeverityHigh},
		{"trivy", "MEDIUM", SeverityMedium},
		{"trivy", "LOW", SeverityLow},
		{"trivy", "UNKNOWN", SeverityMedium}, // un-scored is not harmless
		{"trivy", "", SeverityMedium},
		{"trivy-config", "CRITICAL", SeverityCritical},
		{"trivy-config", "HIGH", SeverityHigh},
		{"trivy-config", "LOW", SeverityLow},
		{"trivy-config", "UNKNOWN", SeverityMedium},
		{"trivy-config", "bogus", SeverityMedium},
		{"checkov", "", SeverityMedium}, // OSS checkov emits no severity
		{"checkov", "CRITICAL", SeverityCritical},
		{"checkov", "HIGH", SeverityHigh},
		{"checkov", "MEDIUM", SeverityMedium},
		{"checkov", "LOW", SeverityLow},
		{"checkov", "INFO", SeverityInfo},
		{"checkov", "bogus", SeverityMedium},         // unknown fails toward medium
		{"futuretool", "critical", SeverityCritical}, // direct parse for new tools
		{"futuretool", "???", SeverityMedium},
	}
	for _, tt := range tests {
		if got := NormalizeSeverity(tt.tool, tt.raw); got != tt.want {
			t.Errorf("NormalizeSeverity(%q, %q) = %v, want %v", tt.tool, tt.raw, got, tt.want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(SeverityCritical > SeverityHigh && SeverityHigh > SeverityMedium &&
		SeverityMedium > SeverityLow && SeverityLow > SeverityInfo) {
		t.Fatal("severity ordering broken — the gate depends on it")
	}
}

func TestGate(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityLow},
		{Severity: SeverityHigh},
	}
	high := SeverityHigh
	critical := SeverityCritical
	if !GateExceeded(findings, &high) {
		t.Error("high finding must trip a high gate")
	}
	if GateExceeded(findings, &critical) {
		t.Error("high finding must not trip a critical gate")
	}
	if GateExceeded(findings, nil) {
		t.Error("nil gate (none) must never fail")
	}
	if GateExceeded(nil, &high) {
		t.Error("no findings must never fail")
	}
}

func TestParseGate(t *testing.T) {
	if g, err := ParseGate("none"); err != nil || g != nil {
		t.Errorf("ParseGate(none) = %v, %v; want nil, nil", g, err)
	}
	if g, err := ParseGate("HIGH"); err != nil || g == nil || *g != SeverityHigh {
		t.Errorf("ParseGate(HIGH) = %v, %v; want high", g, err)
	}
	if _, err := ParseGate("severe"); err == nil {
		t.Error("ParseGate must reject unknown values, not guess")
	}
}

func TestFingerprintStability(t *testing.T) {
	f := Finding{
		Tool: "semgrep", Category: CategorySAST, RuleID: "rule.sqli",
		Location: Location{File: "app.py", StartLine: 10},
	}
	id1 := Fingerprint(f)
	f.Description = "reworded by a new tool version"
	f.Severity = SeverityCritical
	if Fingerprint(f) != id1 {
		t.Error("fingerprint must ignore description/severity")
	}
	f.Location.StartLine = 11
	if Fingerprint(f) == id1 {
		t.Error("fingerprint must change when the location changes")
	}
	// Field-separator soundness: shifting a boundary must change the hash.
	a := Fingerprint(Finding{Tool: "ab", Category: "c"})
	b := Fingerprint(Finding{Tool: "a", Category: "bc"})
	if a == b {
		t.Error("fingerprint fields must be unambiguously separated")
	}
}

func TestNormalize(t *testing.T) {
	raws := []RawFinding{{
		Tool: "semgrep", Category: CategorySAST, RuleID: "r1",
		RawSeverity: "ERROR", File: "a\\b.py", StartLine: 5, EndLine: 3,
		CWEs: []string{"cwe-89", "CWE-89: SQL Injection", "89", ""},
	}}
	out := Normalize(raws)
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	f := out[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if f.RawSeverity != "ERROR" {
		t.Error("raw severity must be preserved verbatim")
	}
	if f.Location.File != "a/b.py" {
		t.Errorf("file = %q, want forward slashes", f.Location.File)
	}
	if f.Location.EndLine != 5 {
		t.Errorf("endLine = %d, want clamped to startLine", f.Location.EndLine)
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != "CWE-89" {
		t.Errorf("CWEs = %v, want [CWE-89]", f.CWEs)
	}
	if f.ID == "" || f.Title != "r1" {
		t.Errorf("ID/title not populated: %q / %q", f.ID, f.Title)
	}
}

func TestFilterIgnored(t *testing.T) {
	findings := []Finding{
		{RuleID: "keep", Location: Location{File: "src/app.py"}},
		{RuleID: "keep", Location: Location{File: "testdata/fixture/app.py"}},
		{RuleID: "suppressed-rule", Location: Location{File: "src/other.py"}},
		{RuleID: "keep", Location: Location{File: "vendor/lib/x.go"}},
		{RuleID: "keep", Location: Location{File: ""}}, // SCA: no path, never path-ignored
	}
	kept, suppressed := FilterIgnored(findings,
		[]string{"testdata/**", "vendor"}, []string{"suppressed-rule"})
	if suppressed != 3 {
		t.Errorf("suppressed = %d, want 3", suppressed)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2", len(kept))
	}
	for _, f := range kept {
		if f.RuleID != "keep" {
			t.Errorf("wrong finding kept: %+v", f)
		}
	}
	// Ignoring nothing keeps everything.
	kept, suppressed = FilterIgnored(findings, nil, nil)
	if len(kept) != 5 || suppressed != 0 {
		t.Error("empty ignore lists must keep all findings")
	}
}
