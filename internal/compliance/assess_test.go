package compliance

import (
	"testing"
	"time"

	"github.com/leaky-hub/argus/internal/model"
)

// A representative mixed run: mapped SAST, unmapped SAST, mapped IaC,
// hygiene (CIS-unmapped) IaC, a secret, and a vulnerable dependency.
func mixedFindings() []model.Finding {
	return []model.Finding{
		{ID: "f1", Category: model.CategorySAST, RuleID: "sqli", Title: "SQL injection", Severity: model.SeverityHigh, CWEs: []string{"CWE-89"}},
		{ID: "f2", Category: model.CategorySAST, RuleID: "sqli2", Title: "SQL injection 2", Severity: model.SeverityHigh, CWEs: []string{"CWE-89"}},
		{ID: "f3", Category: model.CategorySAST, RuleID: "weird", Title: "Unmappable", Severity: model.SeverityMedium, CWEs: []string{"CWE-99999"}},
		{ID: "f4", Category: model.CategoryIaC, RuleID: "CKV_K8S_16", Title: "Privileged container", Severity: model.SeverityMedium},
		{ID: "f5", Category: model.CategoryIaC, RuleID: "CKV_K8S_8", Title: "No liveness probe", Severity: model.SeverityMedium},
		{ID: "f6", Category: model.CategorySecret, RuleID: "aws-key", Title: "AWS key", Severity: model.SeverityHigh},
		{ID: "f7", Category: model.CategorySCA, RuleID: "CVE-2024-1", Title: "Vulnerable dep", Severity: model.SeverityCritical, CVE: "CVE-2024-1"},
	}
}

// The core reconciliation invariants: nothing is ever lost, and every
// assessable control is in exactly one bucket.
func TestAssessReconciles(t *testing.T) {
	findings := mixedFindings()
	reports, err := Assess(findings)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	fws, _ := Frameworks()
	if len(reports) != len(fws) {
		t.Fatalf("got %d reports, want %d", len(reports), len(fws))
	}
	for _, r := range reports {
		if got := r.MappedFindings + r.UnmappedFindings + r.OutOfScopeFindings; got != len(findings) {
			t.Errorf("%s: mapped(%d)+unmapped(%d)+outOfScope(%d)=%d, want %d",
				r.ID, r.MappedFindings, r.UnmappedFindings, r.OutOfScopeFindings, got, len(findings))
		}
		if r.ViolatedControls+r.CleanControls != len(r.Controls) {
			t.Errorf("%s: violated(%d)+clean(%d) != controls(%d)", r.ID, r.ViolatedControls, r.CleanControls, len(r.Controls))
		}
		if len(r.UnmappedRefs) != r.UnmappedFindings {
			t.Errorf("%s: unmapped refs %d != unmapped count %d", r.ID, len(r.UnmappedRefs), r.UnmappedFindings)
		}
		seen := map[string]bool{}
		violatedZone := true
		for _, c := range r.Controls {
			if seen[c.ID] {
				t.Errorf("%s: control %s appears twice", r.ID, c.ID)
			}
			seen[c.ID] = true
			switch c.Status {
			case StatusViolated:
				if !violatedZone {
					t.Errorf("%s: violated control %s after clean rows (ordering broken)", r.ID, c.ID)
				}
				if c.FindingCount < 1 {
					t.Errorf("%s: violated control %s with zero findings", r.ID, c.ID)
				}
				if len(c.TopFindings) == 0 || len(c.TopFindings) > maxTopFindings {
					t.Errorf("%s: control %s has %d top findings", r.ID, c.ID, len(c.TopFindings))
				}
			case StatusClean:
				violatedZone = false
				if c.FindingCount != 0 || len(c.TopFindings) != 0 {
					t.Errorf("%s: clean control %s carries findings — overclaim inversion", r.ID, c.ID)
				}
			default:
				t.Errorf("%s: control %s has unknown status %q", r.ID, c.ID, c.Status)
			}
		}
	}
}

// Spot-check the buckets for the mixed run per framework.
func TestAssessBuckets(t *testing.T) {
	reports, err := Assess(mixedFindings())
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	byID := map[string]FrameworkReport{}
	for _, r := range reports {
		byID[r.ID] = r
	}

	asvs := byID["ASVS"]
	// f1,f2 (CWE-89), f6 (secret), f7 (SCA) map; f3 unmapped; f4,f5 out of scope.
	if asvs.MappedFindings != 4 || asvs.UnmappedFindings != 1 || asvs.OutOfScopeFindings != 2 {
		t.Errorf("ASVS buckets: %+v", asvs)
	}
	control := func(r FrameworkReport, id string) *ControlStatus {
		for i := range r.Controls {
			if r.Controls[i].ID == id {
				return &r.Controls[i]
			}
		}
		return nil
	}
	if c := control(asvs, "V5.3.4"); c == nil || c.Status != StatusViolated || c.FindingCount != 2 {
		t.Errorf("ASVS V5.3.4: %+v", c)
	}
	// LDAP injection control is a rule target with no findings -> clean.
	if c := control(asvs, "V5.3.7"); c == nil || c.Status != StatusClean {
		t.Errorf("ASVS V5.3.7 should be clean: %+v", c)
	}

	cisK8s := byID["CIS-K8S"]
	// f4 maps to 5.2; f5 (probe hygiene) is unmapped; everything else out of scope.
	if cisK8s.MappedFindings != 1 || cisK8s.UnmappedFindings != 1 || cisK8s.OutOfScopeFindings != 5 {
		t.Errorf("CIS-K8S buckets: %+v", cisK8s)
	}
	if c := control(cisK8s, "5.2"); c == nil || c.Status != StatusViolated {
		t.Errorf("CIS-K8S 5.2: %+v", c)
	}
	if len(cisK8s.UnmappedRefs) != 1 || cisK8s.UnmappedRefs[0].ID != "f5" {
		t.Errorf("CIS-K8S unmapped refs: %+v", cisK8s.UnmappedRefs)
	}

	pci := byID["PCI-DSS"]
	// Everything is in scope for PCI; only f3 (unknown CWE) is unmapped.
	if pci.MappedFindings != 6 || pci.UnmappedFindings != 1 || pci.OutOfScopeFindings != 0 {
		t.Errorf("PCI-DSS buckets: %+v", pci)
	}
}

// Platform benchmarks must treat other platforms' rules as out of scope, not
// as mapping gaps: a K8s hygiene rule is "unmapped" only for the K8s benchmark.
func TestRuleIDScope(t *testing.T) {
	findings := []model.Finding{
		{ID: "k1", Category: model.CategoryIaC, RuleID: "KSV-0011", Title: "CPU not limited", Severity: model.SeverityMedium},
	}
	reports, err := Assess(findings)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, r := range reports {
		switch r.ID {
		case "CIS-K8S":
			if r.UnmappedFindings != 1 || r.OutOfScopeFindings != 0 {
				t.Errorf("CIS-K8S: want unmapped=1, got %+v", r)
			}
		case "CIS-AWS", "CIS-DOCKER":
			if r.OutOfScopeFindings != 1 || r.UnmappedFindings != 0 {
				t.Errorf("%s: K8s rule must be out of scope, got unmapped=%d outOfScope=%d",
					r.ID, r.UnmappedFindings, r.OutOfScopeFindings)
			}
		}
	}
}

// TopFindings evidence is capped and inherits input order.
func TestTopFindingsCap(t *testing.T) {
	var findings []model.Finding
	for i := 0; i < 5; i++ {
		f := model.Finding{ID: string(rune('a' + i)), Category: model.CategorySAST,
			RuleID: "sqli", Title: "sqli", Severity: model.SeverityHigh, CWEs: []string{"CWE-89"}}
		findings = append(findings, f)
	}
	reports, err := Assess(findings)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, r := range reports {
		if r.ID != "ASVS" {
			continue
		}
		for _, c := range r.Controls {
			if c.ID == "V5.3.4" {
				if c.FindingCount != 5 {
					t.Errorf("count %d, want 5", c.FindingCount)
				}
				if len(c.TopFindings) != maxTopFindings {
					t.Errorf("top findings %d, want %d", len(c.TopFindings), maxTopFindings)
				}
				if c.TopFindings[0].ID != "a" {
					t.Errorf("top findings must preserve input order, got %s first", c.TopFindings[0].ID)
				}
			}
		}
	}
}

// Assess must never mutate the findings it reads.
func TestAssessReadOnly(t *testing.T) {
	findings := mixedFindings()
	if _, err := Assess(findings); err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, f := range findings {
		if f.ComplianceControls != nil {
			t.Errorf("Assess mutated finding %s", f.ID)
		}
	}
}

func TestSummarizeMatchesAssess(t *testing.T) {
	findings := mixedFindings()
	reports, _ := Assess(findings)
	sums, err := Summarize(findings)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if len(sums) != len(reports) {
		t.Fatalf("summary count %d != report count %d", len(sums), len(reports))
	}
	for i, s := range sums {
		r := reports[i]
		if s.ID != r.ID || s.ViolatedControls != r.ViolatedControls ||
			s.CleanControls != r.CleanControls || s.NotAssessable != len(r.NotAssessable) ||
			s.UnmappedFindings != r.UnmappedFindings {
			t.Errorf("summary %s diverges from report: %+v vs %+v", s.ID, s, r)
		}
	}
}

func TestBuildReport(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	rep, err := BuildReport(mixedFindings(), "/repo", "scan", now)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if rep.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema %s", rep.SchemaVersion)
	}
	if rep.GeneratedAt != "2026-07-04T12:00:00Z" {
		t.Errorf("generatedAt %s", rep.GeneratedAt)
	}
	if rep.TotalFindings != 7 || rep.Target != "/repo" || rep.Source != "scan" || len(rep.Frameworks) == 0 {
		t.Errorf("report fields: %+v", rep)
	}
}
