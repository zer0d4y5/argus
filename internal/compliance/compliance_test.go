package compliance

import (
	"regexp"
	"testing"

	"github.com/leaky-hub/appsec/internal/model"
)

func sast(cwes ...string) model.Finding {
	return model.Finding{ID: "f1", Category: model.CategorySAST, RuleID: "rule", CWEs: cwes}
}

func iac(ruleID string) model.Finding {
	return model.Finding{ID: "f2", Category: model.CategoryIaC, RuleID: ruleID}
}

func mustMap(t *testing.T, f model.Finding) []string {
	t.Helper()
	got, err := MapFinding(f)
	if err != nil {
		t.Fatalf("MapFinding: %v", err)
	}
	return got
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// The embedded data must load and validate: five frameworks, pinned versions.
func TestEmbeddedDataLoads(t *testing.T) {
	fws, err := Frameworks()
	if err != nil {
		t.Fatalf("Frameworks: %v", err)
	}
	want := map[string]string{
		"ASVS":       "4.0.3",
		"PCI-DSS":    "4.0",
		"CIS-AWS":    "1.5.0",
		"CIS-DOCKER": "1.6.0",
		"CIS-K8S":    "1.8.0",
	}
	if len(fws) != len(want) {
		t.Fatalf("got %d frameworks, want %d", len(fws), len(want))
	}
	for _, fw := range fws {
		if want[fw.ID] != fw.Version {
			t.Errorf("framework %s: version %q, want %q", fw.ID, fw.Version, want[fw.ID])
		}
	}
}

// Known CWE -> expected controls, covering every vulnerability class planted in
// the polyglot fixtures plus SECRET/SCA category mappings.
func TestKnownMappings(t *testing.T) {
	cases := []struct {
		name string
		f    model.Finding
		want []string // must all be present
	}{
		{"sql injection", sast("CWE-89"), []string{"ASVS:V5.3.4", "ASVS:V5.3.5", "PCI-DSS:6.2.4"}},
		{"xss", sast("CWE-79"), []string{"ASVS:V5.3.3", "PCI-DSS:6.2.4"}},
		{"os command injection", sast("CWE-78"), []string{"ASVS:V5.3.8", "PCI-DSS:6.2.4"}},
		{"code injection", sast("CWE-94"), []string{"ASVS:V5.2.5", "PCI-DSS:6.2.4"}},
		{"eval injection", sast("CWE-95"), []string{"ASVS:V5.2.4", "PCI-DSS:6.2.4"}},
		{"deserialization", sast("CWE-502"), []string{"ASVS:V5.5.3", "PCI-DSS:6.2.4"}},
		{"weak crypto", sast("CWE-327"), []string{"ASVS:V6.2.2", "PCI-DSS:6.2.4"}},
		{"weak hash", sast("CWE-328"), []string{"ASVS:V6.2.5", "PCI-DSS:6.2.4"}},
		{"cleartext transmission", sast("CWE-319"), []string{"ASVS:V9.1.1", "PCI-DSS:4.2.1"}},
		{"unencrypted storage", sast("CWE-311"), []string{"ASVS:V6.1.1"}},
		{"ssrf", sast("CWE-918"), []string{"ASVS:V5.2.6", "PCI-DSS:6.2.4"}},
		{"path traversal", sast("CWE-22"), []string{"ASVS:V12.3.1", "PCI-DSS:6.2.4"}},
		{"hardcoded creds cwe", sast("CWE-798"), []string{"ASVS:V2.10.4", "ASVS:V6.4.1", "PCI-DSS:8.6.2"}},
		{
			"secret category (gitleaks emits no CWEs)",
			model.Finding{Category: model.CategorySecret, RuleID: "aws-access-token"},
			[]string{"ASVS:V2.10.4", "ASVS:V6.4.1", "PCI-DSS:8.6.2"},
		},
		{
			"sca category",
			model.Finding{Category: model.CategorySCA, RuleID: "CVE-2021-44228", CVE: "CVE-2021-44228"},
			[]string{"ASVS:V14.2.1", "PCI-DSS:6.3.3"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustMap(t, tc.f)
			for _, w := range tc.want {
				if !contains(got, w) {
					t.Errorf("%s: missing %s in %v", tc.name, w, got)
				}
			}
			for _, v := range got {
				if regexp.MustCompile(`^CIS-`).MatchString(v) {
					t.Errorf("%s: non-IaC finding mapped to CIS control %s", tc.name, v)
				}
			}
		})
	}
}

// IaC rules land in the right CIS section AND the PCI configuration-standards
// requirement; never in ASVS (out of scope).
func TestIaCRuleMappings(t *testing.T) {
	cases := []struct {
		ruleID string
		want   []string
	}{
		{"CKV_AWS_24", []string{"CIS-AWS:5", "PCI-DSS:2.2.1"}},   // open SSH ingress -> Networking
		{"AWS-0107", []string{"CIS-AWS:5", "PCI-DSS:2.2.1"}},     // trivy twin of the same class
		{"CKV_AWS_3", []string{"CIS-AWS:2.2", "PCI-DSS:2.2.1"}},  // EBS encryption -> Storage/EC2
		{"AWS-0092", []string{"CIS-AWS:2.1", "PCI-DSS:2.2.1"}},   // S3 public ACL -> Storage/S3
		{"CKV_AWS_18", []string{"CIS-AWS:3", "PCI-DSS:2.2.1"}},   // access logging -> Logging
		{"CKV_DOCKER_3", []string{"CIS-DOCKER:4", "PCI-DSS:2.2.1"}},
		{"DS-0002", []string{"CIS-DOCKER:4", "PCI-DSS:2.2.1"}},   // root user, via DS- family
		{"CKV_K8S_16", []string{"CIS-K8S:5.2", "PCI-DSS:2.2.1"}}, // privileged container
		{"KSV-0017", []string{"CIS-K8S:5.2", "PCI-DSS:2.2.1"}},
		{"CKV_K8S_38", []string{"CIS-K8S:5.1", "PCI-DSS:2.2.1"}}, // SA token mounting
		{"CKV2_K8S_6", []string{"CIS-K8S:5.3", "PCI-DSS:2.2.1"}}, // missing NetworkPolicy
		{"CKV_K8S_21", []string{"CIS-K8S:5.7", "PCI-DSS:2.2.1"}}, // default namespace
	}
	for _, tc := range cases {
		got := mustMap(t, iac(tc.ruleID))
		for _, w := range tc.want {
			if !contains(got, w) {
				t.Errorf("%s: missing %s in %v", tc.ruleID, w, got)
			}
		}
		for _, v := range got {
			if regexp.MustCompile(`^ASVS:`).MatchString(v) {
				t.Errorf("%s: IaC finding mapped into ASVS (out of scope): %s", tc.ruleID, v)
			}
		}
	}
}

// Hygiene checks with no corresponding CIS control map only to the PCI
// category-level requirement — deliberately NOT to a CIS section.
func TestDeliberatelyUnmappedForCIS(t *testing.T) {
	for _, ruleID := range []string{
		"CKV_K8S_8",   // liveness probe
		"CKV_K8S_10",  // CPU requests
		"KSV-0011",    // CPU not limited
		"CKV_AWS_21",  // S3 versioning
		"CKV_AWS_144", // cross-region replication
		"CKV_AWS_23",  // SG description
		"CKV2_AWS_61", // lifecycle configuration
	} {
		got := mustMap(t, iac(ruleID))
		for _, v := range got {
			if regexp.MustCompile(`^CIS-`).MatchString(v) {
				t.Errorf("%s: hygiene rule must not claim a CIS control, got %s", ruleID, v)
			}
		}
		if !contains(got, "PCI-DSS:2.2.1") {
			t.Errorf("%s: IAC finding should still carry PCI-DSS:2.2.1, got %v", ruleID, got)
		}
	}
}

// An unmapped CWE yields no controls — and is never an error.
func TestUnmappedCWE(t *testing.T) {
	got := mustMap(t, sast("CWE-99999"))
	if got != nil {
		t.Errorf("unknown CWE should map to nothing, got %v", got)
	}
}

// Apply enriches in place, never drops or reorders, and emits the documented
// "<FRAMEWORK>:<control-id>" value format, sorted.
func TestApply(t *testing.T) {
	findings := []model.Finding{
		sast("CWE-89"),
		iac("CKV_K8S_16"),
		sast("CWE-99999"),
	}
	findings[0].ID, findings[1].ID, findings[2].ID = "a", "b", "c"
	if err := Apply(findings); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(findings) != 3 || findings[0].ID != "a" || findings[1].ID != "b" || findings[2].ID != "c" {
		t.Fatal("Apply must not drop or reorder findings")
	}
	format := regexp.MustCompile(`^[A-Z0-9-]+:[^\s:]+$`)
	for _, f := range findings[:2] {
		if len(f.ComplianceControls) == 0 {
			t.Fatalf("finding %s: expected controls", f.ID)
		}
		for i, v := range f.ComplianceControls {
			if !format.MatchString(v) {
				t.Errorf("bad control value format: %q", v)
			}
			if i > 0 && f.ComplianceControls[i-1] >= v {
				t.Errorf("controls not sorted/deduped: %v", f.ComplianceControls)
			}
		}
	}
	if findings[2].ComplianceControls != nil {
		t.Errorf("unmapped finding should have empty slot, got %v", findings[2].ComplianceControls)
	}
}

// Engine mechanics: an exact ruleIds match suppresses rulePrefixes rules.
func TestExactRuleBeatsPrefix(t *testing.T) {
	fw := Framework{
		ID: "T", Name: "t", Version: "1", Scope: []string{model.CategoryIaC},
		Controls: []Control{{ID: "A", Title: "a"}, {ID: "B", Title: "b"}},
		Rules: []Rule{
			{RuleIDs: []string{"CKV_X_1"}, Controls: []string{"A"}},
			{RulePrefixes: []string{"CKV_X_"}, Controls: []string{"B"}},
		},
	}
	if err := validate(&fw); err != nil {
		t.Fatalf("validate: %v", err)
	}
	got := fw.controlsFor(iac("CKV_X_1"))
	if len(got) != 1 || got[0] != "A" {
		t.Errorf("exact match must suppress prefix rule: got %v, want [A]", got)
	}
	got = fw.controlsFor(iac("CKV_X_2"))
	if len(got) != 1 || got[0] != "B" {
		t.Errorf("prefix fallback: got %v, want [B]", got)
	}
}

// Loader validation rejects malformed framework data.
func TestValidateRejectsBadData(t *testing.T) {
	base := func() Framework {
		return Framework{
			ID: "T", Name: "t", Version: "1", Scope: []string{"SAST"},
			Controls: []Control{{ID: "A", Title: "a"}},
			Rules:    []Rule{{CWEs: []string{"CWE-1"}, Controls: []string{"A"}}},
		}
	}
	cases := []struct {
		name  string
		mutid func(*Framework)
	}{
		{"missing version", func(fw *Framework) { fw.Version = "" }},
		{"colon in id", func(fw *Framework) { fw.ID = "A:B" }},
		{"empty scope", func(fw *Framework) { fw.Scope = nil }},
		{"unknown scope category", func(fw *Framework) { fw.Scope = []string{"NOPE"} }},
		{"duplicate control", func(fw *Framework) { fw.Controls = append(fw.Controls, Control{ID: "A", Title: "dup"}) }},
		{"rule references unknown control", func(fw *Framework) { fw.Rules[0].Controls = []string{"MISSING"} }},
		{"rule with no match key", func(fw *Framework) { fw.Rules[0].CWEs = nil }},
		{"rule with two match keys", func(fw *Framework) { fw.Rules[0].Category = "SAST" }},
		{"unreachable control", func(fw *Framework) {
			fw.Controls = append(fw.Controls, Control{ID: "ORPHAN", Title: "never referenced"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fw := base()
			tc.mutid(&fw)
			if err := validate(&fw); err == nil {
				t.Errorf("validate accepted bad data (%s)", tc.name)
			}
		})
	}
	good := base()
	if err := validate(&good); err != nil {
		t.Fatalf("baseline framework should validate: %v", err)
	}
}
