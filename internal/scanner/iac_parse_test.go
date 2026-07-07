package scanner

import (
	"testing"

	"github.com/leaky-hub/argus/internal/model"
)

// Payloads mirror real checkov 3.3.2 / trivy 0.71.2 output shapes (trimmed).

func TestParseCheckov(t *testing.T) {
	// Top-level array of per-framework runs, severity null (OSS), benchmarks null.
	checkovJSON := `[
		{
			"check_type": "terraform",
			"results": {
				"passed_checks": [{"check_id": "CKV_AWS_999", "check_result": {"result": "PASSED"}}],
				"failed_checks": [
					{
						"check_id": "CKV_AWS_24",
						"bc_check_id": "BC_AWS_NETWORKING_1",
						"check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
						"check_result": {"result": "FAILED"},
						"file_path": "/main.tf",
						"file_line_range": [6, 14],
						"resource": "aws_security_group.open_ssh",
						"severity": null,
						"benchmarks": null,
						"guideline": "https://example.com/networking-1"
					},
					{"not_a_check": true},
					{
						"check_id": "CKV_AWS_20",
						"check_name": "S3 Bucket has an ACL defined which allows public READ access.",
						"check_result": {"result": "FAILED"},
						"file_path": "/main.tf",
						"file_line_range": [1, 4],
						"resource": "aws_s3_bucket.public_bucket",
						"severity": "HIGH",
						"benchmarks": {"CIS AWS V1.4": ["2.1.5"]}
					}
				]
			}
		},
		{
			"check_type": "dockerfile",
			"results": {
				"failed_checks": [
					{
						"check_id": "CKV_DOCKER_7",
						"check_name": "Ensure the base image uses a non latest version tag",
						"check_result": {"result": "FAILED"},
						"file_path": "/docker/Dockerfile",
						"file_line_range": [1, 1],
						"resource": "/docker/Dockerfile.FROM",
						"severity": null
					}
				]
			}
		}
	]`

	findings, err := parseCheckov([]byte(checkovJSON))
	if err != nil {
		t.Fatalf("parseCheckov error: %v", err)
	}
	// The malformed entry (no check_id) is skipped; passed checks never
	// become findings.
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.Tool != "checkov" {
		t.Errorf("Tool = %q; want checkov", f1.Tool)
	}
	if f1.Category != model.CategoryIaC {
		t.Errorf("Category = %q; want %q", f1.Category, model.CategoryIaC)
	}
	if f1.RuleID != "CKV_AWS_24" {
		t.Errorf("RuleID = %q; want CKV_AWS_24", f1.RuleID)
	}
	if f1.File != "/main.tf" {
		t.Errorf("File = %q; want /main.tf (re-rooting happens in Scan)", f1.File)
	}
	if f1.StartLine != 6 || f1.EndLine != 14 {
		t.Errorf("lines = %d-%d; want 6-14", f1.StartLine, f1.EndLine)
	}
	if f1.RawSeverity != "" {
		t.Errorf("RawSeverity = %q; want empty (OSS null)", f1.RawSeverity)
	}
	if f1.Meta["resource"] != "aws_security_group.open_ssh" {
		t.Errorf("meta resource = %q", f1.Meta["resource"])
	}
	if f1.Meta["framework"] != "terraform" {
		t.Errorf("meta framework = %q; want terraform", f1.Meta["framework"])
	}
	if f1.Meta["guideline"] != "https://example.com/networking-1" {
		t.Errorf("meta guideline = %q", f1.Meta["guideline"])
	}
	if _, ok := f1.Meta["benchmarks"]; ok {
		t.Error("null benchmarks must not be captured")
	}
	if len(f1.RawPayload) == 0 {
		t.Error("RawPayload not preserved")
	}

	f2 := findings[1]
	if f2.RawSeverity != "HIGH" {
		t.Errorf("platform-enriched severity = %q; want HIGH", f2.RawSeverity)
	}
	if f2.Meta["benchmarks"] != `{"CIS AWS V1.4": ["2.1.5"]}` {
		t.Errorf("CIS benchmarks not captured to meta: %q", f2.Meta["benchmarks"])
	}

	f3 := findings[2]
	if f3.RuleID != "CKV_DOCKER_7" || f3.Meta["framework"] != "dockerfile" {
		t.Errorf("dockerfile run mis-parsed: %+v", f3)
	}
}

func TestParseCheckovSingleRunObject(t *testing.T) {
	// One framework -> checkov emits a single object, not an array.
	single := `{
		"check_type": "kubernetes",
		"results": {
			"failed_checks": [
				{
					"check_id": "CKV_K8S_16",
					"check_name": "Container should not be privileged",
					"file_path": "/deployment.yaml",
					"file_line_range": [1, 27],
					"resource": "Deployment.default.vulnerable-app"
				}
			]
		}
	}`
	findings, err := parseCheckov([]byte(single))
	if err != nil {
		t.Fatalf("parseCheckov error: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "CKV_K8S_16" {
		t.Fatalf("single-object shape mis-parsed: %+v", findings)
	}
}

func TestParseCheckovMalformed(t *testing.T) {
	if _, err := parseCheckov([]byte("not json")); err == nil {
		t.Error("expected decode error for garbage input")
	}
}

func TestParseTrivyConfig(t *testing.T) {
	trivyJSON := `{
		"SchemaVersion": 2,
		"Results": [
			{
				"Target": "terraform/main.tf",
				"Class": "config",
				"Type": "terraform",
				"Misconfigurations": [
					{
						"Type": "Terraform Security Check",
						"ID": "AWS-0107",
						"AVDID": "AVD-AWS-0107",
						"Title": "Security groups should not allow unrestricted ingress to SSH",
						"Description": "Opening up ports to the public internet is generally to be avoided.",
						"Message": "Security group rule allows unrestricted ingress to SSH",
						"Resolution": "Restrict the CIDR range",
						"Severity": "HIGH",
						"Status": "FAIL",
						"PrimaryURL": "https://avd.aquasec.com/misconfig/aws-0107",
						"CauseMetadata": {
							"Resource": "aws_security_group.open_ssh",
							"Provider": "AWS",
							"Service": "vpc",
							"StartLine": 17,
							"EndLine": 22
						}
					},
					{
						"ID": "AWS-0999",
						"Title": "A passing check",
						"Severity": "LOW",
						"Status": "PASS"
					},
					{"garbage": ["not", {"a": "misconf"}]}
				]
			},
			{
				"Target": "docker/Dockerfile",
				"Class": "config",
				"Type": "dockerfile",
				"Misconfigurations": [
					{
						"ID": "DS-0031",
						"Title": "Secrets passed via envs",
						"Severity": "CRITICAL",
						"Status": "FAIL",
						"CauseMetadata": {"StartLine": 4, "EndLine": 4}
					}
				]
			},
			{"Target": "unrelated.txt", "Class": "config", "Misconfigurations": null}
		]
	}`

	findings, err := parseTrivyConfig([]byte(trivyJSON))
	if err != nil {
		t.Fatalf("parseTrivyConfig error: %v", err)
	}
	// PASS entries and entries without an ID are skipped.
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.Tool != "trivy-config" {
		t.Errorf("Tool = %q; want trivy-config", f1.Tool)
	}
	if f1.Category != model.CategoryIaC {
		t.Errorf("Category = %q; want %q", f1.Category, model.CategoryIaC)
	}
	if f1.RuleID != "AWS-0107" {
		t.Errorf("RuleID = %q; want AWS-0107", f1.RuleID)
	}
	if f1.RawSeverity != "HIGH" {
		t.Errorf("RawSeverity = %q; want HIGH", f1.RawSeverity)
	}
	if f1.File != "terraform/main.tf" {
		t.Errorf("File = %q; want terraform/main.tf", f1.File)
	}
	if f1.StartLine != 17 || f1.EndLine != 22 {
		t.Errorf("lines = %d-%d; want 17-22", f1.StartLine, f1.EndLine)
	}
	if f1.Remediation != "Restrict the CIDR range" {
		t.Errorf("Remediation = %q", f1.Remediation)
	}
	if f1.Meta["resource"] != "aws_security_group.open_ssh" || f1.Meta["avdid"] != "AVD-AWS-0107" {
		t.Errorf("meta not captured: %+v", f1.Meta)
	}
	if f1.Meta["message"] != "Security group rule allows unrestricted ingress to SSH" {
		t.Errorf("meta message = %q", f1.Meta["message"])
	}

	f2 := findings[1]
	if f2.RuleID != "DS-0031" || f2.RawSeverity != "CRITICAL" || f2.File != "docker/Dockerfile" {
		t.Errorf("dockerfile misconf mis-parsed: %+v", f2)
	}
}

func TestParseTrivyConfigMalformed(t *testing.T) {
	if _, err := parseTrivyConfig([]byte("not json")); err == nil {
		t.Error("expected decode error for garbage input")
	}
}

func TestIaCAdapterIdentity(t *testing.T) {
	c := &Checkov{}
	if c.Name() != "checkov" || c.Category() != model.CategoryIaC {
		t.Errorf("checkov identity: %s/%s", c.Name(), c.Category())
	}
	tc := &TrivyConfig{}
	if tc.Name() != "trivy-config" || tc.Category() != model.CategoryIaC {
		t.Errorf("trivy-config identity: %s/%s", tc.Name(), tc.Category())
	}
	// Both IaC adapters must be in the default registry.
	names := map[string]bool{}
	for _, a := range All(nil) {
		names[a.Name()] = true
	}
	for _, want := range []string{"semgrep", "gitleaks", "trivy", "checkov", "trivy-config"} {
		if !names[want] {
			t.Errorf("All() missing adapter %q", want)
		}
	}
}
