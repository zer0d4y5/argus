package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/leaky-hub/appsec/internal/model"
)

func TestParseSemgrep(t *testing.T) {
	semgrepJSON := `{
		"results": [
			{
				"check_id": "python.lang.security.xss.raw-string.raw-string",
				"path": "app/views.py",
				"start": {"line": 10},
				"end": {"line": 12},
				"extra": {
					"message": "Use of raw string detected",
					"severity": "ERROR",
					"fix": "Remove the raw string prefix.",
					"metadata": {
						"confidence": "HIGH",
						"cwe": ["CWE-79", "CWE-80"],
						"owasp": ["A7:2017-Cross-Site Scripting (XSS)"],
						"category": "security"
					}
				}
			},
			{
				"check_id": "go.lang.security.sql-injection.sql-injection",
				"path": "pkg/db/query.go",
				"start": {"line": 45},
				"end": {"line": 45},
				"extra": {
					"message": "SQL injection vulnerability",
					"severity": "CRITICAL",
					"fix": "Use parameterized queries.",
					"metadata": {
						"confidence": "HIGH",
						"cwe": "CWE-89",
						"owasp": "A1:2017-Injection",
						"category": "security"
					}
				}
			}
		]
	}`

	findings, err := parseSemgrep([]byte(semgrepJSON))
	if err != nil {
		t.Fatalf("parseSemgrep error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first finding (array CWEs)
	f1 := findings[0]
	if f1.Tool != "semgrep" {
		t.Errorf("f1 Tool = %q; want %q", f1.Tool, "semgrep")
	}
	if f1.Category != model.CategorySAST {
		t.Errorf("f1 Category = %q; want %q", f1.Category, model.CategorySAST)
	}
	if f1.RuleID != "python.lang.security.xss.raw-string.raw-string" {
		t.Errorf("f1 RuleID = %q; want %q", f1.RuleID, "python.lang.security.xss.raw-string.raw-string")
	}
	if f1.File != "app/views.py" {
		t.Errorf("f1 File = %q; want %q", f1.File, "app/views.py")
	}
	if f1.StartLine != 10 {
		t.Errorf("f1 StartLine = %d; want %d", f1.StartLine, 10)
	}
	if f1.EndLine != 12 {
		t.Errorf("f1 EndLine = %d; want %d", f1.EndLine, 12)
	}
	if f1.RawSeverity != "ERROR" {
		t.Errorf("f1 RawSeverity = %q; want %q", f1.RawSeverity, "ERROR")
	}
	if f1.Confidence != "HIGH" {
		t.Errorf("f1 Confidence = %q; want %q", f1.Confidence, "HIGH")
	}
	if len(f1.CWEs) != 2 {
		t.Errorf("f1 CWEs length = %d; want 2", len(f1.CWEs))
	}
	if f1.CWEs[0] != "CWE-79" || f1.CWEs[1] != "CWE-80" {
		t.Errorf("f1 CWEs = %v; want [CWE-79, CWE-80]", f1.CWEs)
	}
	if f1.Remediation != "Remove the raw string prefix." {
		t.Errorf("f1 Remediation = %q; want %q", f1.Remediation, "Remove the raw string prefix.")
	}
	if f1.Meta["owasp"] != "A7:2017-Cross-Site Scripting (XSS)" {
		t.Errorf("f1 Meta[owasp] = %q; want %q", f1.Meta["owasp"], "A7:2017-Cross-Site Scripting (XSS)")
	}

	// Check second finding (string CWE)
	f2 := findings[1]
	if len(f2.CWEs) != 1 {
		t.Errorf("f2 CWEs length = %d; want 1", len(f2.CWEs))
	}
	if f2.CWEs[0] != "CWE-89" {
		t.Errorf("f2 CWEs[0] = %q; want %q", f2.CWEs[0], "CWE-89")
	}
	if f2.RawSeverity != "CRITICAL" {
		t.Errorf("f2 RawSeverity = %q; want %q", f2.RawSeverity, "CRITICAL")
	}
}

func TestParseGitleaks(t *testing.T) {
	gitleaksJSON := `[
		{
			"Description": "High entropy string detected",
			"File": "config/secrets.yml",
			"StartLine": 5,
			"EndLine": 5,
			"RuleID": "generic-api-key",
			"Match": "key=SUPERSECRETVALUE",
			"Secret": "SUPERSECRETVALUE",
			"Commit": "abc123",
			"Line": "api_key = SUPERSECRETVALUE",
			"Entropy": 4.2
		}
	]`

	findings, err := parseGitleaks([]byte(gitleaksJSON))
	if err != nil {
		t.Fatalf("parseGitleaks error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Tool != "gitleaks" {
		t.Errorf("Tool = %q; want %q", f.Tool, "gitleaks")
	}
	if f.Category != model.CategorySecret {
		t.Errorf("Category = %q; want %q", f.Category, model.CategorySecret)
	}
	if f.RuleID != "generic-api-key" {
		t.Errorf("RuleID = %q; want %q", f.RuleID, "generic-api-key")
	}
	if f.File != "config/secrets.yml" {
		t.Errorf("File = %q; want %q", f.File, "config/secrets.yml")
	}
	if f.StartLine != 5 {
		t.Errorf("StartLine = %d; want %d", f.StartLine, 5)
	}
	if f.EndLine != 5 {
		t.Errorf("EndLine = %d; want %d", f.EndLine, 5)
	}
	if f.RawSeverity != "HIGH" {
		t.Errorf("RawSeverity = %q; want %q", f.RawSeverity, "HIGH")
	}

	// Assert no secret leakage in any field
	payloadStr := string(f.RawPayload)
	metaStr, _ := json.Marshal(f.Meta)
	allData := strings.Join([]string{f.Title, f.Description, payloadStr, string(metaStr)}, "")
	if strings.Contains(allData, "SUPERSECRETVALUE") {
		t.Errorf("finding contains leaked secret 'SUPERSECRETVALUE' in Title/Desc/Payload/Meta")
	}

	// Check specific meta values
	if f.Meta["entropy"] != "4.20" {
		t.Errorf("Meta[entropy] = %q; want %q", f.Meta["entropy"], "4.20")
	}
	if f.Meta["match"] != "key=[REDACTED]" {
		t.Errorf("Meta[match] = %q; want %q", f.Meta["match"], "key=[REDACTED]")
	}
}

func TestParseTrivy(t *testing.T) {
	trivyJSON := `{
		"Results": [
			{
				"Target": "requirements.txt",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2020-14343",
						"Title": "PyYAML Improper Input Validation",
						"Description": "PyYAML before 5.4...",
						"Severity": "CRITICAL",
						"CweIDs": ["CWE-20"],
						"PkgName": "PyYAML",
						"InstalledVersion": "5.3.1",
						"FixedVersion": "5.4",
						"PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2020-14343"
					}
				]
			},
			{
				"Target": "package.json",
				"Vulnerabilities": null
			}
		]
	}`

	findings, err := parseTrivy([]byte(trivyJSON))
	if err != nil {
		t.Fatalf("parseTrivy error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Tool != "trivy" {
		t.Errorf("Tool = %q; want %q", f.Tool, "trivy")
	}
	if f.Category != model.CategorySCA {
		t.Errorf("Category = %q; want %q", f.Category, model.CategorySCA)
	}
	if f.RuleID != "CVE-2020-14343" {
		t.Errorf("RuleID = %q; want %q", f.RuleID, "CVE-2020-14343")
	}
	if f.CVE != "CVE-2020-14343" {
		t.Errorf("CVE = %q; want %q", f.CVE, "CVE-2020-14343")
	}
	if f.Package != "PyYAML@5.3.1" {
		t.Errorf("Package = %q; want %q", f.Package, "PyYAML@5.3.1")
	}
	if f.Remediation != "Upgrade PyYAML to 5.4" {
		t.Errorf("Remediation = %q; want %q", f.Remediation, "Upgrade PyYAML to 5.4")
	}
	if f.RawSeverity != "CRITICAL" {
		t.Errorf("RawSeverity = %q; want %q", f.RawSeverity, "CRITICAL")
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != "CWE-20" {
		t.Errorf("CWEs = %v; want [CWE-20]", f.CWEs)
	}
	if f.Meta["target"] != "requirements.txt" {
		t.Errorf("Meta[target] = %q; want %q", f.Meta["target"], "requirements.txt")
	}
	if f.Meta["primaryURL"] != "https://nvd.nist.gov/vuln/detail/CVE-2020-14343" {
		t.Errorf("Meta[primaryURL] = %q; want %q", f.Meta["primaryURL"], "https://nvd.nist.gov/vuln/detail/CVE-2020-14343")
	}
}

func TestParseGitleaks_EmptyInput(t *testing.T) {
	findings, err := parseGitleaks([]byte(""))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if findings != nil && len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTrivy_NullResults(t *testing.T) {
	trivyJSON := `{"Results": null}`
	findings, err := parseTrivy([]byte(trivyJSON))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if findings != nil && len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
