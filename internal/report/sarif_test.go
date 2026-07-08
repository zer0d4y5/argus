package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func sampleFindings() []model.Finding {
	return []model.Finding{
		{
			ID: "abc123", Tool: "semgrep", Tools: []string{"semgrep"},
			Category: model.CategorySAST, RuleID: "python.sqli",
			Title: "SQL injection", Description: "user input in query",
			Severity: model.SeverityHigh, CWEs: []string{"CWE-89"},
			Location: model.Location{File: "./app.py", StartLine: 18, EndLine: 18},
		},
		{
			ID: "def456", Tool: "trivy", Tools: []string{"trivy"},
			Category: model.CategorySCA, RuleID: "CVE-2020-14343",
			Title: "PyYAML deserialization", Severity: model.SeverityCritical,
			CVE: "CVE-2020-14343", Package: "PyYAML@5.3.1",
			Meta: map[string]string{"target": "requirements.txt"},
		},
		{
			ID: "ghi789", Tool: "gitleaks", Tools: []string{"gitleaks"},
			Category: model.CategorySecret, RuleID: "aws-access-key-id",
			Severity: model.SeverityHigh, // no title/description on purpose
			Location: model.Location{File: "config.env", StartLine: 3},
		},
	}
}

func writeSARIF(t *testing.T, findings []model.Finding) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return doc
}

func TestSARIFEveryFindingBecomesAResult(t *testing.T) {
	findings := sampleFindings()
	doc := writeSARIF(t, findings)
	runs := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != len(findings) {
		t.Fatalf("results = %d, want %d — SARIF must never drop findings", len(results), len(findings))
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
}

func TestSARIFResultInvariants(t *testing.T) {
	doc := writeSARIF(t, sampleFindings())
	run := doc["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)

	for _, r := range run["results"].([]any) {
		res := r.(map[string]any)
		// message.text must be non-empty (schema requirement).
		msg := res["message"].(map[string]any)["text"].(string)
		if strings.TrimSpace(msg) == "" {
			t.Error("empty message.text")
		}
		// ruleIndex must point at the matching rule.
		idx := int(res["ruleIndex"].(float64))
		if idx < 0 || idx >= len(rules) {
			t.Fatalf("ruleIndex %d out of range", idx)
		}
		if rules[idx].(map[string]any)["id"] != res["ruleId"] {
			t.Error("ruleIndex does not match ruleId")
		}
		// fingerprint present.
		fp := res["partialFingerprints"].(map[string]any)
		if fp["appsec/fingerprint/v1"] == "" {
			t.Error("missing fingerprint")
		}
		// locations, when present, need clean relative URIs and startLine >= 1.
		if locs, ok := res["locations"].([]any); ok {
			pl := locs[0].(map[string]any)["physicalLocation"].(map[string]any)
			uri := pl["artifactLocation"].(map[string]any)["uri"].(string)
			if strings.HasPrefix(uri, "./") || strings.Contains(uri, "\\") {
				t.Errorf("bad uri %q", uri)
			}
			if region, ok := pl["region"].(map[string]any); ok {
				if region["startLine"].(float64) < 1 {
					t.Errorf("region.startLine < 1 in %q", uri)
				}
			}
		}
	}
}

func TestSARIFSCAFallsBackToManifestLocation(t *testing.T) {
	doc := writeSARIF(t, sampleFindings())
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	for _, r := range results {
		res := r.(map[string]any)
		if res["ruleId"] != "CVE-2020-14343" {
			continue
		}
		locs := res["locations"].([]any)
		pl := locs[0].(map[string]any)["physicalLocation"].(map[string]any)
		uri := pl["artifactLocation"].(map[string]any)["uri"].(string)
		if uri != "requirements.txt" {
			t.Errorf("SCA uri = %q, want requirements.txt (Meta[target] fallback)", uri)
		}
		if _, hasRegion := pl["region"]; hasRegion {
			t.Error("manifest fallback must not invent a line region")
		}
		return
	}
	t.Fatal("SCA finding not found in results")
}

// TestSARIFCloudFallsBackToResource: a CLOUD finding has no source file; its
// resource UID/ARN fills the artifactLocation URI, with no invented line
// region (schema 2.1.0 decision).
func TestSARIFCloudFallsBackToResource(t *testing.T) {
	cloud := model.Finding{
		ID: "c1", Tool: "prowler", Tools: []string{"prowler"},
		Category: model.CategoryCloud, RuleID: "s3_bucket_public_access",
		Title: "S3 bucket allows public access", Severity: model.SeverityHigh,
		Location: model.Location{Resource: "arn:aws:s3:::data-exports"},
	}
	doc := writeSARIF(t, []model.Finding{cloud})
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	res := results[0].(map[string]any)
	locs, ok := res["locations"].([]any)
	if !ok || len(locs) == 0 {
		t.Fatal("cloud finding must carry a location (resource fallback), not a run-level result")
	}
	pl := locs[0].(map[string]any)["physicalLocation"].(map[string]any)
	uri := pl["artifactLocation"].(map[string]any)["uri"].(string)
	if uri != "arn:aws:s3:::data-exports" {
		t.Errorf("cloud uri = %q, want the resource ARN", uri)
	}
	if _, hasRegion := pl["region"]; hasRegion {
		t.Error("cloud finding has no line — must not invent a region")
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		sev   model.Severity
		level string
		score string
	}{
		{model.SeverityCritical, "error", "9.5"},
		{model.SeverityHigh, "error", "8.0"},
		{model.SeverityMedium, "warning", "5.5"},
		{model.SeverityLow, "note", "3.0"},
		{model.SeverityInfo, "note", "1.0"},
	}
	for _, tt := range tests {
		if got := sarifLevel(tt.sev); got != tt.level {
			t.Errorf("sarifLevel(%v) = %q, want %q", tt.sev, got, tt.level)
		}
		if got := securitySeverityScore(tt.sev); got != tt.score {
			t.Errorf("securitySeverityScore(%v) = %q, want %q", tt.sev, got, tt.score)
		}
	}
}

func TestSARIFEmptyFindings(t *testing.T) {
	doc := writeSARIF(t, nil)
	run := doc["runs"].([]any)[0].(map[string]any)
	if results := run["results"].([]any); len(results) != 0 {
		t.Errorf("expected empty results array, got %d", len(results))
	}
	// results must be [] not null: GitHub rejects null.
	var buf bytes.Buffer
	_ = WriteSARIF(&buf, nil)
	if strings.Contains(buf.String(), `"results": null`) {
		t.Error("results must serialize as [], not null")
	}
}

// TestSARIFToolSeverityProperty: schema 2.0.0 — banded severity drives
// level/security-severity, and the tool-normalized value is preserved as
// properties.toolSeverity for audit. Absent toolSeverity (old documents)
// must not fabricate the property.
func TestSARIFToolSeverityProperty(t *testing.T) {
	high := model.SeverityHigh
	findings := []model.Finding{
		{ID: "a", Tool: "gitleaks", Category: model.CategorySecret,
			RuleID: "aws-access-token", Title: "AWS access key",
			Severity: model.SeverityMedium, ToolSeverity: &high,
			Location: model.Location{File: "testdata/creds.env", StartLine: 1}},
		{ID: "b", Tool: "semgrep", Category: model.CategorySAST,
			RuleID: "r.x", Title: "X", Severity: model.SeverityLow},
	}
	doc := writeSARIF(t, findings)
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)

	p0 := results[0].(map[string]any)["properties"].(map[string]any)
	if p0["severity"] != "medium" || p0["toolSeverity"] != "high" {
		t.Errorf("banded+tool severity = %v / %v, want medium / high", p0["severity"], p0["toolSeverity"])
	}
	// Level follows the BANDED severity, not the tool's.
	if lvl := results[0].(map[string]any)["level"]; lvl != "warning" {
		t.Errorf("level = %v, want warning (banded medium)", lvl)
	}
	p1 := results[1].(map[string]any)["properties"].(map[string]any)
	if _, present := p1["toolSeverity"]; present {
		t.Error("nil toolSeverity must be omitted, never fabricated")
	}
}
