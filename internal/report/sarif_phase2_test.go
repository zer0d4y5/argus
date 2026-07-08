package report

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

// TestSARIFPhase2Properties pins the Phase 2 enrichment contract: riskScore
// and triage verdict/rationale ride in result properties, and
// security-severity stays severity-derived (GitHub bucketing must never move
// on LLM output).
func TestSARIFPhase2Properties(t *testing.T) {
	score := 8.4
	fpScore := 1.0
	findings := []model.Finding{
		{
			ID: "aaaa", Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "rule-sqli", Title: "SQLi", Severity: model.SeverityHigh,
			Location:  model.Location{File: "app.py", StartLine: 17, EndLine: 17},
			RiskScore: &score,
			Triage: &model.Triage{
				Verdict: model.VerdictTruePositive, Confidence: 0.9,
				Rationale: "User input reaches the query.", Model: "ollama/test",
			},
		},
		{
			ID: "bbbb", Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "rule-shell", Title: "shell=True", Severity: model.SeverityMedium,
			Location:  model.Location{File: "safe.py", StartLine: 3, EndLine: 3},
			RiskScore: &fpScore,
			Triage:    &model.Triage{Verdict: model.VerdictFalsePositive, Confidence: 1.0, Rationale: "Constant string.", Model: "ollama/test"},
		},
		{
			ID: "cccc", Tool: "trivy", Tools: []string{"trivy"}, Category: model.CategorySCA,
			RuleID: "CVE-1", Title: "dep", Severity: model.SeverityLow,
			// untriaged, unscored: properties must simply omit the fields
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]any `json:"properties"`
			} `json:"results"`
			Tool struct {
				Driver struct {
					Rules []struct {
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	results := doc.Runs[0].Results

	if got := results[0].Properties["riskScore"]; got != 8.4 {
		t.Errorf("riskScore = %v, want 8.4", got)
	}
	if got := results[0].Properties["triageVerdict"]; got != model.VerdictTruePositive {
		t.Errorf("triageVerdict = %v", got)
	}
	if got := results[1].Properties["triageRationale"]; got != "Constant string." {
		t.Errorf("triageRationale = %v", got)
	}
	for _, key := range []string{"riskScore", "triageVerdict", "triageRationale"} {
		if _, ok := results[2].Properties[key]; ok {
			t.Errorf("unenriched finding must omit %s", key)
		}
	}

	// The FP verdict lowered riskScore to 1.0, but the rule's
	// security-severity must still reflect medium severity (5.5).
	if got := doc.Runs[0].Tool.Driver.Rules[1].Properties.SecuritySeverity; got != "5.5" {
		t.Errorf("security-severity moved on LLM output: %v", got)
	}

	if dump := os.Getenv("APPSEC_SARIF_DUMP"); dump != "" {
		if err := os.WriteFile(dump, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
