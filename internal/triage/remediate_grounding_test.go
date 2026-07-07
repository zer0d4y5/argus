package triage

import (
	"strings"
	"testing"

	"github.com/leaky-hub/argus/internal/model"
)

// TestRemediatePromptGroundsCodeFindings: a code finding whose CWE maps to the
// mitigation library gets the curated secure pattern injected as trusted
// reference; a cloud finding (no code weakness) does not.
func TestRemediatePromptGroundsCodeFindings(t *testing.T) {
	sast := model.Finding{
		Category: model.CategorySAST, RuleID: "sqli", Title: "SQL injection",
		Severity: model.SeverityHigh, CWEs: []string{"CWE-89"},
		Location: model.Location{File: "app/db.py", StartLine: 10, EndLine: 10},
	}
	p := buildRemediatePrompt(sast, "NONCE")
	if !strings.Contains(p, "SECURE PATTERN") {
		t.Error("code finding prompt should inject the curated secure pattern")
	}
	if !strings.Contains(p, "SQL Injection") || !strings.Contains(p, "parameterized") {
		t.Error("secure pattern should carry the SQLi principle/snippet")
	}

	// Unmapped CWE → no grounding section.
	unmapped := sast
	unmapped.CWEs = []string{"CWE-1004"}
	if strings.Contains(buildRemediatePrompt(unmapped, "NONCE"), "SECURE PATTERN") {
		t.Error("an unmapped CWE must not inject a secure pattern")
	}

	// Cloud finding → no code grounding.
	cloud := model.Finding{
		Category: model.CategoryCloud, RuleID: "sg-open", Title: "SG open",
		Severity: model.SeverityHigh, CWEs: []string{"CWE-89"},
		Location: model.Location{Resource: "arn:aws:..."},
	}
	if strings.Contains(buildRemediatePrompt(cloud, "NONCE"), "SECURE PATTERN") {
		t.Error("cloud finding must not get the code secure-pattern section")
	}
}
