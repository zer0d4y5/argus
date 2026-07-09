package prcomment

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func sastFinding(id string) model.Finding {
	score := 7.4
	return model.Finding{
		ID:          id,
		Tool:        "semgrep",
		Category:    model.CategorySAST,
		RuleID:      "go.sql-string-concat",
		Title:       "SQL query built from string concatenation",
		Description: "Tainted data reaches a SQL string.",
		Remediation: "Use parameterized queries.",
		Severity:    model.SeverityHigh,
		RiskScore:   &score,
		CWEs:        []string{"CWE-89"},
		Location:    model.Location{File: "app/db.go", StartLine: 12},
	}
}

func TestInlineBody(t *testing.T) {
	body := inlineBody(sastFinding("0123456789abcdef0123456789abcdef"))
	for _, want := range []string{
		"**HIGH**", "SQL query built from string concatenation", "risk 7.4",
		"`go.sql-string-concat`", "semgrep", "CWE-89",
		"Tainted data reaches a SQL string.",
		"**Remediation:** Use parameterized queries.",
		"<!-- argus-fp:0123456789abcdef0123456789abcdef -->",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("inline body missing %q:\n%s", want, body)
		}
	}
}

// TestInlineBodySecretRedaction pins the SECRET rule: rule identity and
// rotation guidance go out; the tool's description and remediation strings,
// which can restate matched credential context, never do.
func TestInlineBodySecretRedaction(t *testing.T) {
	f := sastFinding("00000000000000000000000000000000")
	f.Category = model.CategorySecret
	f.Tool = "gitleaks"
	f.RuleID = "aws-access-key"
	f.Title = "AWS access key"
	f.Description = "context around AKIAIOSFODNN7EXAMPLE leaked"
	f.Remediation = "remove AKIAIOSFODNN7EXAMPLE from the file"
	body := inlineBody(f)
	if strings.Contains(body, "AKIA") {
		t.Fatalf("secret context leaked into the comment:\n%s", body)
	}
	for _, want := range []string{"**HIGH**", "`aws-access-key`", "Rotate it"} {
		if !strings.Contains(body, want) {
			t.Errorf("secret body missing %q:\n%s", want, body)
		}
	}
}

// TestInlineBodyNoMarkerWithoutID: an unfingerprinted finding must not emit
// a marker that could suppress a different finding on a later run.
func TestInlineBodyNoMarkerWithoutID(t *testing.T) {
	f := sastFinding("")
	if body := inlineBody(f); strings.Contains(body, "argus-fp") {
		t.Errorf("empty-ID finding emitted a marker:\n%s", body)
	}
}

func TestSummaryBody(t *testing.T) {
	var rest []model.Finding
	for i := 0; i < maxSummaryRows+5; i++ {
		f := sastFinding(fmt.Sprintf("%032x", i+1))
		f.Title = fmt.Sprintf("Finding number %d | with a pipe", i)
		rest = append(rest, f)
	}
	body := summaryBody(2, rest)

	if !strings.Contains(body, fmt.Sprintf("%d new finding(s)", maxSummaryRows+7)) {
		t.Errorf("summary total wrong:\n%s", body)
	}
	if !strings.Contains(body, "2 commented inline") {
		t.Errorf("summary missing inline count:\n%s", body)
	}
	if !strings.Contains(body, "and 5 more") {
		t.Errorf("summary missing overflow note:\n%s", body)
	}
	if got := strings.Count(body, "| HIGH |"); got != maxSummaryRows {
		t.Errorf("summary table rows = %d, want %d", got, maxSummaryRows)
	}
	// Every listed finding keeps its idempotency marker, including past the
	// visible table cap, and pipes in titles never break the table.
	if got := strings.Count(body, "argus-fp:"); got != len(rest) {
		t.Errorf("summary markers = %d, want %d", got, len(rest))
	}
	if strings.Contains(body, "number 0 | with") {
		t.Errorf("unescaped pipe in a table cell:\n%s", body)
	}
}

func TestSummaryBodyAllInline(t *testing.T) {
	body := summaryBody(3, nil)
	if strings.Contains(body, "|---|") {
		t.Errorf("all-inline summary should have no table:\n%s", body)
	}
	if !strings.Contains(body, "3 new finding(s)") || !strings.Contains(body, "3 commented inline") {
		t.Errorf("all-inline summary wrong:\n%s", body)
	}
}

func TestWhere(t *testing.T) {
	f := sastFinding("")
	if got := where(f); got != "app/db.go:12" {
		t.Errorf("where = %q", got)
	}
	f.Location = model.Location{Resource: "arn:aws:s3:::bucket"}
	if got := where(f); got != "arn:aws:s3:::bucket" {
		t.Errorf("where(resource) = %q", got)
	}
	f.Location = model.Location{URL: "https://app.example/login"}
	if got := where(f); got != "https://app.example/login" {
		t.Errorf("where(url) = %q", got)
	}
}
