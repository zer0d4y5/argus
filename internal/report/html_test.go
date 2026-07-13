package report

import (
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func riskPtr(f float64) *float64 { return &f }

func TestWriteHTMLEscapesAndStructures(t *testing.T) {
	findings := []model.Finding{
		{
			Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: "xss", Title: `SQLi <script>alert(1)</script>`, Severity: model.SeverityCritical,
			Location:           model.Location{File: "app/db.py", StartLine: 42},
			Description:        "Untrusted input in query",
			Remediation:        "Use parameterized queries",
			RiskScore:          riskPtr(9.5),
			CWEs:               []string{"CWE-89"},
			ComplianceControls: []string{"ASVS:V5.3.4"},
			ID:                 "fp-crit",
		},
		{
			Tool: "gitleaks", Category: model.CategorySecret, RuleID: "aws",
			Title: "AWS key", Severity: model.SeverityLow, ID: "fp-low",
			Location: model.Location{File: "config.env", StartLine: 1},
		},
	}
	var sb strings.Builder
	err := WriteHTML(&sb, findings, HTMLMeta{
		Target: "acme/app", RunID: "2026-07-06", GeneratedAt: "2026-07-06 12:00",
		GateThreshold: "high", GateFailed: true, GateSuppressed: 1,
		Dispositions: map[string]string{"fp-low": "accepted-risk"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := sb.String()

	// XSS safety: the script tag from the finding title must be escaped, never
	// emitted as live markup.
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("finding title was not HTML-escaped — report is XSS-vulnerable")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected the escaped title in the output")
	}

	// Structure: branding, both findings, gate, disposition badge, compliance.
	for _, want := range []string{
		"Argus", "Application Security Report", "acme/app",
		"Untrusted input in query", "Use parameterized queries",
		"AWS key", "Accepted risk", "FAIL", "1 accepted", "ASVS:V5.3.4", "CWE-89",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// Self-contained: no asset actually fetched from the network (the SVG
	// xmlns namespace URI is not a fetch, so we check loading attributes).
	for _, bad := range []string{`src="http`, `src="//`, `href="http`, "@import", "url(http"} {
		if strings.Contains(out, bad) {
			t.Errorf("report loads external asset %q — not self-contained", bad)
		}
	}
}

// TestWriteHTMLProof: a confirmed dynamic finding renders its reproduction and
// bounded-confirmation proof, and hostile content in those fields is escaped.
func TestWriteHTMLProof(t *testing.T) {
	findings := []model.Finding{{
		Tool: "argus-cmdi", Category: model.CategoryDAST, RuleID: "cmdi",
		Title: "OS Command Injection", Severity: model.SeverityCritical, ID: "dast-1",
		Location: model.Location{URL: "http://t/exec"},
		CWEs:     []string{"CWE-78"},
		Proof: &model.Proof{
			Curl:      `curl -sS -X POST 'http://t/exec' --data 'ip=1;id'`,
			Rationale: "A benign probe ran <b>id</b> on the host.",
			Observed:  "uid=33(www-data)",
			Impact: &model.ImpactProof{
				Kind: "cmd-id", Command: "id",
				Summary: "uid=33(www-data) gid=33(www-data)",
			},
		},
	}}
	var sb strings.Builder
	if err := WriteHTML(&sb, findings, HTMLMeta{}); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"Proof of concept", "Reproduce", "curl -sS -X POST", "Observed",
		"Bounded confirmation (cmd-id)", "uid=33(www-data)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("proof report missing %q", want)
		}
	}
	// Hostile content in a proof field must be escaped, never live markup.
	if strings.Contains(out, "<b>id</b>") {
		t.Error("proof rationale was not HTML-escaped")
	}
}

func TestWriteHTMLEmpty(t *testing.T) {
	var sb strings.Builder
	if err := WriteHTML(&sb, nil, HTMLMeta{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "No findings") {
		t.Error("empty report should state no findings")
	}
}

// TestWriteHTMLWorkItems: the tickets and threat-model sections render when the
// meta carries them, and their hostile text is escaped.
func TestWriteHTMLWorkItems(t *testing.T) {
	var buf strings.Builder
	meta := HTMLMeta{
		Tickets: []TicketReport{{ID: "tk-1", Title: "<b>SQLi</b>", Status: "open", Priority: "high", MaxSeverity: "critical", LinkCount: 2}},
		ThreatModels: []ThreatModelReport{{Name: "Checkout", Components: 1, Threats: []ThreatReportRow{
			{Category: "spoofing", Title: "Session hijack", Status: "open", Mitigation: "auth-session"},
		}}},
	}
	if err := WriteHTML(&buf, nil, meta); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Tickets", "tk-1", "critical", "Threat models", "Checkout", "spoofing", "auth-session"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(out, "<b>SQLi</b>") {
		t.Error("ticket title not escaped")
	}
}
