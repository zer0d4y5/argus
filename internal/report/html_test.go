package report

import (
	"strings"
	"testing"

	"github.com/leaky-hub/appsec/internal/model"
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
