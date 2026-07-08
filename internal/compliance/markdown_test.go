package compliance

import (
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
)

// The renderer must emit every section and neutralize hostile finding text.
func TestWriteMarkdown(t *testing.T) {
	findings := mixedFindings()
	// Hostile title: pipes break tables, newlines break rows.
	findings[0].Title = "SQL injection | `rm -rf` \n # fake heading"
	findings[0].Location = model.Location{File: "app|main.go", StartLine: 42}

	rep, err := BuildReport(findings, "/repo", "scan", time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	var sb strings.Builder
	if err := WriteMarkdown(&sb, rep); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := sb.String()

	for _, want := range []string{
		"# Compliance Gap Assessment",
		"## ASVS — OWASP Application Security Verification Standard v4.0.3",
		"## PCI-DSS — PCI Data Security Standard v4.0",
		"### Violated controls",
		"### No violations detected",
		"### Not assessable by static scanning",
		"### Unmapped findings",
		"V5.3.4",
		"evidence from static scanning only",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}

	if strings.Contains(out, "SQL injection | `rm") {
		t.Error("unescaped pipe from hostile title reached a table cell")
	}
	if !strings.Contains(out, "app\\|main.go") {
		t.Error("hostile file path not escaped")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "# fake heading") {
			t.Error("hostile newline injected a heading")
		}
	}
}

// mdCell truncation must be rune-safe.
func TestMdCellRuneSafe(t *testing.T) {
	s := strings.Repeat("é", 200)
	got := mdCell(s)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("expected truncation marker")
	}
	if want := strings.Repeat("é", 160) + "…"; got != want {
		t.Errorf("rune-unsafe truncation")
	}
}
