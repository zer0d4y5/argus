package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

func WriteMarkdown(w io.Writer, findings []model.Finding) error {
	model.Sort(findings)
	summary := model.Summarize(findings)

	// Heading
	if _, err := fmt.Fprintln(w, "# AppSec Scan Report"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}

	// Summary Table
	if _, err := fmt.Fprintln(w, "| Severity | Count |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "|---|---|"); err != nil {
		return err
	}

	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}

	for _, sev := range severities {
		name := sev.String()
		count := summary.BySeverity[name]
		if _, err := fmt.Fprintf(w, "| %s | %d |\n", name, count); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "| Total | %d |\n", summary.Total); err != nil {
		return err
	}

	// Findings Section
	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "## Findings"); err != nil {
		return err
	}

	if len(findings) == 0 {
		if _, err := fmt.Fprintln(w, ""); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "No findings."); err != nil {
			return err
		}
		return nil
	}

	// Group by severity
	groups := make(map[model.Severity][]model.Finding)
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}

	for _, sev := range severities {
		flist, exists := groups[sev]
		if !exists || len(flist) == 0 {
			continue
		}

		title := capitalize(sev.String()) // "Critical", "High", etc.
		if _, err := fmt.Fprintf(w, "\n### %s (%d)\n\n", title, len(flist)); err != nil {
			return err
		}

		if _, err := fmt.Fprintln(w, "| Title | Tool | Category | Location | Risk | Verdict | CWE/CVE | Remediation |"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|"); err != nil {
			return err
		}

		for _, f := range flist {
			titleCell := truncate(escapePipe(f.Title), 120)
			toolCell := escapePipe(strings.Join(f.Tools, ", "))
			if toolCell == "" {
				toolCell = escapePipe(f.Tool)
			}
			catCell := escapePipe(f.Category)
			locCell := escapePipe(formatLocation(f))

			var riskCell string
			if f.RiskScore != nil {
				riskCell = fmt.Sprintf("%.1f", *f.RiskScore)
			} else {
				riskCell = "-"
			}

			var verdictCell string
			if f.Triage != nil && f.Triage.Verdict != "" {
				verdictCell = escapePipe(f.Triage.Verdict)
			} else {
				verdictCell = "-"
			}

			cweCveCell := escapePipe(formatCWECVE(f))
			remCell := truncate(escapePipe(f.Remediation), 120)

			if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				titleCell, toolCell, catCell, locCell, riskCell, verdictCell, cweCveCell, remCell); err != nil {
				return err
			}
		}
	}

	return nil
}

func formatLocation(f model.Finding) string {
	file := f.Location.File
	if file != "" && f.Location.StartLine > 0 {
		file = fmt.Sprintf("%s:%d", file, f.Location.StartLine)
	}
	switch {
	case f.Package != "" && file != "":
		return fmt.Sprintf("%s (%s)", f.Package, file)
	case f.Package != "":
		return f.Package
	case file != "":
		return file
	case f.Location.Resource != "":
		return f.Location.Resource
	case f.Location.URL != "":
		return f.Location.URL
	}
	return "-"
}

func formatCWECVE(f model.Finding) string {
	var parts []string
	if len(f.CWEs) > 0 {
		parts = append(parts, strings.Join(f.CWEs, ", "))
	}
	if f.CVE != "" {
		parts = append(parts, f.CVE)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func escapePipe(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "..."
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
