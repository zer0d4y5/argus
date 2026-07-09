package prcomment

import (
	"fmt"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// descMaxRunes bounds the description in an inline comment. Titles are
// already capped by model.SanitizeTitle.
const descMaxRunes = 400

// marker renders the invisible idempotency marker for a finding. Empty for a
// finding without a fingerprint: it cannot be deduplicated, so it must not
// emit a marker that could suppress a different finding.
func marker(f model.Finding) string {
	if f.ID == "" {
		return ""
	}
	return "<!-- argus-fp:" + f.ID + " -->"
}

// inlineBody renders one finding as an inline review comment.
//
// SECRET findings are the redaction-sensitive case: the body carries only
// severity, rule identity, and rotation guidance. Tool descriptions and
// remediation strings for secrets can restate matched credential context, so
// they never go out; the comment's placement already says where.
func inlineBody(f model.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**%s**: %s", strings.ToUpper(f.Severity.String()), f.Title)
	if f.RiskScore != nil {
		fmt.Fprintf(&b, " (risk %.1f)", *f.RiskScore)
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "Rule `%s` (%s, %s)", f.RuleID, f.Tool, f.Category)
	if len(f.CWEs) > 0 {
		fmt.Fprintf(&b, ", %s", strings.Join(f.CWEs, ", "))
	}
	if f.CVE != "" {
		fmt.Fprintf(&b, ", %s", f.CVE)
	}
	b.WriteString(".\n")

	if f.Category == model.CategorySecret {
		b.WriteString("\nA credential in a pull request is exposed to everyone who can see the repository, and to CI logs. Rotate it, then remove it from the change (and from history if the branch already pushed).\n")
	} else {
		if desc := strings.TrimSpace(f.Description); desc != "" && desc != f.Title {
			b.WriteString("\n" + truncate(desc, descMaxRunes) + "\n")
		}
		if rem := strings.TrimSpace(f.Remediation); rem != "" {
			b.WriteString("\n**Remediation:** " + truncate(rem, descMaxRunes) + "\n")
		}
	}

	b.WriteString("\n<sub>Posted by [Argus](https://zer0d4y5.github.io/argus/): new since the baseline.</sub>\n")
	if m := marker(f); m != "" {
		b.WriteString(m + "\n")
	}
	return b.String()
}

// summaryBody renders the review's top-level body: the run rollup plus a
// table of the findings that could not be commented inline (no file, line
// outside the PR diff, or past the inline cap). Each listed finding carries
// its marker so re-posts stay idempotent for these too.
func summaryBody(inline int, rest []model.Finding) string {
	total := inline + len(rest)
	var b strings.Builder
	fmt.Fprintf(&b, "## Argus: %d new finding(s) in this pull request\n\n", total)
	if inline > 0 {
		fmt.Fprintf(&b, "%d commented inline on changed lines.\n", inline)
	}
	if len(rest) == 0 {
		return b.String()
	}

	fmt.Fprintf(&b, "%d not on lines this pull request changes (pre-existing lines, cloud resources, or past the %d-comment inline cap):\n\n", len(rest), maxInline)
	b.WriteString("| Severity | Rule | Where | Title |\n|---|---|---|---|\n")
	for i, f := range rest {
		if i == maxSummaryRows {
			fmt.Fprintf(&b, "\nand %d more: see the scan report in the workflow logs.\n", len(rest)-maxSummaryRows)
			break
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n",
			strings.ToUpper(f.Severity.String()), cell(f.RuleID), cell(where(f)), cell(f.Title))
	}
	b.WriteString("\n")
	for _, f := range rest {
		if m := marker(f); m != "" {
			b.WriteString(m + "\n")
		}
	}
	return b.String()
}

// where renders the compact location hint for the summary table.
func where(f model.Finding) string {
	if f.Location.File != "" {
		if f.Location.StartLine > 0 {
			return fmt.Sprintf("%s:%d", f.Location.File, f.Location.StartLine)
		}
		return f.Location.File
	}
	if f.Location.Resource != "" {
		return f.Location.Resource
	}
	return f.Location.URL
}

// cell makes a string safe inside a one-line Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return truncate(s, 120)
}

// truncate caps s at n runes, marking the cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
