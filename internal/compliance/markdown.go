package compliance

import (
	"fmt"
	"io"
	"strings"
)

// errWriter collapses the per-line error checks: the first write error sticks
// and every later printf becomes a no-op.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...interface{}) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

// mdCell neutralizes hostile finding text (titles, files, rule IDs originate
// in scanned code) for Markdown table cells and bullets: no pipes, no
// newlines, bounded length. Truncation is rune-safe.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if r := []rune(s); len(r) > 160 {
		return string(r[:160]) + "…"
	}
	return s
}

// evidence renders one finding reference as "`file:line` title".
func evidence(f FindingRef) string {
	loc := ""
	if f.File != "" {
		loc = mdCell(f.File)
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Line)
		}
		loc = "`" + loc + "` "
	}
	label := f.Title
	if label == "" {
		label = f.RuleID
	}
	return loc + mdCell(label)
}

// WriteMarkdown renders the gap assessment as GitHub-flavored Markdown — the
// auditor-shaped artifact. Section order per framework: violated, clean
// ("no violations detected"), not assessable, unmapped findings.
func WriteMarkdown(w io.Writer, r Report) error {
	ew := &errWriter{w: w}

	ew.printf("# Compliance Gap Assessment\n\n")
	ew.printf("Generated %s by %s (schema %s) — target `%s`, source `%s`, %d findings.\n\n",
		r.GeneratedAt, r.Tool, r.SchemaVersion, mdCell(r.Target), mdCell(r.Source), r.TotalFindings)
	ew.printf("> **Scope**: this report is evidence from static scanning only (SAST, secrets, dependencies, IaC). A control with no violations detected is not certified compliant; controls listed as not assessable require process, runtime, or physical evidence this platform cannot collect.\n\n")

	for _, fw := range r.Frameworks {
		ew.printf("## %s — %s v%s\n\n", fw.ID, fw.Name, fw.Version)
		ew.printf("**%d** controls violated · **%d** with no violations detected · **%d** areas not assessable · %d findings mapped, %d unmapped, %d out of scope.\n\n",
			fw.ViolatedControls, fw.CleanControls, len(fw.NotAssessable),
			fw.MappedFindings, fw.UnmappedFindings, fw.OutOfScopeFindings)

		if fw.ViolatedControls > 0 {
			ew.printf("### Violated controls\n\n")
			ew.printf("| Control | Requirement | Findings | Top evidence |\n")
			ew.printf("| --- | --- | --- | --- |\n")
			for _, c := range fw.Controls {
				if c.Status != StatusViolated {
					continue
				}
				parts := make([]string, 0, len(c.TopFindings))
				for _, f := range c.TopFindings {
					parts = append(parts, evidence(f))
				}
				ew.printf("| %s | %s | %d | %s |\n",
					mdCell(c.ID), mdCell(c.Title), c.FindingCount, strings.Join(parts, "<br>"))
			}
			ew.printf("\n")
		}

		if fw.CleanControls > 0 {
			ew.printf("### No violations detected\n\n")
			for _, c := range fw.Controls {
				if c.Status != StatusClean {
					continue
				}
				ew.printf("- **%s** — %s\n", mdCell(c.ID), mdCell(c.Title))
			}
			ew.printf("\n")
		}

		if len(fw.NotAssessable) > 0 {
			ew.printf("### Not assessable by static scanning\n\n")
			ew.printf("| Area | Title | Why |\n")
			ew.printf("| --- | --- | --- |\n")
			for _, na := range fw.NotAssessable {
				ew.printf("| %s | %s | %s |\n", mdCell(na.ID), mdCell(na.Title), mdCell(na.Reason))
			}
			ew.printf("\n")
		}

		if fw.UnmappedFindings > 0 {
			ew.printf("### Unmapped findings\n\n")
			ew.printf("The following in-scope findings match no curated mapping for this framework. They are listed here rather than dropped:\n\n")
			for _, f := range fw.UnmappedRefs {
				loc := ""
				if f.File != "" {
					loc = " (`" + mdCell(f.File)
					if f.Line > 0 {
						loc += fmt.Sprintf(":%d", f.Line)
					}
					loc += "`)"
				}
				ew.printf("- %s `%s` %s%s\n", mdCell(f.Severity), mdCell(f.RuleID), mdCell(f.Title), loc)
			}
			ew.printf("\n")
		}
	}

	return ew.err
}
