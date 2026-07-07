package compliance

import (
	"time"

	"github.com/leaky-hub/argus/internal/model"
)

// SECURITY-CRITICAL BUCKETING: this file decides what the gap report claims.
// The failure mode is overclaiming — a control reading "no violations
// detected" when findings existed, or a finding vanishing from all buckets.
// Invariants (unit-tested):
//   - every assessable control is exactly one of violated | clean;
//   - per framework, mapped + unmapped + out-of-scope findings = total findings;
//   - "clean" is never rendered as "compliant" — it means the scanners could
//     have produced evidence against the control and did not, this run.

// Control status values, verbatim in JSON output.
const (
	StatusViolated = "violated"
	StatusClean    = "clean" // rendered as "no violations detected"
)

// FindingRef is a compact evidence pointer into the run's findings.
type FindingRef struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	RuleID   string `json:"ruleId"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// ControlStatus is one row of a framework's gap table.
type ControlStatus struct {
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Status       string       `json:"status"` // violated | clean
	FindingCount int          `json:"findingCount"`
	TopFindings  []FindingRef `json:"topFindings,omitempty"` // up to maxTopFindings, severity order
}

// maxTopFindings caps the evidence pointers per control; the full set is
// reachable via findingCount + the run's findings.
const maxTopFindings = 3

// FrameworkReport is one framework's complete gap assessment.
type FrameworkReport struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Scope   []string `json:"scope"`

	Controls      []ControlStatus `json:"controls"` // all assessable controls, violated first, then data order
	NotAssessable []NotAssessable `json:"notAssessable"`

	ViolatedControls int `json:"violatedControls"`
	CleanControls    int `json:"cleanControls"`

	// Finding-side reconciliation: MappedFindings + UnmappedFindings +
	// OutOfScopeFindings == the run's total findings, always.
	MappedFindings     int          `json:"mappedFindings"`
	UnmappedFindings   int          `json:"unmappedFindings"`
	OutOfScopeFindings int          `json:"outOfScopeFindings"`
	UnmappedRefs       []FindingRef `json:"unmappedRefs,omitempty"` // every unmapped in-scope finding, listed
}

// Report is the full gap assessment document (`argus comply` JSON output).
type Report struct {
	Tool          string            `json:"tool"`
	SchemaVersion string            `json:"schemaVersion"`
	GeneratedAt   string            `json:"generatedAt"`
	Target        string            `json:"target"`
	Source        string            `json:"source"` // "scan" or the saved-run ID
	TotalFindings int               `json:"totalFindings"`
	Frameworks    []FrameworkReport `json:"frameworks"`
}

// FrameworkSummary is the compact per-framework rollup for the console.
type FrameworkSummary struct {
	ID               string `json:"id"`
	Version          string `json:"version"`
	ViolatedControls int    `json:"violatedControls"`
	CleanControls    int    `json:"cleanControls"`
	NotAssessable    int    `json:"notAssessable"`
	UnmappedFindings int    `json:"unmappedFindings"`
}

func ref(f model.Finding) FindingRef {
	return FindingRef{
		ID:       f.ID,
		Title:    f.Title,
		Severity: f.Severity.String(),
		RuleID:   f.RuleID,
		File:     f.Location.File,
		Line:     f.Location.StartLine,
	}
}

// Assess buckets every finding against every framework. Findings are consumed
// in their given order (the pipeline sorts severity-descending, so per-control
// TopFindings and UnmappedRefs inherit severity order). Findings are read
// only — Assess never mutates them.
func Assess(findings []model.Finding) ([]FrameworkReport, error) {
	fws, err := Frameworks()
	if err != nil {
		return nil, err
	}
	reports := make([]FrameworkReport, 0, len(fws))
	for i := range fws {
		fw := &fws[i]
		rep := FrameworkReport{
			ID:            fw.ID,
			Name:          fw.Name,
			Version:       fw.Version,
			Scope:         fw.Scope,
			NotAssessable: fw.NotAssessable,
		}

		perControl := map[string]*ControlStatus{}
		for _, f := range findings {
			if !fw.inScope(f) {
				rep.OutOfScopeFindings++
				continue
			}
			controls := fw.controlsFor(f)
			if len(controls) == 0 {
				rep.UnmappedFindings++
				rep.UnmappedRefs = append(rep.UnmappedRefs, ref(f))
				continue
			}
			rep.MappedFindings++
			for _, id := range controls {
				cs := perControl[id]
				if cs == nil {
					cs = &ControlStatus{ID: id, Title: fw.controlTitle[id], Status: StatusViolated}
					perControl[id] = cs
				}
				cs.FindingCount++
				if len(cs.TopFindings) < maxTopFindings {
					cs.TopFindings = append(cs.TopFindings, ref(f))
				}
			}
		}

		// Every assessable control lands in exactly one bucket: violated rows
		// first (data order), then clean rows (data order). Data order within
		// a framework file is the framework's own control order.
		for _, c := range fw.Controls {
			if cs, ok := perControl[c.ID]; ok {
				rep.Controls = append(rep.Controls, *cs)
				rep.ViolatedControls++
			}
		}
		for _, c := range fw.Controls {
			if _, ok := perControl[c.ID]; !ok {
				rep.Controls = append(rep.Controls, ControlStatus{ID: c.ID, Title: c.Title, Status: StatusClean})
				rep.CleanControls++
			}
		}
		reports = append(reports, rep)
	}
	return reports, nil
}

// BuildReport assembles the full comply document around Assess.
func BuildReport(findings []model.Finding, target, source string, now time.Time) (Report, error) {
	fwReports, err := Assess(findings)
	if err != nil {
		return Report{}, err
	}
	return Report{
		Tool:          "appsec",
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Target:        target,
		Source:        source,
		TotalFindings: len(findings),
		Frameworks:    fwReports,
	}, nil
}

// Summarize is the compact rollup for the console's compliance panel.
func Summarize(findings []model.Finding) ([]FrameworkSummary, error) {
	reports, err := Assess(findings)
	if err != nil {
		return nil, err
	}
	out := make([]FrameworkSummary, 0, len(reports))
	for _, r := range reports {
		out = append(out, FrameworkSummary{
			ID:               r.ID,
			Version:          r.Version,
			ViolatedControls: r.ViolatedControls,
			CleanControls:    r.CleanControls,
			NotAssessable:    len(r.NotAssessable),
			UnmappedFindings: r.UnmappedFindings,
		})
	}
	return out, nil
}
