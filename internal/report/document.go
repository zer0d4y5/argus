package report

import (
	"github.com/zer0d4y5/argus/internal/coverage"
	"github.com/zer0d4y5/argus/internal/model"
)

// Document is the canonical JSON report shape. It is what `WriteJSON` emits and
// what `--save` persists as a run file, so the run store and every reader can
// decode the exact structure the scanner produces (no drift between writer and
// reader). Fields mirror the schema documented in docs/findings-model.md.
type Document struct {
	Tool          string          `json:"tool"`
	Version       string          `json:"version"`
	SchemaVersion string          `json:"schemaVersion"`
	Summary       model.Summary   `json:"summary"`
	Findings      []model.Finding `json:"findings"`
	// Coverage is the skip accounting for the scanned tree (schema 2.0.0):
	// what was analyzable and what was NOT scanned (binaries, oversize files,
	// unsupported languages). Set on the save path only, like snippets —
	// stdout reports are unchanged. Absent in older documents and in
	// non-saved output; readers feature-detect.
	Coverage *coverage.Accounting `json:"coverage,omitempty"`
	// ToolVersions records external scanner provenance for the run (e.g.
	// {"prowler": "Prowler 5.31.0"}): which tool version produced the raw
	// findings, for auditability. Absent when not captured.
	ToolVersions map[string]string `json:"toolVersions,omitempty"`
}

// BuildDocument assembles a Document from findings. It sorts findings
// deterministically (via model.Sort inside Summarize's caller path) and
// computes the summary rollup, so callers get a report identical to WriteJSON's.
func BuildDocument(findings []model.Finding) Document {
	model.Sort(findings)
	return Document{
		Tool:          toolName,
		Version:       toolVersion,
		SchemaVersion: model.SchemaVersion,
		Summary:       model.Summarize(findings),
		Findings:      findings,
	}
}
