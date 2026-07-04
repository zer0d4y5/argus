package report

import (
	"encoding/json"
	"io"

	"github.com/leaky-hub/appsec/internal/model"
)

// WriteJSON writes a JSON report to w containing the provided findings.
func WriteJSON(w io.Writer, findings []model.Finding) error {
	model.Sort(findings)

	summary := model.Summarize(findings)

	out := struct {
		Tool          string          `json:"tool"`
		Version       string          `json:"version"`
		SchemaVersion string          `json:"schemaVersion"`
		Summary       model.Summary   `json:"summary"`
		Findings      []model.Finding `json:"findings"`
	}{
		Tool:          "appsec",
		Version:       "0.1.0",
		SchemaVersion: model.SchemaVersion,
		Summary:       summary,
		Findings:      findings,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
