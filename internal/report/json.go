package report

import (
	"encoding/json"
	"io"

	"github.com/leaky-hub/appsec/internal/model"
)

// WriteJSON writes a JSON report to w containing the provided findings.
func WriteJSON(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(BuildDocument(findings))
}
