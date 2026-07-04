package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
)

// Gitleaks implements the Adapter interface for the gitleaks secret scanner.
type Gitleaks struct{}

// Name returns the tool name.
func (g *Gitleaks) Name() string {
	return "gitleaks"
}

// Category returns the finding category.
func (g *Gitleaks) Category() string {
	return model.CategorySecret
}

// Available checks if gitleaks is installed on the PATH.
func (g *Gitleaks) Available() bool {
	return toolOnPath("gitleaks")
}

// Scan executes gitleaks and returns normalized raw findings. The JSON
// report goes to a temp file (not /dev/stdout, which gitleaks cannot always
// open) that is removed before returning.
func (g *Gitleaks) Scan(ctx context.Context, target string) ([]model.RawFinding, error) {
	reportFile, err := os.CreateTemp("", "appsec-gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("gitleaks scan: temp report: %w", err)
	}
	reportPath := reportFile.Name()
	reportFile.Close()
	defer os.Remove(reportPath)

	args := []string{
		"detect",
		"--source", target,
		"--no-git",
		"--report-format", "json",
		"--report-path", reportPath,
		"--redact",
		"--exit-code", "0",
	}

	if _, err := runJSON(ctx, "gitleaks", args...); err != nil {
		return nil, fmt.Errorf("gitleaks scan: %w", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("gitleaks scan: read report: %w", err)
	}
	return parseGitleaks(data)
}

// gitleaksResult mirrors the JSON structure returned by gitleaks.
type gitleaksResult struct {
	Description string  `json:"Description"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	RuleID      string  `json:"RuleID"`
	Match       string  `json:"Match"`
	Secret      string  `json:"Secret"`
	Commit      string  `json:"Commit"`
	Line        string  `json:"Line"`
	Entropy     float64 `json:"Entropy"`
}

// parseGitleaks converts raw JSON output into model.RawFinding slices.
func parseGitleaks(data []byte) ([]model.RawFinding, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	var results []gitleaksResult
	if err := json.Unmarshal([]byte(trimmed), &results); err != nil {
		return nil, fmt.Errorf("parse gitleaks json: %w", err)
	}

	findings := make([]model.RawFinding, 0, len(results))
	for _, r := range results {
		// Defense in depth: --redact should already mask the secret in Match,
		// but scrub it ourselves too so a plaintext report can never leak
		// secret material into findings.
		match := r.Match
		if r.Secret != "" {
			match = strings.ReplaceAll(match, r.Secret, "[REDACTED]")
		}

		// Build sanitized payload without Secret or Line to prevent leakage.
		sanitized := map[string]interface{}{
			"Description": r.Description,
			"File":        r.File,
			"StartLine":   r.StartLine,
			"EndLine":     r.EndLine,
			"RuleID":      r.RuleID,
			"Match":       match,
			"Commit":      r.Commit,
			"Entropy":     r.Entropy,
		}
		payloadBytes, err := json.Marshal(sanitized)
		if err != nil {
			// Should not happen with simple types, but handle gracefully.
			continue
		}

		finding := model.RawFinding{
			Tool:        "gitleaks",
			Category:    model.CategorySecret,
			RuleID:      r.RuleID,
			Title:       r.RuleID,
			Description: r.Description,
			RawSeverity: "HIGH",
			File:        r.File,
			StartLine:   r.StartLine,
			EndLine:     r.EndLine,
			Meta: map[string]string{
				"match":   match,
				"entropy": formatEntropy(r.Entropy),
			},
			RawPayload: json.RawMessage(payloadBytes),
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// formatEntropy formats the entropy value to 2 decimal places.
func formatEntropy(e float64) string {
	if e == 0 {
		return "0.00"
	}
	return fmt.Sprintf("%.2f", e)
}
