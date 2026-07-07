package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leaky-hub/argus/internal/model"
)

// Semgrep implements the Adapter interface for the semgrep CLI (SAST).
//
// Rulesets is the curated registry pack list to run (resolved from the active
// profile or a config override; see profiles.go). Empty falls back to p/ci so
// the adapter is always safe to construct directly.
type Semgrep struct {
	Rulesets []string
}

func (s *Semgrep) Name() string     { return "semgrep" }
func (s *Semgrep) Category() string { return model.CategorySAST }
func (s *Semgrep) Available() bool  { return toolOnPath("semgrep") }

// Scan executes semgrep against the target and returns raw findings. Each
// ruleset pack is passed as a separate --config flag (semgrep unions them). An
// explicit config (unlike --config auto) works with metrics disabled.
func (s *Semgrep) Scan(ctx context.Context, target string) ([]model.RawFinding, error) {
	packs := s.Rulesets
	if len(packs) == 0 {
		// p/ci is semgrep's curated low-false-positive security ruleset — a
		// safe default if the adapter is built without a resolved profile.
		packs = []string{"p/ci"}
	}
	args := []string{
		"--json",
		"--quiet",
		"--metrics=off",
		"--timeout", "0",
	}
	for _, p := range packs {
		args = append(args, "--config", p)
	}
	args = append(args, target)

	data, err := runJSON(ctx, "semgrep", args...)
	if err != nil {
		return nil, fmt.Errorf("semgrep scan failed: %w", err)
	}
	return parseSemgrep(data)
}

// parseSemgrep decodes semgrep JSON output into RawFindings. Split out from
// Scan so it is unit-testable without invoking the binary.
func parseSemgrep(data []byte) ([]model.RawFinding, error) {
	var result struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("semgrep json decode: %w", err)
	}

	findings := make([]model.RawFinding, 0, len(result.Results))
	for _, rawRes := range result.Results {
		finding, err := parseSemgrepResult(rawRes)
		if err != nil {
			// Skip only the malformed result, not the whole run.
			continue
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

type semgrepResult struct {
	CheckID string          `json:"check_id"`
	Path    string          `json:"path"`
	Start   semgrepPosition `json:"start"`
	End     semgrepPosition `json:"end"`
	Extra   semgrepExtra    `json:"extra"`
}

type semgrepPosition struct {
	Line int `json:"line"`
}

type semgrepExtra struct {
	Message  string          `json:"message"`
	Severity string          `json:"severity"`
	Fix      string          `json:"fix"`
	Metadata semgrepMetadata `json:"metadata"`
}

// semgrepMetadata: cwe and owasp are emitted by the registry sometimes as a
// string and sometimes as an array, so both decode via flexStrings.
type semgrepMetadata struct {
	CWE        json.RawMessage `json:"cwe"`
	Owasp      json.RawMessage `json:"owasp"`
	Confidence string          `json:"confidence"`
	Category   string          `json:"category"`
	Fix        string          `json:"fix"`
}

func parseSemgrepResult(raw json.RawMessage) (model.RawFinding, error) {
	var res semgrepResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return model.RawFinding{}, err
	}

	meta := map[string]string{}
	if owasp := flexStrings(res.Extra.Metadata.Owasp); len(owasp) > 0 {
		meta["owasp"] = strings.Join(owasp, ", ")
	}
	if res.Extra.Metadata.Category != "" {
		meta["category"] = res.Extra.Metadata.Category
	}
	if len(meta) == 0 {
		meta = nil
	}

	return model.RawFinding{
		Tool:     "semgrep",
		Category: model.CategorySAST,
		RuleID:   res.CheckID,
		// Human title (schema 2.0.0): the first sentence of the rule message,
		// never the dotted check_id path. Empty messages fall back to a
		// humanized check_id in Normalize; sanitization (control chars,
		// whitespace, 120-rune cap) also happens there for every adapter.
		Title:       firstSentence(res.Extra.Message),
		Description: res.Extra.Message,
		RawSeverity: res.Extra.Severity,
		Confidence:  res.Extra.Metadata.Confidence,
		File:        res.Path,
		StartLine:   res.Start.Line,
		EndLine:     res.End.Line,
		CWEs:        flexStrings(res.Extra.Metadata.CWE),
		Remediation: firstNonEmpty(res.Extra.Metadata.Fix, res.Extra.Fix),
		Meta:        meta,
		RawPayload:  raw,
	}, nil
}

// firstSentence cuts a rule message at the first sentence boundary: a period
// followed by whitespace, or a newline. A trailing period is kept. Messages
// with no boundary pass through whole (Normalize caps the length).
// Deterministic — titles are tool-derived, never generated.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	for i, r := range s {
		if r == '\n' {
			return strings.TrimSpace(s[:i])
		}
		if r == '.' && i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
			return s[:i+1]
		}
	}
	return s
}

// flexStrings decodes a JSON value that may be a string, an array of strings,
// or absent, into a []string.
func flexStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil
		}
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		out := many[:0]
		for _, s := range many {
			if s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
