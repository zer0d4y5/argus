package model

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// Severity is the normalized severity scale shared by every finding regardless
// of which tool produced it. The ordering is significant: a higher value is
// more severe, and the severity gate compares with >=.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if s < SeverityInfo || s > SeverityCritical {
		return "info"
	}
	return severityNames[s]
}

// MarshalJSON emits the lowercase name so reports are human-readable and the
// schema is not coupled to Go iota values.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	sev, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = sev
	return nil
}

// ParseSeverity parses a normalized severity name (case-insensitive).
// It rejects unknown values rather than guessing: callers that need a
// fallback must choose one explicitly.
func ParseSeverity(name string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "info", "informational", "note":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium", "moderate":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	}
	return SeverityInfo, fmt.Errorf("unknown severity %q", name)
}

// SeverityForScore bands a deterministic risk score (stages 1–2 of
// docs/risk-scoring.md, one decimal) onto the severity scale. The bands are
// the canonical, user-specified table in docs/risk-scoring.md ("Severity
// banding") and match the Overview histogram cutoffs by construction:
//
//	9.0 – 10.0  critical
//	7.0 – 8.9   high
//	4.0 – 6.9   medium
//	0.1 – 3.9   low
//	0.0         info   (reachable: the stage-1 floor is 0.0)
//
// The input must be the DETERMINISTIC score — never the stage-3
// triage-adjusted riskScore, so no LLM output can ever move a severity.
// Banding compares on the integer decisecond value so float representation
// never decides a boundary; out-of-range inputs clamp into the scale.
func SeverityForScore(score float64) Severity {
	d := int(math.Round(score * 10))
	switch {
	case d >= 90:
		return SeverityCritical
	case d >= 70:
		return SeverityHigh
	case d >= 40:
		return SeverityMedium
	case d >= 1:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// NormalizeSeverity maps a tool's native severity string onto the shared
// scale. Since schema 2.0.0 this value is the finding's toolSeverity — the
// stage-1 risk-score input and "tool said" audit trail — while the finding's
// severity is banded from the deterministic risk score (SeverityForScore).
// Mappings are explicit per tool; anything unrecognized falls back to
// the tool default so a new native value can never silently vanish from
// reports (the raw string is preserved on the finding either way).
//
//	semgrep:  ERROR -> high, WARNING -> medium, INFO -> info
//	gitleaks: no native scale; secrets are high (leaked credential = direct impact)
//	trivy:    CRITICAL/HIGH/MEDIUM/LOW verbatim, UNKNOWN -> medium
//	trivy-config: same scale as trivy (same engine, misconfiguration pass)
//	checkov:  CRITICAL/HIGH/MEDIUM/LOW/INFO verbatim when present; OSS checkov
//	          emits NO severity for most checks -> medium
//	prowler:  Critical/High/Medium/Low verbatim, Informational -> info,
//	          empty -> medium (an un-scored posture failure is unassessed,
//	          not harmless — same policy as trivy UNKNOWN)
//
// UNKNOWN from trivy maps to medium, not info: an un-scored CVE is
// unassessed, not harmless, and mapping it to info would let the severity
// gate wave it through. The same reasoning fixes the checkov policy: an
// un-scored misconfiguration defaults to medium — visible, gate-relevant
// under a medium gate, and never info. Runs enriched by the checkov platform
// DO carry a native severity and are mapped verbatim.
func NormalizeSeverity(tool, raw string) Severity {
	v := strings.ToUpper(strings.TrimSpace(raw))
	switch strings.ToLower(tool) {
	case "semgrep":
		switch v {
		case "ERROR", "CRITICAL", "HIGH":
			return SeverityHigh
		case "WARNING", "MEDIUM":
			return SeverityMedium
		case "LOW":
			return SeverityLow
		case "INFO", "INVENTORY", "EXPERIMENT":
			return SeverityInfo
		}
		return SeverityMedium
	case "gitleaks":
		// gitleaks has no severity concept; a detected secret is high.
		return SeverityHigh
	case "trivy", "trivy-config":
		switch v {
		case "CRITICAL":
			return SeverityCritical
		case "HIGH":
			return SeverityHigh
		case "MEDIUM":
			return SeverityMedium
		case "LOW":
			return SeverityLow
		case "UNKNOWN", "":
			return SeverityMedium
		}
		return SeverityMedium
	case "checkov":
		switch v {
		case "CRITICAL":
			return SeverityCritical
		case "HIGH":
			return SeverityHigh
		case "MEDIUM":
			return SeverityMedium
		case "LOW":
			return SeverityLow
		case "INFO":
			return SeverityInfo
		case "":
			// OSS checkov emits no severity; un-scored != harmless.
			return SeverityMedium
		}
		return SeverityMedium
	case "prowler":
		switch v {
		case "CRITICAL":
			return SeverityCritical
		case "HIGH":
			return SeverityHigh
		case "MEDIUM":
			return SeverityMedium
		case "LOW":
			return SeverityLow
		case "INFORMATIONAL", "INFO":
			return SeverityInfo
		}
		// Empty or a new native value: un-scored != harmless.
		return SeverityMedium
	}
	// Unknown tool: try the string directly, then fail toward medium so the
	// finding still surfaces and can trip a medium-or-lower gate.
	if sev, err := ParseSeverity(v); err == nil {
		return sev
	}
	return SeverityMedium
}

// MaxSeverity returns the highest severity present in findings, and false if
// the slice is empty.
func MaxSeverity(findings []Finding) (Severity, bool) {
	if len(findings) == 0 {
		return SeverityInfo, false
	}
	max := SeverityInfo
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max, true
}

// GateExceeded reports whether any finding meets or exceeds the threshold.
// This is the CI pass/fail decision. A threshold of nil means the gate is
// disabled ("none") and never fails the build.
func GateExceeded(findings []Finding, threshold *Severity) bool {
	if threshold == nil {
		return false
	}
	for _, f := range findings {
		if f.Severity >= *threshold {
			return true
		}
	}
	return false
}

// ParseGate parses a fail-severity gate value: a severity name or "none"
// (disabled). Returns nil for "none".
func ParseGate(value string) (*Severity, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "none" || v == "off" || v == "" {
		return nil, nil
	}
	sev, err := ParseSeverity(v)
	if err != nil {
		return nil, fmt.Errorf("invalid fail severity %q (want critical|high|medium|low|info|none)", value)
	}
	return &sev, nil
}
