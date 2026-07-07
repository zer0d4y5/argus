// Package risk computes the 0–10 risk score for every finding. The formula is
// a written contract — docs/risk-scoring.md — and this file must match it
// exactly. Security-critical: the LLM never sets a score; it can only move
// the deterministic baseline within the bounds encoded here, via a validated
// verdict + confidence.
package risk

import (
	"math"
	"strings"

	"github.com/leaky-hub/argus/internal/model"
)

// highImpactCWEs is the direct code-execution / auth-bypass / data-exfil
// class from docs/risk-scoring.md. Extending it is a normal reviewed change.
var highImpactCWEs = map[string]bool{
	"CWE-22":   true, // path traversal
	"CWE-77":   true, // command injection
	"CWE-78":   true, // OS command injection
	"CWE-89":   true, // SQL injection
	"CWE-94":   true, // code injection
	"CWE-95":   true, // eval injection
	"CWE-287":  true, // improper authentication
	"CWE-306":  true, // missing authentication
	"CWE-434":  true, // unrestricted upload
	"CWE-502":  true, // unsafe deserialization
	"CWE-611":  true, // XXE
	"CWE-798":  true, // hardcoded credentials
	"CWE-918":  true, // SSRF
	"CWE-1336": true, // template injection
}

// Apply sets RiskScore and RiskSignals on every finding, in place,
// unconditionally: the heuristic baseline always, the per-category context
// modifier always (neutral when no signal fires), plus the bounded triage
// adjustment when a verdict is present. It takes the full run's findings so
// co-location signals can see across scanners. Idempotent; never touches any
// field other than RiskScore and RiskSignals.
//
// The returned slice is the STAGE-2 DETERMINISTIC score per finding
// (index-aligned, one decimal): where the LLM-free part of the formula ends
// and the severity-banding input (model.SeverityForScore) begins. The stored
// RiskScore is the full stage-3 value; the two differ exactly when a triage
// verdict adjusted the score. Callers that band severity do so from the
// return value, never from RiskScore, so no LLM output can move a severity.
func Apply(findings []model.Finding) []float64 {
	rc := buildRunContext(findings)
	det := make([]float64, len(findings))
	for i := range findings {
		s, d, signals := score(findings[i], rc)
		findings[i].RiskScore = &s
		findings[i].RiskSignals = signals
		det[i] = d
	}
	return det
}

// ApplyAndBand runs Apply and then sets each finding's Severity by banding
// its deterministic (stage-2) score — the schema 2.0.0 pipeline step. It
// lives beside Apply so no caller can accidentally band from the stored
// stage-3 riskScore, which a triage verdict may have moved.
func ApplyAndBand(findings []model.Finding) {
	det := Apply(findings)
	for i := range findings {
		findings[i].Severity = model.SeverityForScore(det[i])
	}
}

func score(f model.Finding, rc runContext) (final, deterministic float64, _ []model.RiskSignal) {
	s := Baseline(f)

	// Stage 2: per-category context modifier (context.go). The summed delta
	// is capped at ±3.0 so no heuristic stack can dominate severity; a
	// synthetic row records the clamp so exported deltas sum exactly to the
	// applied change.
	signals := contextSignals(f, rc)
	raw := 0.0
	for _, sg := range signals {
		raw += sg.Delta
	}
	delta := clamp(raw, -contextCap, contextCap)
	if delta != raw {
		signals = append(signals, model.RiskSignal{
			Code: "context.cap", Delta: round2(delta - raw),
			Note: "context delta capped at ±3.0",
		})
	}
	s = clamp(s+delta, 0, 10)

	// Unverified ceiling: the top of the critical band ([9.5, 10]) is
	// reserved for credentials explicitly verified live. Static heuristics
	// corroborating each other reach at most 9.4 — and so does a triage
	// true-positive below, because the LLM never sees the secret value and
	// therefore cannot confirm liveness.
	ceiled := secretShaped(f) && verifiedState(f) != verifiedLive
	if ceiled && s > unverifiedCeiling {
		signals = append(signals, model.RiskSignal{
			Code: "secret.unverified_ceiling", Delta: round2(unverifiedCeiling - s),
			Note: "unverified secrets cap at 9.4; only meta.verified=live lifts the ceiling",
		})
		s = unverifiedCeiling
	}

	// Stage 2 ends here: `det` is the deterministic score severity is banded
	// from (docs/risk-scoring.md, "Severity banding"). Everything below is the
	// bounded LLM adjustment, which reaches riskScore only — never severity.
	deterministic = round1(s)

	// Stage 3: bounded triage adjustment, unchanged from v1.
	floor := 0.0
	if f.Triage != nil {
		s += adjustment(f.Triage)
		if f.Triage.Verdict == model.VerdictFalsePositive {
			// An FP verdict deprioritizes but never erases: advice, not proof.
			floor = 0.5
		}
	}
	s = clamp(s, floor, 10)
	if ceiled {
		s = math.Min(s, unverifiedCeiling)
	}
	return round1(s), deterministic, signals
}

// Baseline is stage 1 of docs/risk-scoring.md: deterministic, LLM-free.
//
// The severity input is ToolSeverity — what NormalizeSeverity produced —
// NEVER the finding's (banded) Severity: banded severity is derived from this
// score, and feeding it back would make scores self-amplify across re-scores.
// Findings from documents older than 2.0.0 have no ToolSeverity; their stored
// Severity IS tool-normalized (never re-banded), so it is the correct input.
func Baseline(f model.Finding) float64 {
	sev := f.Severity
	if f.ToolSeverity != nil {
		sev = *f.ToolSeverity
	}
	s := severityBase(sev)

	switch strings.ToLower(strings.TrimSpace(f.Confidence)) {
	case "high":
		s += 0.5
	case "low":
		s -= 1.0
	}

	if f.Category == model.CategorySecret {
		s += 1.0
	}

	for _, cwe := range f.CWEs {
		if highImpactCWEs[cwe] {
			s += 0.5
			break
		}
	}

	if strings.TrimSpace(f.Remediation) != "" {
		s += 0.25
	}

	return clamp(s, 0, 10)
}

func severityBase(s model.Severity) float64 {
	switch s {
	case model.SeverityCritical:
		return 9.0
	case model.SeverityHigh:
		return 7.0
	case model.SeverityMedium:
		return 5.0
	case model.SeverityLow:
		return 3.0
	default:
		return 1.0
	}
}

// adjustment is stage 3: a pure, bounded function of the validated verdict
// and confidence. Confidence is clamped again here so a bug upstream can
// never widen the bounds.
func adjustment(t *model.Triage) float64 {
	c := clamp(t.Confidence, 0, 1)
	switch t.Verdict {
	case model.VerdictTruePositive:
		return 1.0 * c
	case model.VerdictFalsePositive:
		return -4.0 * c
	default:
		return 0
	}
}

func clamp(v, lo, hi float64) float64 {
	return math.Min(hi, math.Max(lo, v))
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

// round2 keeps synthetic signal deltas (cap/ceiling remainders) clean in
// JSON; table deltas are exact two-decimal constants already.
func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
