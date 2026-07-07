package triage

// LLM output parsing is a security boundary and is never delegated or
// auto-generated. Model output is only trusted after validation: the verdict
// must match the enum exactly, confidence is clamped into [0,1], and free
// text reaches reports only through the sanitized, length-bounded rationale.
// Anything else fails parsing and the finding degrades to "uncertain".

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/leaky-hub/argus/internal/model"
)

type rawVerdict struct {
	Verdict    string   `json:"verdict"`
	Confidence *float64 `json:"confidence"`
	Rationale  string   `json:"rationale"`
}

// parseVerdict validates raw model output into a bounded Triage value
// (Model field left empty; the caller stamps it). It never returns a partially
// trusted result: on error the caller must discard everything.
func parseVerdict(raw string) (model.Triage, error) {
	v, err := decodeFirstObject(raw)
	if err != nil {
		return model.Triage{}, err
	}

	verdict := strings.ToLower(strings.TrimSpace(v.Verdict))
	switch verdict {
	case model.VerdictTruePositive, model.VerdictFalsePositive, model.VerdictUncertain:
	default:
		return model.Triage{}, fmt.Errorf("unknown verdict %.40q", v.Verdict)
	}

	// Missing confidence is "no opinion", not certainty: 0.5 keeps the risk
	// adjustment moderate. NaN/Inf and out-of-range values are clamped.
	conf := 0.5
	if v.Confidence != nil && !math.IsNaN(*v.Confidence) && !math.IsInf(*v.Confidence, 0) {
		conf = math.Min(1, math.Max(0, *v.Confidence))
	}

	return model.Triage{
		Verdict:    verdict,
		Confidence: conf,
		Rationale:  sanitizeRationale(v.Rationale),
	}, nil
}

// decodeFirstObject finds and decodes the first JSON object in the model's
// output, tolerating prose or code fences around it (models add those).
func decodeFirstObject(s string) (rawVerdict, error) {
	return firstJSONObject[rawVerdict](s)
}

// firstJSONObject finds the first parseable JSON object in s and decodes it
// into a fresh T, tolerating prose or code fences around the object. It is the
// single JSON-extraction seam every triage parser shares.
//
// Provider responses are capped at 1 MB. A naive "restart a decoder at every
// '{'" scan is O(n^2) on adversarial input — a long run that stays grammatically
// valid until EOF (e.g. `{"x":{"x":{"x":…`) makes each attempt scan the whole
// tail before failing, and there is a '{' at every step. A 1 MB such payload
// pinned a core for ~25s. Legitimate output carries the object within the first
// few '{' positions, so bound the number of candidates: the scan stays linear
// and a hostile completion can no longer burn CPU.
func firstJSONObject[T any](s string) (T, error) {
	const maxCandidates = 64
	tried := 0
	for idx := 0; idx < len(s); idx++ {
		if s[idx] != '{' {
			continue
		}
		var v T
		if err := json.NewDecoder(strings.NewReader(s[idx:])).Decode(&v); err == nil {
			return v, nil
		}
		if tried++; tried >= maxCandidates {
			break
		}
	}
	var zero T
	return zero, errors.New("no JSON object in model output")
}

// sanitizeRationale is the ONLY path by which model free-text reaches a
// report: control characters collapse to spaces and length is bounded.
func sanitizeRationale(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		n++
		if n >= maxRationaleRunes {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}
