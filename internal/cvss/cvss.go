// Package cvss computes a CVSS 3.1 base score from a vector string. The score
// is derived deterministically from the metrics per the specification — the
// LLM validate seam proposes the metric values (its judgement of the finding),
// and this package does the arithmetic, so a model can never fudge the number.
package cvss

import (
	"fmt"
	"math"
	"strings"
)

// Base holds the eight CVSS 3.1 base metrics.
type Base struct {
	AV, AC, PR, UI, S, C, I, A string
}

var (
	avW = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acW = map[string]float64{"L": 0.77, "H": 0.44}
	uiW = map[string]float64{"N": 0.85, "R": 0.62}
	// PR depends on Scope.
	prU  = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prC  = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	ciaW = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.00}
)

// valid enumerates the allowed values per metric so a malformed vector is
// rejected rather than silently scored wrong.
var valid = map[string]map[string]bool{
	"AV": {"N": true, "A": true, "L": true, "P": true},
	"AC": {"L": true, "H": true},
	"PR": {"N": true, "L": true, "H": true},
	"UI": {"N": true, "R": true},
	"S":  {"U": true, "C": true},
	"C":  {"H": true, "L": true, "N": true},
	"I":  {"H": true, "L": true, "N": true},
	"A":  {"H": true, "L": true, "N": true},
}

// Parse reads a CVSS 3.1 vector like
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" and validates every base
// metric is present and legal.
func Parse(vector string) (Base, error) {
	got := map[string]string{}
	for _, part := range strings.Split(strings.TrimSpace(vector), "/") {
		if part == "" || strings.HasPrefix(part, "CVSS:") {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return Base{}, fmt.Errorf("malformed metric %q", part)
		}
		k, v := strings.ToUpper(kv[0]), strings.ToUpper(kv[1])
		if allowed, ok := valid[k]; ok && allowed[v] {
			if _, dup := got[k]; dup {
				// The spec forbids repeating a metric. Last-one-wins would let a
				// duplicated metric silently move the score across a severity
				// band, so reject rather than guess which value was meant.
				return Base{}, fmt.Errorf("duplicate base metric %s", k)
			}
			got[k] = v
		}
	}
	for _, m := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if got[m] == "" {
			return Base{}, fmt.Errorf("missing or invalid base metric %s", m)
		}
	}
	return Base{AV: got["AV"], AC: got["AC"], PR: got["PR"], UI: got["UI"], S: got["S"], C: got["C"], I: got["I"], A: got["A"]}, nil
}

// Vector renders the canonical CVSS 3.1 base vector string.
func (b Base) Vector() string {
	return fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s", b.AV, b.AC, b.PR, b.UI, b.S, b.C, b.I, b.A)
}

// Score computes the CVSS 3.1 base score (0.0–10.0) per the specification.
func (b Base) Score() float64 {
	scopeChanged := b.S == "C"
	pr := prU[b.PR]
	if scopeChanged {
		pr = prC[b.PR]
	}
	iss := 1 - (1-ciaW[b.C])*(1-ciaW[b.I])*(1-ciaW[b.A])
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	expl := 8.22 * avW[b.AV] * acW[b.AC] * pr * uiW[b.UI]
	if impact <= 0 {
		return 0.0
	}
	sum := impact + expl
	if scopeChanged {
		sum = 1.08 * sum
	}
	return roundup(math.Min(sum, 10))
}

// Severity bands a base score, matching the CVSS 3.1 qualitative scale (and
// the console's own severity bands).
func Severity(score float64) string {
	switch {
	case score == 0:
		return "None"
	case score < 4.0:
		return "Low"
	case score < 7.0:
		return "Medium"
	case score < 9.0:
		return "High"
	default:
		return "Critical"
	}
}

// roundup is CVSS 3.1's specific "round up to one decimal" operation.
func roundup(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
}
