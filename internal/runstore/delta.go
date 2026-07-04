package runstore

import (
	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/report"
)

// Delta is the difference between a previous run and the current run, keyed by
// stable fingerprint. New + Unchanged partition the current run; Resolved are
// findings that were in the previous run and are gone from the current one.
type Delta struct {
	New       []model.Finding `json:"new"`       // in current, not in previous
	Resolved  []model.Finding `json:"resolved"`  // in previous, not in current
	Unchanged []model.Finding `json:"unchanged"` // in both (current copy)
}

// Counts is the headline delta summary for the Runs view.
type Counts struct {
	New       int `json:"new"`
	Resolved  int `json:"resolved"`
	Unchanged int `json:"unchanged"`
	Total     int `json:"total"` // total in the current run
}

// Counts reduces a Delta to its headline numbers.
func (d Delta) Counts() Counts {
	return Counts{
		New:       len(d.New),
		Resolved:  len(d.Resolved),
		Unchanged: len(d.Unchanged),
		Total:     len(d.New) + len(d.Unchanged),
	}
}

// ComputeDelta compares the current run against the previous one by fingerprint.
//
// Rules (deliberately simple — see the package doc on why):
//   - a current finding whose ID is absent from previous  → New
//   - a current finding whose ID is present in previous    → Unchanged
//   - a previous finding whose ID is absent from current   → Resolved
//
// prev may be nil (the first run): then every current finding is New and
// nothing is Resolved. Findings are never dropped or mutated — the current
// finding object is carried through verbatim, so verdicts and risk scores ride
// along untouched.
func ComputeDelta(prev *report.Document, curr report.Document) Delta {
	prevIDs := map[string]bool{}
	if prev != nil {
		for _, f := range prev.Findings {
			prevIDs[f.ID] = true
		}
	}
	currIDs := make(map[string]bool, len(curr.Findings))
	for _, f := range curr.Findings {
		currIDs[f.ID] = true
	}

	var d Delta
	for _, f := range curr.Findings {
		if prevIDs[f.ID] {
			d.Unchanged = append(d.Unchanged, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	if prev != nil {
		for _, f := range prev.Findings {
			if !currIDs[f.ID] {
				d.Resolved = append(d.Resolved, f)
			}
		}
	}
	return d
}
