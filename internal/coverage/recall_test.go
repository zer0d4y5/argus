package coverage

import (
	"context"
	"testing"
	"time"

	"github.com/leaky-hub/appsec/internal/scanner"
)

// profileOrder gives the superset chain: fast ⊂ standard ⊂ max (pack lists
// are supersets by construction; TestMaxSupersetsStandard pins that).
var profileOrder = map[string]int{
	scanner.ProfileFast:     0,
	scanner.ProfileStandard: 1,
	scanner.ProfileMax:      2,
}

// TestParsePlants is the fast unit check: labels are well-formed, unique,
// and present in meaningful numbers. Runs without semgrep.
func TestParsePlants(t *testing.T) {
	polyglotRoot, _, _ := paths(t)
	plants, err := ParsePlants(polyglotRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(plants) < 25 {
		t.Fatalf("only %d labeled plants — the polyglot fixtures should carry at least 25", len(plants))
	}
	perProfile := map[string]int{}
	for _, p := range plants {
		perProfile[p.MinProfile]++
	}
	// Every profile tier must have at least one plant that proves it: a tier
	// with no plants of its own is an unproven claim.
	for _, prof := range []string{scanner.ProfileFast, scanner.ProfileStandard, scanner.ProfileMax} {
		if perProfile[prof] == 0 {
			t.Errorf("no plant is labeled min-profile=%s — that tier's recall is unproven", prof)
		}
	}
}

// TestProfileRecall is the recall eval (locked decision 7): every plant is
// caught by its min profile and every superset, and caught-plant sets form
// the inclusion chain fast ⊆ standard ⊆ max on plant IDs. New packs only
// land with plants that prove they matter — this is where that bar is held.
func TestProfileRecall(t *testing.T) {
	requireSemgrep(t)
	polyglotRoot, _, _ := paths(t)

	plants, err := ParsePlants(polyglotRoot)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	caughtBy := map[string]map[string]bool{}
	for _, prof := range []string{scanner.ProfileFast, scanner.ProfileStandard, scanner.ProfileMax} {
		findings, err := Scan(ctx, prof, polyglotRoot)
		if err != nil {
			t.Fatalf("%s scan: %v", prof, err)
		}
		caughtBy[prof] = CaughtPlants(plants, DetectedCWEs(findings))
		t.Logf("%s: %d/%d plants caught", prof, len(caughtBy[prof]), len(plants))
	}

	// Each plant: caught by its min profile and everything above it.
	for _, p := range plants {
		for prof, order := range profileOrder {
			if order >= profileOrder[p.MinProfile] && !caughtBy[prof][p.ID] {
				t.Errorf("MISS: plant %s (%s:%d, %s) labeled min-profile=%s but not caught by %s",
					p.ID, p.File, p.Line, p.CWE, p.MinProfile, prof)
			}
			// A catch below the labeled minimum is not a failure — an
			// upstream pack update improving fast is good news — but the
			// label can be tightened; say so.
			if order < profileOrder[p.MinProfile] && caughtBy[prof][p.ID] {
				t.Logf("NOTE: plant %s is already caught by %s; min-profile=%s can be tightened",
					p.ID, prof, p.MinProfile)
			}
		}
	}

	// Inclusion chain on plant IDs, not counts: everything fast catches,
	// standard must catch; everything standard catches, max must catch.
	for _, pair := range [][2]string{
		{scanner.ProfileFast, scanner.ProfileStandard},
		{scanner.ProfileStandard, scanner.ProfileMax},
	} {
		lo, hi := pair[0], pair[1]
		for id := range caughtBy[lo] {
			if !caughtBy[hi][id] {
				t.Errorf("INCLUSION BROKEN: plant %s caught by %s but not by %s", id, lo, hi)
			}
		}
	}
}
