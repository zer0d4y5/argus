package threatlib

import (
	"testing"

	"github.com/zer0d4y5/argus/internal/mitigation"
)

func TestLibraryLoadsAndIsWellFormed(t *testing.T) {
	comps := Components()
	if len(comps) < 4 {
		t.Fatalf("expected several component types, got %d", len(comps))
	}
	for _, c := range comps {
		if c.Tech == "" || c.Title == "" || len(c.Threats) == 0 {
			t.Errorf("%q: missing tech/title/threats", c.Tech)
		}
		for _, th := range c.Threats {
			if !ValidCategory(th.Category) {
				t.Errorf("%q/%s: invalid STRIDE category %q", c.Tech, th.Title, th.Category)
			}
			if th.Title == "" || th.Description == "" {
				t.Errorf("%q: threat missing title/description", c.Tech)
			}
		}
	}
}

// TestMitigationRefsResolve enforces the payoff wiring: every suggested
// mitigation id must be a real weakness in the mitigation library, so a threat
// always links to guidance that exists.
func TestMitigationRefsResolve(t *testing.T) {
	for _, c := range Components() {
		for _, th := range c.Threats {
			if th.Mitigation == "" {
				continue
			}
			if _, ok := mitigation.Get(th.Mitigation); !ok {
				t.Errorf("%q/%s references mitigation %q which does not exist", c.Tech, th.Title, th.Mitigation)
			}
		}
	}
}

func TestEnumerate(t *testing.T) {
	threats, ok := Enumerate("web-app")
	if !ok || len(threats) == 0 {
		t.Fatalf("web-app enumerate = %d ok=%v", len(threats), ok)
	}
	// Case/space-insensitive.
	if _, ok := Enumerate("  WEB-APP "); !ok {
		t.Error("enumerate should normalize tech")
	}
	if _, ok := Enumerate("nonesuch"); ok {
		t.Error("unknown tech should not resolve")
	}
}
