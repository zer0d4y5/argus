package scanner

import (
	"strings"
	"testing"
)

func TestResolveSemgrepRulesets_Profiles(t *testing.T) {
	tests := []struct {
		profile   string
		wantFirst string
		minPacks  int
	}{
		{ProfileFast, "p/ci", 1},
		{ProfileStandard, "p/security-audit", 8},
		{ProfileMax, "p/security-audit", 15},
	}
	for _, tt := range tests {
		got := ResolveSemgrepRulesets(tt.profile, nil)
		if len(got) < tt.minPacks {
			t.Errorf("profile %q: got %d packs, want >= %d", tt.profile, len(got), tt.minPacks)
		}
		if got[0] != tt.wantFirst {
			t.Errorf("profile %q: first pack = %q, want %q", tt.profile, got[0], tt.wantFirst)
		}
	}
}

func TestResolveSemgrepRulesets_UnknownFallsBackToDefault(t *testing.T) {
	got := ResolveSemgrepRulesets("bogus", nil)
	want := ResolveSemgrepRulesets(DefaultProfile, nil)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("unknown profile did not fall back to default:\n got %v\nwant %v", got, want)
	}
	if len(got) == 0 {
		t.Fatal("resolution must never yield zero packs")
	}
}

func TestResolveSemgrepRulesets_EmptyFallsBackToDefault(t *testing.T) {
	got := ResolveSemgrepRulesets("", nil)
	if len(got) == 0 || got[0] != "p/security-audit" {
		t.Errorf("empty profile should resolve to default standard set, got %v", got)
	}
}

func TestResolveSemgrepRulesets_OverrideReplaces(t *testing.T) {
	override := []string{"p/custom", "p/other"}
	got := ResolveSemgrepRulesets(ProfileMax, override)
	if len(got) != 2 || got[0] != "p/custom" || got[1] != "p/other" {
		t.Errorf("a bare override should replace the profile packs, got %v", got)
	}
}

func TestResolveSemgrepRulesets_AdditiveMarker(t *testing.T) {
	std := ResolveSemgrepRulesets(ProfileStandard, nil)
	got := ResolveSemgrepRulesets(ProfileStandard, []string{"+", "./rules/custom.yml"})
	// Additive: all standard packs, then the custom entry, deduped.
	if len(got) != len(std)+1 {
		t.Fatalf("additive should be profile packs + 1 custom, got %d (std=%d): %v", len(got), len(std), got)
	}
	if got[0] != std[0] {
		t.Errorf("additive should lead with the profile packs, got %v", got)
	}
	if got[len(got)-1] != "./rules/custom.yml" {
		t.Errorf("additive should append the custom entry last, got %v", got)
	}
	// The curated sentinel (a standard pack) must survive additive merging.
	found := false
	for _, p := range got {
		if p == CuratedRuleset {
			found = true
		}
	}
	if !found {
		t.Error("additive merge dropped the argus/curated sentinel")
	}
}

func TestResolveSemgrepRulesets_AdditiveDedupes(t *testing.T) {
	// A custom entry that repeats a profile pack collapses to one.
	got := ResolveSemgrepRulesets(ProfileStandard, []string{"+", "p/python"})
	std := ResolveSemgrepRulesets(ProfileStandard, nil)
	if len(got) != len(std) {
		t.Errorf("additive of a pack already in the profile should not grow the list: got %d want %d", len(got), len(std))
	}
}

func TestResolveSemgrepRulesets_BareMarkerIsProfile(t *testing.T) {
	// A lone "+" (additive, nothing to add) resolves to the profile packs.
	got := ResolveSemgrepRulesets(ProfileStandard, []string{"+"})
	std := ResolveSemgrepRulesets(ProfileStandard, nil)
	if strings.Join(got, ",") != strings.Join(std, ",") {
		t.Errorf("bare additive marker should equal the profile packs:\n got %v\nwant %v", got, std)
	}
}

func TestResolveSemgrepRulesets_Dedupes(t *testing.T) {
	got := ResolveSemgrepRulesets("", []string{"p/a", "p/a", " p/b ", "", "p/b"})
	if len(got) != 2 || got[0] != "p/a" || got[1] != "p/b" {
		t.Errorf("expected deduped, trimmed [p/a p/b], got %v", got)
	}
}

func TestMaxSupersetsStandard(t *testing.T) {
	std := ResolveSemgrepRulesets(ProfileStandard, nil)
	max := map[string]bool{}
	for _, p := range ResolveSemgrepRulesets(ProfileMax, nil) {
		max[p] = true
	}
	for _, p := range std {
		if !max[p] {
			t.Errorf("max profile is missing standard pack %q", p)
		}
	}
}

func TestValidateProfile(t *testing.T) {
	for _, ok := range []string{"", "fast", "standard", "max"} {
		if err := ValidateProfile(ok); err != nil {
			t.Errorf("ValidateProfile(%q) = %v, want nil", ok, err)
		}
	}
	if err := ValidateProfile("nonsense"); err == nil {
		t.Error("ValidateProfile(nonsense) = nil, want error")
	}
}

func TestSemgrepAdapterUsesRulesets(t *testing.T) {
	// The adapter must carry the resolved packs; empty falls back at scan time.
	a := &Semgrep{Rulesets: []string{"p/x", "p/y"}}
	if len(a.Rulesets) != 2 {
		t.Fatalf("adapter did not retain rulesets")
	}
	all := All([]string{"p/z"}, false)
	sg, ok := all[0].(*Semgrep)
	if !ok || len(sg.Rulesets) != 1 || sg.Rulesets[0] != "p/z" {
		t.Errorf("All() did not thread rulesets into semgrep adapter: %+v", all[0])
	}
}
