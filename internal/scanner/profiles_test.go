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

func TestResolveSemgrepRulesets_OverrideWins(t *testing.T) {
	override := []string{"p/custom", "p/other"}
	got := ResolveSemgrepRulesets(ProfileMax, override)
	if len(got) != 2 || got[0] != "p/custom" || got[1] != "p/other" {
		t.Errorf("override should be used verbatim, got %v", got)
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
	all := All([]string{"p/z"})
	sg, ok := all[0].(*Semgrep)
	if !ok || len(sg.Rulesets) != 1 || sg.Rulesets[0] != "p/z" {
		t.Errorf("All() did not thread rulesets into semgrep adapter: %+v", all[0])
	}
}
