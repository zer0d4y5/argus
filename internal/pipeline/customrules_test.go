package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/scanner"
)

// TestValidateCustomRulesetsDropsInvalid: a missing local rule is dropped with
// a clear warning while registry packs pass through untouched. Needs no
// semgrep: a missing path fails at resolution, before the validator runs.
func TestValidateCustomRulesetsDropsInvalid(t *testing.T) {
	var warnings []string
	prog := func(line string) { warnings = append(warnings, line) }

	in := []string{"p/python", "./definitely-missing-rule.yml", scanner.CuratedRuleset}
	got := validateCustomRulesets(context.Background(), in, prog)

	for _, r := range got {
		if strings.Contains(r, "missing") {
			t.Errorf("invalid local rule survived: %v", got)
		}
	}
	if len(got) != 2 || got[0] != "p/python" || got[1] != scanner.CuratedRuleset {
		t.Errorf("packs should pass through unchanged, got %v", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "custom rule skipped") {
		t.Errorf("expected one clear skip warning, got %v", warnings)
	}
}

// TestValidateCustomRulesetsPacksOnlyNoop: a packs-only list is returned
// unchanged and triggers no validation work.
func TestValidateCustomRulesetsPacksOnlyNoop(t *testing.T) {
	called := false
	prog := func(string) { called = true }
	in := []string{"p/python", "p/javascript", scanner.CuratedRuleset}
	got := validateCustomRulesets(context.Background(), in, prog)
	if len(got) != len(in) {
		t.Errorf("packs-only list changed: %v", got)
	}
	if called {
		t.Error("packs-only list should emit no warnings")
	}
}
