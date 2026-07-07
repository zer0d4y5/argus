package scanner

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestRulePackCatalogWellFormed: every catalog entry has a p/ id, a label, a
// known category, and a description. Runs without semgrep.
func TestRulePackCatalogWellFormed(t *testing.T) {
	valid := map[string]bool{}
	for _, c := range RulePackCategories {
		valid[c] = true
	}
	seen := map[string]bool{}
	for _, p := range RulePackCatalog {
		if seen[p.ID] {
			t.Errorf("duplicate catalog pack %q", p.ID)
		}
		seen[p.ID] = true
		if len(p.ID) < 3 || p.ID[:2] != "p/" {
			t.Errorf("pack %q is not a p/ registry ref", p.ID)
		}
		if p.Label == "" || p.Description == "" {
			t.Errorf("pack %q missing label or description", p.ID)
		}
		if !valid[p.Category] {
			t.Errorf("pack %q has unknown category %q", p.ID, p.Category)
		}
	}
	if len(RulePackCatalog) < 20 {
		t.Errorf("catalog has only %d packs", len(RulePackCatalog))
	}
}

// TestRulePackCatalogResolves proves every catalog pack actually resolves
// against the semgrep registry, so the console never offers a typo that would
// break a scan. Needs semgrep + network; skipped in -short.
func TestRulePackCatalogResolves(t *testing.T) {
	if testing.Short() {
		t.Skip("resolves registry packs over the network")
	}
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH")
	}
	empty := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	for _, p := range RulePackCatalog {
		cmd := exec.CommandContext(ctx, "semgrep", "scan", "--config", p.ID, "--metrics=off", "--quiet", "--json", empty)
		cmd.Env = os.Environ()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("catalog pack %s failed to resolve: %v\n%s", p.ID, err, truncate(out, 300))
		}
	}
}
