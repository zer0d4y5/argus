package scanner

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestSemgrepPacksResolve makes the "every pack is registry-validated" claim
// in profiles.go CI-runnable instead of a comment: each pack referenced by
// any profile must resolve against the semgrep registry (a typo'd pack
// silently narrows coverage — the one failure that file exists to prevent).
// Needs semgrep + network; skipped in -short mode like the smoke test.
func TestSemgrepPacksResolve(t *testing.T) {
	if testing.Short() {
		t.Skip("resolves registry packs over the network")
	}
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH")
	}

	seen := map[string]bool{}
	var packs []string
	for _, prof := range KnownProfiles() {
		for _, p := range ResolveSemgrepRulesets(prof, nil) {
			if !seen[p] {
				seen[p] = true
				packs = append(packs, p)
			}
		}
	}
	if len(packs) < 20 {
		t.Fatalf("only %d packs resolved from profiles — expected the full curated set", len(packs))
	}

	empty := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, pack := range packs {
		cmd := exec.CommandContext(ctx, "semgrep", "scan", "--config", pack, "--metrics=off", "--quiet", "--json", empty)
		cmd.Env = os.Environ()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("pack %s failed to resolve: %v\n%s", pack, err, truncate(out, 400))
		}
	}
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
