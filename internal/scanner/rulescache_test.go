package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsRegistryPackAndCachePath(t *testing.T) {
	cases := map[string]bool{
		"p/security-audit": true,
		"r/python.lang":    true,
		CuratedRuleset:     false,
		"./rules/x.yml":    false,
		"/abs/rules.yml":   false,
	}
	for ref, want := range cases {
		if got := IsRegistryPack(ref); got != want {
			t.Errorf("IsRegistryPack(%q) = %v, want %v", ref, got, want)
		}
	}
	if got := CachedPackPath("/cache", "p/security-audit"); got != filepath.Join("/cache", "p_security-audit.yml") {
		t.Errorf("CachedPackPath = %q", got)
	}
}

func TestRegistryPacksIn(t *testing.T) {
	in := []string{"p/a", CuratedRuleset, "./local.yml", "p/a", "p/b"}
	got := RegistryPacksIn(in)
	if len(got) != 2 || got[0] != "p/a" || got[1] != "p/b" {
		t.Errorf("RegistryPacksIn(%v) = %v, want [p/a p/b]", in, got)
	}
}

func TestResolveOffline(t *testing.T) {
	dir := t.TempDir()
	// Cache p/a only; p/b is missing.
	cachedA := CachedPackPath(dir, "p/a")
	if err := os.WriteFile(cachedA, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(dir, "byo.yml")
	os.WriteFile(local, []byte("rules: []\n"), 0o644)

	var warned []string
	in := []string{"p/a", "p/b", CuratedRuleset, local}
	got := ResolveOffline(in, dir, func(m string) { warned = append(warned, m) })

	// p/a -> its cache file; p/b -> dropped+warned; curated + local pass through.
	want := []string{cachedA, CuratedRuleset, local}
	if len(got) != len(want) {
		t.Fatalf("ResolveOffline = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
	if len(warned) != 1 {
		t.Errorf("want exactly one warning (for uncached p/b), got %v", warned)
	}
}

func TestResolveOfflineNeverEmptiesCurated(t *testing.T) {
	// Empty cache: every registry pack drops, but curated survives so the scan
	// still runs the embedded rules.
	got := ResolveOffline([]string{"p/x", "p/y", CuratedRuleset}, t.TempDir(), nil)
	if len(got) != 1 || got[0] != CuratedRuleset {
		t.Errorf("want only curated to survive an empty cache, got %v", got)
	}
}

func TestRulesCacheDirOverride(t *testing.T) {
	if got := RulesCacheDir("/custom/dir"); got != "/custom/dir" {
		t.Errorf("override ignored: %q", got)
	}
	if got := RulesCacheDir(""); got == "" {
		t.Error("default cache dir should not be empty")
	}
}
