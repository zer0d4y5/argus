package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// This file backs offline scanning. `argus rules sync` fetches the profile's
// registry packs into a local cache; an offline scan then reads those cached
// files instead of resolving p/* refs over the network. The curated rules are
// already embedded, so an offline scan runs even with an empty cache.

// RulesCacheDir resolves the directory where `argus rules sync` stores fetched
// registry packs and where an offline scan reads them. An explicit override
// (config offline.cache_dir) wins; otherwise <user-cache>/argus/rules, falling
// back to a repo-local dir if the OS user-cache dir is unavailable.
func RulesCacheDir(override string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ".argus-rules-cache"
	}
	return filepath.Join(base, "argus", "rules")
}

// IsRegistryPack reports whether a ruleset entry is a semgrep registry pack
// reference (p/… or r/…): the entries that would be fetched over the network,
// and which `argus rules sync` caches. The CuratedRuleset sentinel and local
// file/dir paths are not registry packs.
func IsRegistryPack(ref string) bool {
	return strings.HasPrefix(ref, "p/") || strings.HasPrefix(ref, "r/")
}

// CachedPackPath returns the on-disk file a registry pack ref caches to, e.g.
// "p/security-audit" -> "<cacheDir>/p_security-audit.yml". The mapping is a
// pure function of the ref so sync and offline-resolve agree without any index.
func CachedPackPath(cacheDir, packRef string) string {
	return filepath.Join(cacheDir, strings.ReplaceAll(packRef, "/", "_")+".yml")
}

// RegistryPacksIn returns the registry-pack subset of a ruleset list, in order,
// deduplicated: the packs `argus rules sync` should fetch for a profile.
func RegistryPacksIn(rulesets []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rulesets {
		if IsRegistryPack(r) && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// ResolveOffline rewrites a resolved ruleset list for an offline scan: each
// registry pack ref becomes its cached local file when present, or is dropped
// with a warning when the cache lacks it (the user should run `argus rules
// sync` while online). The curated sentinel and local file/dir paths pass
// through unchanged (they are already local) so the returned list never
// causes semgrep to reach the network. Curated always survives, so an offline
// scan with an empty cache still runs the embedded rules rather than nothing.
func ResolveOffline(rulesets []string, cacheDir string, warn func(string)) []string {
	out := make([]string, 0, len(rulesets))
	for _, r := range rulesets {
		if r == CuratedRuleset || !IsRegistryPack(r) {
			out = append(out, r)
			continue
		}
		path := CachedPackPath(cacheDir, r)
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			out = append(out, path)
			continue
		}
		if warn != nil {
			warn(fmt.Sprintf("offline: registry pack %s is not cached at %s; skipped (run `argus rules sync` while online)", r, path))
		}
	}
	return out
}
