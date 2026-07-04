package model

import (
	"path"
	"strings"
)

// FilterIgnored removes findings suppressed by config: ignore_paths (glob
// patterns against the finding's file path) and ignore_rules (exact rule
// IDs). It returns the kept findings plus the number suppressed, so callers
// can report suppression counts instead of hiding them — silent suppression
// is how real issues disappear.
//
// Path pattern semantics (documented in README):
//   - `path.Match` glob against the full slash-separated path ("*" does not
//     cross "/"), e.g. "vendor/*/*.go"
//   - a pattern ending in "/**" ignores the whole subtree, e.g. "testdata/**"
//   - a bare directory name (no glob metacharacters, no extension) ignores
//     the subtree rooted there, e.g. "vendor"
func FilterIgnored(findings []Finding, ignorePaths, ignoreRules []string) (kept []Finding, suppressed int) {
	rules := make(map[string]bool, len(ignoreRules))
	for _, r := range ignoreRules {
		if r = strings.TrimSpace(r); r != "" {
			rules[r] = true
		}
	}

	kept = make([]Finding, 0, len(findings))
	for _, f := range findings {
		if rules[f.RuleID] || pathIgnored(f.Location.File, ignorePaths) {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

func pathIgnored(file string, patterns []string) bool {
	if file == "" {
		return false
	}
	file = strings.TrimPrefix(path.Clean(strings.ReplaceAll(file, "\\", "/")), "./")
	for _, p := range patterns {
		p = strings.TrimPrefix(strings.TrimSpace(strings.ReplaceAll(p, "\\", "/")), "./")
		if p == "" {
			continue
		}
		// Subtree forms: "dir/**" or a bare directory name.
		if sub, ok := strings.CutSuffix(p, "/**"); ok {
			if file == sub || strings.HasPrefix(file, sub+"/") {
				return true
			}
			continue
		}
		if !strings.ContainsAny(p, "*?[") {
			if file == p || strings.HasPrefix(file, p+"/") {
				return true
			}
			continue
		}
		if ok, err := path.Match(p, file); err == nil && ok {
			return true
		}
	}
	return false
}
