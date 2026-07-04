package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// This file is the DETECTION POLICY of the platform: the curated semgrep
// rulesets behind each scan profile. It is deliberately hand-maintained and
// reviewed — the breadth of what we detect is the product. Ruleset lists are
// data, so a repo can override them via `semgrep_rulesets:` in appsec.yml, but
// the defaults below are the vetted baseline every scan uses out of the box.
//
// Every pack listed here is validated against the semgrep registry
// (`semgrep --config <pack> --validate`) before being added; a typo'd pack
// silently narrows coverage, which is the one failure this file exists to
// prevent. See docs/coverage.md for the profile × language × cost matrix.

// Profile names. String-typed because they appear verbatim in the CLI flag and
// in appsec.yml.
const (
	ProfileFast     = "fast"
	ProfileStandard = "standard"
	ProfileMax      = "max"
)

// DefaultProfile is what a scan uses when neither --profile nor config sets one.
// standard is the breadth/false-positive tradeoff we want the demo to show:
// wide multi-language coverage, with AI triage (Phase 2) as the FP answer.
const DefaultProfile = ProfileStandard

// semgrepProfiles maps each profile to its curated registry pack list.
//
//   - fast     — semgrep's own curated low-noise CI pack. Fastest; what Phase 1
//     shipped. Good for tight PR gates.
//   - standard — security-audit + OWASP Top Ten + a per-language security pack
//     for every language we claim to cover. The default. Broadest useful signal
//     without the long-tail noise of p/default.
//   - max      — standard plus the long-tail: the full default ruleset, a
//     dedicated secrets pass, gosec, and framework/category packs. Highest
//     recall, highest FP volume (that is the point — triage handles it).
//
// Order within a list is preserved and de-duplicated at resolution time, so
// packs shared across profiles are expressed once via composition.
var semgrepProfiles = map[string][]string{
	ProfileFast: {
		"p/ci",
	},
	ProfileStandard: standardPacks,
	ProfileMax:      append(append([]string{}, standardPacks...), maxOnlyPacks...),
}

// standardPacks: cross-cutting security audit + OWASP, then one vetted security
// pack per language we cover. Adding a language means adding its pack here AND
// a labeled fixture under testdata/polyglot/.
var standardPacks = []string{
	"p/security-audit",
	"p/owasp-top-ten",
	"p/python",
	"p/javascript",
	"p/typescript",
	"p/golang",
	"p/java",
	"p/csharp",
	"p/ruby",
	"p/php",
	"p/kotlin",
}

// maxOnlyPacks: long-tail recall added on top of standard.
var maxOnlyPacks = []string{
	"p/default",
	"p/secrets",
	"p/gosec",
	"p/nodejsscan",
	"p/react",
	"p/command-injection",
	"p/sql-injection",
	"p/xss",
	"p/jwt",
	"p/insecure-transport",
}

// KnownProfiles returns the valid profile names, sorted, for validation and
// help text.
func KnownProfiles() []string {
	names := make([]string, 0, len(semgrepProfiles))
	for name := range semgrepProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidProfile reports whether name is a known profile.
func ValidProfile(name string) bool {
	_, ok := semgrepProfiles[name]
	return ok
}

// ResolveSemgrepRulesets returns the semgrep pack list a scan should use.
//
// Precedence: an explicit override (from `semgrep_rulesets:` in config) always
// wins and is used verbatim — a repo that curates its own list opts out of the
// profile machinery entirely. Otherwise the named profile's curated list is
// returned. An empty/unknown profile falls back to DefaultProfile rather than
// erroring, so a scan never silently runs with zero rules.
//
// The returned slice is de-duplicated (first occurrence wins) so profile
// composition can freely repeat packs. It always contains at least one pack.
func ResolveSemgrepRulesets(profile string, override []string) []string {
	if len(override) > 0 {
		return dedupePacks(override)
	}
	packs, ok := semgrepProfiles[profile]
	if !ok {
		packs = semgrepProfiles[DefaultProfile]
	}
	return dedupePacks(packs)
}

// dedupePacks trims, drops empties, and removes duplicates while preserving
// first-seen order.
func dedupePacks(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// ValidateProfile returns a descriptive error if profile is non-empty and
// unknown. Empty is valid (means "use the default").
func ValidateProfile(profile string) error {
	if profile == "" || ValidProfile(profile) {
		return nil
	}
	return fmt.Errorf("unknown profile %q; must be one of %s", profile, strings.Join(KnownProfiles(), ", "))
}
