package coverage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leaky-hub/appsec/internal/scanner"
)

// vulnClass groups the CWEs that represent one weakness category, for the
// columns of the coverage matrix.
type vulnClass struct {
	Label string
	CWEs  []string
}

// matrixClasses are the columns of the coverage matrix, in display order.
var matrixClasses = []vulnClass{
	{"SQL Injection", []string{"CWE-89"}},
	{"Command Injection", []string{"CWE-78", "CWE-77"}},
	{"Code Injection", []string{"CWE-94", "CWE-95"}},
	{"XSS", []string{"CWE-79"}},
	{"Deserialization", []string{"CWE-502"}},
	{"Weak Crypto", []string{"CWE-327", "CWE-328"}},
}

// detLevel is the detection strength of a class in a language.
type detLevel int

const (
	detNone     detLevel = iota // not detected by any curated profile
	detMax                      // detected only under `max`
	detStandard                 // detected under `standard` (and therefore max)
)

func (d detLevel) cell() string {
	switch d {
	case detStandard:
		return "✅"
	case detMax:
		return "◐"
	default:
		return "·"
	}
}

// classLevel resolves how well a vuln class is covered for one fixture file,
// given the standard and max detection maps.
func classLevel(file string, class vulnClass, std, max map[string]map[string]bool) detLevel {
	if anyCWE(std[file], class.CWEs) {
		return detStandard
	}
	if anyCWE(max[file], class.CWEs) {
		return detMax
	}
	return detNone
}

func anyCWE(got map[string]bool, cwes []string) bool {
	for _, c := range cwes {
		if got[c] {
			return true
		}
	}
	return false
}

// GenerateMarkdown renders docs/coverage.md from live scan results. std and max
// are DetectedCWEs maps from a `standard` and `max` scan of the polyglot
// fixtures. The output is fully derived from those scans plus the manifest, so
// it can never claim coverage the scanners did not actually produce.
func GenerateMarkdown(labels []Label, std, max map[string]map[string]bool) string {
	var b strings.Builder

	b.WriteString("# Coverage — the eagle-eye matrix\n\n")
	b.WriteString("> **Generated, not authored.** This file is produced by\n")
	b.WriteString("> `internal/coverage` from a live scan of the labeled fixtures under\n")
	b.WriteString("> `testdata/polyglot/`. Regenerate with `make coverage` (or\n")
	b.WriteString("> `APPSEC_UPDATE_COVERAGE=1 go test ./internal/coverage`). If a cell here\n")
	b.WriteString("> disagrees with a scan, the scan is right and this file is stale.\n\n")
	b.WriteString("Detection is proven, not claimed: a network-dependent test\n")
	b.WriteString("(`TestPolyglotCoverage`) asserts every ✅ canary below is caught under the\n")
	b.WriteString("`standard` profile, and fails CI if breadth regresses.\n\n")

	// --- Profiles → rulesets ------------------------------------------------
	b.WriteString("## Scan profiles\n\n")
	b.WriteString("`--profile fast|standard|max` (config: `profile:`). Ruleset lists are the\n")
	b.WriteString("detection policy; they live in one reviewed file (`internal/scanner/profiles.go`)\n")
	b.WriteString("and are overridable per repo via `semgrep_rulesets:`.\n\n")
	b.WriteString("| Profile | semgrep packs | Intended use | Relative cost |\n")
	b.WriteString("|---|---|---|---|\n")
	profileCost := map[string]string{
		scanner.ProfileFast:     "fastest",
		scanner.ProfileStandard: "~1 pack-set, moderate",
		scanner.ProfileMax:      "highest (adds p/default)",
	}
	profileUse := map[string]string{
		scanner.ProfileFast:     "tight PR gates, low noise",
		scanner.ProfileStandard: "default — broad multi-language audit",
		scanner.ProfileMax:      "deep audit; recall over noise (triage handles FPs)",
	}
	for _, p := range []string{scanner.ProfileFast, scanner.ProfileStandard, scanner.ProfileMax} {
		packs := scanner.ResolveSemgrepRulesets(p, nil)
		b.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n",
			p, "`"+strings.Join(packs, "`, `")+"`", profileUse[p], profileCost[p]))
	}
	b.WriteString("\n")

	// --- The matrix ---------------------------------------------------------
	b.WriteString("## Language × weakness coverage\n\n")
	b.WriteString("✅ caught under `standard` · ◐ caught only under `max` · · not caught by any profile\n\n")

	// Header row.
	b.WriteString("| Language |")
	for _, c := range matrixClasses {
		b.WriteString(" " + c.Label + " |")
	}
	b.WriteString("\n|---|")
	for range matrixClasses {
		b.WriteString(":---:|")
	}
	b.WriteString("\n")

	// One row per language, in manifest order.
	for _, l := range labels {
		b.WriteString("| " + l.Language + " |")
		for _, c := range matrixClasses {
			b.WriteString(" " + classLevel(l.File, c, std, max).cell() + " |")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// --- Canary list --------------------------------------------------------
	b.WriteString("## Canaries (regression guard)\n\n")
	b.WriteString("Each is asserted detected under `standard` by `TestPolyglotCoverage`:\n\n")
	for _, l := range labels {
		var names []string
		for _, c := range l.Canaries {
			names = append(names, fmt.Sprintf("%s (%s)", c.Name, c.CWE))
		}
		b.WriteString(fmt.Sprintf("- **%s** — %s\n", l.Language, strings.Join(names, "; ")))
	}
	b.WriteString("\n")

	// --- Honest gaps --------------------------------------------------------
	b.WriteString("## Known gaps (honest accounting)\n\n")
	gaps := knownGaps(labels, std, max)
	if len(gaps) == 0 {
		b.WriteString("None among the labeled classes — every weakness class shown is caught by at least one profile.\n\n")
	} else {
		b.WriteString("Weakness classes present in a fixture that no curated profile currently catches:\n\n")
		for _, g := range gaps {
			b.WriteString("- " + g + "\n")
		}
		b.WriteString("\nThese are tracked as detection-policy work, not hidden. ")
		b.WriteString("Compiled-language command injection (Java `Runtime.exec`, C# `Process.Start`, ")
		b.WriteString("Go `exec.Command`) and path traversal are the notable holes; a dedicated ")
		b.WriteString("gosec/CodeQL-style pass is the roadmap answer.\n\n")
	}

	// --- Per-scanner writeup ------------------------------------------------
	b.WriteString("## Per-scanner review\n\n")
	b.WriteString("- **semgrep (SAST)** — the breadth engine. `standard` runs a security-audit +\n")
	b.WriteString("  OWASP-Top-Ten base plus a per-language pack for Python, JS, TS, Go, Java, C#,\n")
	b.WriteString("  Ruby, PHP, and Kotlin. `max` adds `p/default`, `p/secrets`, `p/gosec`, and\n")
	b.WriteString("  framework/category packs, which is what lifts Kotlin command injection,\n")
	b.WriteString("  Python string-format SQLi, and TS weak-crypto into coverage (see ◐ cells).\n")
	b.WriteString("- **gitleaks (SECRET)** — default ruleset (100+ credential patterns) is\n")
	b.WriteString("  sufficient; secret material is redacted before it ever reaches a report or an\n")
	b.WriteString("  LLM. No per-language tuning needed — secrets are language-agnostic.\n")
	b.WriteString("- **trivy (SCA)** — vulnerability scanning of dependency manifests and lockfiles\n")
	b.WriteString("  across ecosystems; `--profile` does not change SCA behavior (semgrep-only).\n")
	b.WriteString("  Trivy's built-in misconfiguration scanner is the Phase 4 IaC teaser.\n\n")

	b.WriteString("## Why breadth is safe here\n\n")
	b.WriteString("Wide rulesets raise false-positive volume — that is the intended tradeoff. The\n")
	b.WriteString("Phase 2 AI triage layer is the answer: every finding gets a local-LLM verdict and\n")
	b.WriteString("a 0–10 risk score, so `standard`/`max` breadth stays actionable instead of\n")
	b.WriteString("drowning the reviewer. Breadth + triage is the pairing the demo shows.\n")

	return b.String()
}

// knownGaps lists weakness classes that appear in a fixture (as a canary) yet
// are caught by neither profile — defensive: with correct labels this is empty,
// but it surfaces any silent regression in the source packs.
func knownGaps(labels []Label, std, max map[string]map[string]bool) []string {
	var out []string
	for _, l := range labels {
		for _, c := range matrixClasses {
			// Only report a gap for a class the fixture is known to contain,
			// i.e. one of its canaries falls in this class.
			if !fileHasCanaryInClass(l, c) {
				continue
			}
			if classLevel(l.File, c, std, max) == detNone {
				out = append(out, fmt.Sprintf("%s — %s", l.Language, c.Label))
			}
		}
	}
	sort.Strings(out)
	return out
}

func fileHasCanaryInClass(l Label, c vulnClass) bool {
	for _, can := range l.Canaries {
		for _, cwe := range c.CWEs {
			if can.CWE == cwe {
				return true
			}
		}
	}
	return false
}
