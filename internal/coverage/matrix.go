package coverage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/scanner"
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

	b.WriteString("# Coverage: the eagle-eye matrix\n\n")
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
		scanner.ProfileStandard: "default: broad multi-language audit",
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
		b.WriteString(fmt.Sprintf("- **%s**: %s\n", l.Language, strings.Join(names, "; ")))
	}
	b.WriteString("\n")

	// --- Honest gaps --------------------------------------------------------
	b.WriteString("## Known gaps (honest accounting)\n\n")
	gaps := knownGaps(labels, std, max)
	if len(gaps) == 0 {
		b.WriteString("None among the labeled classes: every weakness class shown is caught by at least one profile.\n\n")
	} else {
		b.WriteString("Weakness classes present in a fixture that no curated profile currently catches:\n\n")
		for _, g := range gaps {
			b.WriteString("- " + g + "\n")
		}
		b.WriteString("\nThese are tracked as detection-policy work, not hidden: each is a\n")
		b.WriteString("candidate for a registry pack or an argus/curated rule, under the same\n")
		b.WriteString("earn-your-slot bar.\n\n")
	}

	// --- Per-scanner writeup ------------------------------------------------
	b.WriteString("## Per-scanner review\n\n")
	b.WriteString("- **semgrep (SAST)**: the breadth engine. `standard` runs a security-audit +\n")
	b.WriteString("  OWASP-Top-Ten base plus a per-language pack for Python, JS, TS, Go, Java, C#,\n")
	b.WriteString("  Ruby, PHP, Kotlin, **Rust** (`p/rust`), and **Scala** (`p/scala`), plus the\n")
	b.WriteString("  **argus/curated** local ruleset (below). `max` adds `p/default`, `p/secrets`,\n")
	b.WriteString("  `p/gosec`, and framework/category packs, which is what lifts Kotlin command\n")
	b.WriteString("  injection, Python string-format SQLi, and TS weak-crypto into coverage\n")
	b.WriteString("  (see ◐ cells).\n")
	b.WriteString("- **argus/curated (local rules, detection-depth session).** The platform's own\n")
	b.WriteString("  vetted rules (`internal/scanner/rules/curated.yaml`, embedded in the binary,\n")
	b.WriteString("  never fetched) close gaps every registry pack provably missed: Python path\n")
	b.WriteString("  traversal (CWE-22), Go shell command injection (CWE-78), JavaScript SQLi\n")
	b.WriteString("  through a query string (CWE-89), Kotlin concatenated-statement SQLi (CWE-89)\n")
	b.WriteString("  and predictable PRNG (CWE-330), PHP extract() (CWE-621) and rand() tokens\n")
	b.WriteString("  (CWE-330), and all five Swift plants (SQLi, shell cmdi, MD5, disabled TLS\n")
	b.WriteString("  validation, hardcoded credential). Every rule holds the same earn-your-slot\n")
	b.WriteString("  bar as a pack, per rule, via TestProfileRecall, and each class has a\n")
	b.WriteString("  safe-code PLANT-FP counterpart that must stay unflagged.\n")
	b.WriteString("- **New languages, honest accounting.** **Rust** and **Scala** landed with\n")
	b.WriteString("  dedicated packs (`p/rust`: untrusted-input CWE-807, unsafe-usage CWE-242;\n")
	b.WriteString("  `p/scala`: tainted-sql-string CWE-89). **C** landed through\n")
	b.WriteString("  `p/security-audit`'s own C rules (`insecure-use-gets-fn`, CWE-676); a\n")
	b.WriteString("  dedicated `p/c` added nothing over it on the plants, so it was NOT added.\n")
	b.WriteString("  **Swift** landed via argus/curated after `p/swift` caught none of its\n")
	b.WriteString("  plants. **Elixir** did NOT land and cannot on the OSS engine: parsing\n")
	b.WriteString("  Elixir is a Pro-only plugin (every elixir rule errors with MissingPlugin),\n")
	b.WriteString("  so neither registry packs nor local rules can cover it; its fixture stays\n")
	b.WriteString("  `PLANT-GAP` documentation and `.ex`/`.exs` stay \"unsupported source\" in\n")
	b.WriteString("  skip accounting. Nothing is claimed that a scan did not prove.\n")
	b.WriteString("- **gitleaks (SECRET)**: default ruleset (100+ credential patterns) is\n")
	b.WriteString("  sufficient; secret material is redacted before it ever reaches a report or an\n")
	b.WriteString("  LLM. No per-language tuning needed: secrets are language-agnostic.\n")
	b.WriteString("  **Git history mode** (schema 2.0.0): when the scan target is a git\n")
	b.WriteString("  repository, a second pass scans the commit history, so a credential that\n")
	b.WriteString("  was committed and later deleted, but never rotated, still surfaces,\n")
	b.WriteString("  labeled `meta.gitHistory` with the introducing commit. Shallow console\n")
	b.WriteString("  workspaces (depth-1 clones) cover a single commit of history and say so\n")
	b.WriteString("  (`meta.gitShallow`). Cost: roughly one extra gitleaks pass per scan.\n")
	b.WriteString("- **trivy (SCA)**: vulnerability scanning of dependency manifests and lockfiles\n")
	b.WriteString("  across ecosystems; `--profile` does not change SCA behavior (semgrep-only).\n")
	b.WriteString("  Trivy's built-in misconfiguration scanner is the Phase 4 IaC teaser.\n\n")

	b.WriteString("## Recall is proven, not asserted\n\n")
	b.WriteString("Every planted vulnerability in `testdata/polyglot` carries an in-fixture\n")
	b.WriteString("label `PLANT(<id>, min-profile=<fast|standard|max>, <CWE>)` naming the\n")
	b.WriteString("minimum profile that must catch it. `TestProfileRecall` scans the fixtures\n")
	b.WriteString("under every profile and asserts (a) each plant is caught by its minimum\n")
	b.WriteString("profile and every superset, and (b) the caught-plant sets form the\n")
	b.WriteString("inclusion chain fast ⊆ standard ⊆ max on plant IDs. A new pack lands in a\n")
	b.WriteString("profile only with a plant proving it detects something the existing packs\n")
	b.WriteString("miss; packs that add nothing are rejected (p/flask, p/django, p/brakeman\n")
	b.WriteString("were evaluated and rejected on exactly that bar). Plants no profile catches\n")
	b.WriteString("are labeled `PLANT-GAP` in the fixtures and listed under Known gaps.\n\n")

	b.WriteString("## Skip accounting (what a scan did NOT look at)\n\n")
	b.WriteString("Every saved run carries a `coverage` block (schema 2.0.0): files bucketed\n")
	b.WriteString("as SAST-covered, IaC/config, secrets-only text, **unsupported source**\n")
	b.WriteString("(recognizable code in a language no profile analyzes), **binary**, and\n")
	b.WriteString("**oversize** (> 5 MB), plus git-repo/shallow facts, with sample paths.\n")
	b.WriteString("The console renders it on the run detail. \"No findings\" in a tree full\n")
	b.WriteString("of unscanned binaries is a different claim than \"no findings\" in a fully\n")
	b.WriteString("analyzable tree; the accounting keeps the difference visible.\n\n")

	b.WriteString("## Why breadth is safe here\n\n")
	b.WriteString("Wide rulesets raise false-positive volume; that is the intended tradeoff. The\n")
	b.WriteString("Phase 2 AI triage layer is the answer: every finding gets a local-LLM verdict and\n")
	b.WriteString("a 0–10 risk score, so `standard`/`max` breadth stays actionable instead of\n")
	b.WriteString("drowning the reviewer. Breadth + triage is the pairing the demo shows.\n")

	return b.String()
}

// GenerateIaCSection renders the IaC portion of docs/coverage.md from live
// scan results: one row per planted misconfiguration, with the engine(s) that
// actually detected it. Like the language matrix, it is fully derived from
// the manifest plus real findings, so it cannot claim coverage the engines
// did not produce.
func GenerateIaCSection(labels []IaCLabel, findings []model.Finding) string {
	// tool -> fixture-relative file -> rule IDs that fired.
	byTool := map[string]map[string]map[string]bool{}
	for _, f := range findings {
		rel := iacRelPath(f.Location.File)
		if rel == "" || f.RuleID == "" {
			continue
		}
		files := byTool[f.Tool]
		if files == nil {
			files = map[string]map[string]bool{}
			byTool[f.Tool] = files
		}
		set := files[rel]
		if set == nil {
			set = map[string]bool{}
			files[rel] = set
		}
		set[f.RuleID] = true
	}
	detectedBy := func(file string, rules []string) string {
		var tools []string
		for _, tool := range []string{"checkov", "trivy-config"} {
			if anyRule(byTool[tool][file], rules) {
				tools = append(tools, tool)
			}
		}
		if len(tools) == 0 {
			return "**MISS**"
		}
		return strings.Join(tools, " + ")
	}

	var b strings.Builder
	b.WriteString("## Infrastructure-as-Code coverage\n\n")
	b.WriteString("IaC misconfiguration scanning (category `IAC`) runs **checkov** and\n")
	b.WriteString("**trivy-config** (the trivy misconfiguration pass, no extra binary) against\n")
	b.WriteString("Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, and Helm charts.\n")
	b.WriteString("IaC engines run whenever available; `--profile` governs semgrep only. Planted\n")
	b.WriteString("misconfigurations under `testdata/iac/` are asserted detected by\n")
	b.WriteString("`TestIaCCoverage`; the table below is generated from that live scan.\n\n")
	b.WriteString("| Fixture | Planted misconfiguration | Canary rules | Detected by |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, l := range labels {
		for _, c := range l.Canaries {
			b.WriteString(fmt.Sprintf("| %s (`%s`) | %s | %s | %s |\n",
				l.Kind, l.File, c.Name,
				"`"+strings.Join(c.Rules, "`, `")+"`",
				detectedBy(l.File, c.Rules)))
		}
	}
	b.WriteString("\nEvery IaC finding rolls up to **A05 Security Misconfiguration** in the OWASP\n")
	b.WriteString("view and gets the same triage + 0–10 risk score as app-code findings.\n")
	b.WriteString("Severity policy for the IaC engines is documented in `docs/findings-model.md`.\n")
	return b.String()
}

// knownGaps lists weakness classes that appear in a fixture (as a canary) yet
// are caught by neither profile. Defensive: with correct labels this is empty,
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
				out = append(out, fmt.Sprintf("%s: %s", l.Language, c.Label))
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
