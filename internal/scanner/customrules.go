package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Bring-your-own semgrep rules. A `semgrep_rulesets:` entry (config or console)
// may be a registry pack (p/... or r/...), the argus/curated sentinel, or a
// LOCAL rule file/dir. Local rules are the new surface, and they are treated
// carefully: the path is validated, and semgrep's own validator runs over it
// before a scan uses it, so a malformed rule is a clear, specific error rather
// than an opaque mid-scan failure. Remote rule URLs are refused outright: rules
// that run must be local and reviewable, never fetched at scan time.
//
// This file is the trust boundary for user-supplied rule references. It never
// executes rule logic (semgrep does that against the target); it only decides
// what kind of reference an entry is and whether semgrep will accept it.

// RulesetKind classifies one semgrep_rulesets entry.
type RulesetKind int

const (
	// KindRegistryPack is a semgrep registry reference (p/..., r/...) or the
	// argus/curated sentinel. Resolved by semgrep at scan time; not validated
	// here (a user-named registry pack is their call, resolved over the network
	// when the scan runs).
	KindRegistryPack RulesetKind = iota
	// KindLocalPath is a filesystem file or directory of rules.
	KindLocalPath
)

func (k RulesetKind) String() string {
	if k == KindLocalPath {
		return "local"
	}
	return "pack"
}

// registryPackPattern matches a semgrep registry shorthand: a single-letter
// namespace (p = ruleset, r = rule, s = snippet) followed by a slash-separated
// path of word/dot/dash segments. Deliberately strict so a local path is never
// mistaken for a pack.
var registryPackPattern = regexp.MustCompile(`^[a-z]/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)

// ruleFileExtensions are the extensions semgrep accepts for a rule FILE. A
// directory is accepted whatever its contents (semgrep walks it for these).
var ruleFileExtensions = map[string]bool{".yml": true, ".yaml": true, ".json": true}

// ClassifyRuleset decides what kind of reference an entry is, WITHOUT touching
// the filesystem. It rejects the two things that must never reach semgrep as a
// --config: an empty entry, and a remote URL (rules that run must be local).
// Everything shaped like a registry pack is a pack; everything else is treated
// as a local path, validated for real by ValidateLocalRuleset.
func ClassifyRuleset(entry string) (RulesetKind, error) {
	e := strings.TrimSpace(entry)
	switch {
	case e == "":
		return 0, fmt.Errorf("empty ruleset entry")
	case e == AdditiveMarker:
		// The additive marker is handled by ResolveSemgrepRulesets and must be
		// stripped before classification; reaching here is a caller bug.
		return 0, fmt.Errorf("the %q marker is not a ruleset", AdditiveMarker)
	case strings.Contains(e, "://"):
		return 0, fmt.Errorf("remote rule URLs are not allowed (%q): host the rules locally and reference the file, or use a registry pack", e)
	case e == CuratedRuleset || registryPackPattern.MatchString(e):
		return KindRegistryPack, nil
	default:
		return KindLocalPath, nil
	}
}

// resolveLocalRuleset resolves a local entry to an absolute path (relative
// entries against baseDir, or the process CWD when baseDir is empty) and
// checks it is a usable rule reference: it must exist, and a FILE must carry a
// semgrep rule extension. It returns the resolved path for validation/scanning.
func resolveLocalRuleset(entry, baseDir string) (string, error) {
	p := strings.TrimSpace(entry)
	if !filepath.IsAbs(p) {
		if baseDir != "" {
			p = filepath.Join(baseDir, p)
		} else {
			abs, err := filepath.Abs(p)
			if err != nil {
				return "", fmt.Errorf("custom rule %q: %w", entry, err)
			}
			p = abs
		}
	}
	info, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("custom rule %q not found (looked at %s)", entry, p)
		}
		return "", fmt.Errorf("custom rule %q: %w", entry, err)
	}
	if info.IsDir() {
		return p, nil
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("custom rule %q is not a regular file", entry)
	}
	if ext := strings.ToLower(filepath.Ext(p)); !ruleFileExtensions[ext] {
		return "", fmt.Errorf("custom rule %q must be a .yml, .yaml, or .json file or a directory", entry)
	}
	return p, nil
}

// RulesetStatus is the per-entry outcome of validation, for the console and
// the pipeline warning.
type RulesetStatus struct {
	Entry   string `json:"entry"`             // the entry as written
	Kind    string `json:"kind"`              // "pack" | "local"
	OK      bool   `json:"ok"`                // safe to use
	Message string `json:"message,omitempty"` // why not, when OK is false
}

// ValidateRulesets classifies every entry and, for LOCAL rules, resolves the
// path and runs `semgrep --validate` over it. Registry packs and the sentinel
// are reported OK without a network round trip (they resolve at scan time).
// The additive marker, if present as the first entry, is skipped. baseDir
// resolves relative local paths (the served dir for the console; "" = CWD for
// the CLI). A nil/empty semgrep on PATH degrades local entries to a clear
// "cannot validate" status rather than a crash.
func ValidateRulesets(ctx context.Context, entries []string, baseDir string) []RulesetStatus {
	_, entries = splitAdditive(entries)
	out := make([]RulesetStatus, 0, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		kind, err := ClassifyRuleset(e)
		if err != nil {
			out = append(out, RulesetStatus{Entry: e, OK: false, Message: err.Error()})
			continue
		}
		if kind == KindRegistryPack {
			out = append(out, RulesetStatus{Entry: e, Kind: kind.String(), OK: true})
			continue
		}
		path, err := resolveLocalRuleset(e, baseDir)
		if err != nil {
			out = append(out, RulesetStatus{Entry: e, Kind: kind.String(), OK: false, Message: err.Error()})
			continue
		}
		if err := semgrepValidate(ctx, path); err != nil {
			out = append(out, RulesetStatus{Entry: e, Kind: kind.String(), OK: false, Message: err.Error()})
			continue
		}
		out = append(out, RulesetStatus{Entry: e, Kind: kind.String(), OK: true})
	}
	return out
}

// FirstInvalid returns the first non-OK status, or nil if all entries are OK.
// Callers that want to reject a whole ruleset list (console save) use this for
// a single clear error.
func FirstInvalid(statuses []RulesetStatus) *RulesetStatus {
	for i := range statuses {
		if !statuses[i].OK {
			return &statuses[i]
		}
	}
	return nil
}

// ValidateLocalRuleFile validates that a local file is a loadable semgrep
// config (`semgrep --validate`). Exported for `argus rules sync`, which uses it
// to reject a fetched pack that is truncated or an error page before caching it.
func ValidateLocalRuleFile(ctx context.Context, path string) error {
	return semgrepValidate(ctx, path)
}

// semgrepValidate runs `semgrep --validate --config <path>` and turns a failure
// into a concise error. It parses rule DATA, never the scanned code, so it is
// safe to run over a user-supplied path. semgrep missing from PATH is itself a
// clear error (the scan could not have used the rule anyway).
func semgrepValidate(ctx context.Context, path string) error {
	bin := semgrepBinary()
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("cannot validate %s: semgrep is not installed", filepath.Base(path))
	}
	cmd := exec.CommandContext(ctx, bin, "--validate", "--config", path, "--metrics=off", "--quiet")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("validation of %s timed out", filepath.Base(path))
	}
	if err != nil {
		return fmt.Errorf("semgrep rejected %s: %s", filepath.Base(path), firstMeaningfulLine(out))
	}
	return nil
}

// firstMeaningfulLine extracts a short, human line from semgrep's validator
// output for an error message, skipping blank and banner lines.
func firstMeaningfulLine(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "┌") || strings.HasPrefix(s, "│") || strings.HasPrefix(s, "└") {
			continue
		}
		if len(s) > 200 {
			s = s[:200] + "…"
		}
		return s
	}
	return "invalid rule configuration"
}
