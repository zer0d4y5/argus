// Package correlate dedups and merges findings that describe the same
// underlying issue. Correlation is intentionally conservative: merging two
// DIFFERENT issues silently drops a finding, which is the worst failure mode
// a security tool can have. When in doubt, keep findings separate.
package correlate

import (
	"sort"
	"strconv"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// Correlate collapses duplicate findings and returns the merged, sorted set.
// Two findings correlate only when they are the same class of issue at the
// same place:
//
//   - SCA: same CVE/advisory in the same package (cross-tool: two SCA
//     scanners reporting CVE-2023-1234 in lodash@4.17.4 are one finding).
//   - Code findings (SAST/SECRET/IAC): same file, overlapping line range,
//     and either the same rule ID or a shared CWE. Same-category only —
//     a secret and a SAST hit on one line are different issues.
//   - SAST noise collapse: the SAME tool flagging the same weakness (shared
//     CWE) at an overlapping range via DIFFERENT rule IDs is one finding —
//     the dominant duplicate shape of wide semgrep profiles, where three
//     packs each carry a variant of the same rule. Collapse, not
//     suppression: the survivor unions the evidence and records every
//     absorbed rule ID in Meta["alsoRuleIds"]. SAST only — a second
//     gitleaks rule is a different credential claim, and distinct IaC/CLOUD
//     checks on one resource are distinct controls even when CWEs collide.
//
// Merging never discards data: severities take the maximum, CWE sets union,
// and every contributing tool is recorded in Tools.
func Correlate(findings []model.Finding) []model.Finding {
	var out []model.Finding
	byKey := map[string]int{} // exact correlation key -> index in out

	for _, f := range findings {
		if idx, ok := byKey[exactKey(f)]; ok {
			out[idx] = merge(out[idx], f)
			continue
		}
		// Fuzzy pass for code findings: overlapping range + shared CWE.
		if f.Location.File != "" {
			if idx, ok := findOverlap(out, f); ok {
				out[idx] = merge(out[idx], f)
				continue
			}
			if idx, ok := findSameToolDup(out, f); ok {
				out[idx] = collapse(out[idx], f)
				continue
			}
		}
		byKey[exactKey(f)] = len(out)
		out = append(out, f)
	}

	model.Sort(out)
	return out
}

// exactKey is the strict identity used for exact duplicates.
func exactKey(f model.Finding) string {
	if f.Category == model.CategorySCA && f.CVE != "" {
		// Advisory + package identifies an SCA finding regardless of tool.
		return strings.Join([]string{f.Category, f.CVE, f.Package}, "\x00")
	}
	// The place slot takes file, falling back to the cloud resource UID/ARN —
	// the same overload model.Fingerprint uses. Cloud findings have no file, so
	// keying on file alone collapsed every failure of one prowler check across
	// different resources into a single finding.
	place := f.Location.File
	if place == "" {
		place = f.Location.Resource
	}
	return strings.Join([]string{
		f.Category,
		f.RuleID,
		place,
		strconv.Itoa(f.Location.StartLine),
	}, "\x00")
}

// findOverlap looks for an existing finding of the same category in the same
// file with an overlapping line range and a shared CWE. Rule IDs differ
// across tools, so CWE overlap is the cross-tool signal.
func findOverlap(existing []model.Finding, f model.Finding) (int, bool) {
	if len(f.CWEs) == 0 {
		return 0, false
	}
	for i, e := range existing {
		if e.Category != f.Category || e.Location.File != f.Location.File {
			continue
		}
		if e.Tool == f.Tool {
			// Same tool reporting distinct rules is two real findings.
			continue
		}
		if !rangesOverlap(e.Location, f.Location) {
			continue
		}
		if sharesCWE(e.CWEs, f.CWEs) {
			return i, true
		}
	}
	return 0, false
}

// findSameToolDup looks for an existing SAST finding from the same tool in
// the same file with an overlapping range, a shared CWE, and a DIFFERENT rule
// ID — the same-tool duplicate shape wide profiles produce. Every condition
// is required; when any is absent the findings are (or could be) different
// issues and stay separate.
func findSameToolDup(existing []model.Finding, f model.Finding) (int, bool) {
	if f.Category != model.CategorySAST || len(f.CWEs) == 0 {
		return 0, false
	}
	for i, e := range existing {
		if e.Category != model.CategorySAST ||
			e.Tool != f.Tool ||
			e.Location.File != f.Location.File ||
			e.RuleID == f.RuleID {
			continue
		}
		if !rangesOverlap(e.Location, f.Location) {
			continue
		}
		if sharesCWE(e.CWEs, f.CWEs) {
			return i, true
		}
	}
	return 0, false
}

// collapse folds a same-tool duplicate into one finding. The survivor is the
// finding with the most specific title (longest sanitized title; rule ID as
// the deterministic tie-break) and keeps its identity — rule ID, fingerprint,
// title — so run deltas stay continuous for the surviving finding. The other
// finding's rule ID is recorded in Meta["alsoRuleIds"] (sorted,
// comma-joined): absorbed, never hidden. Severity/CWEs/tools union exactly
// like a cross-tool merge.
func collapse(a, b model.Finding) model.Finding {
	survivor, absorbed := a, b
	if len([]rune(b.Title)) > len([]rune(a.Title)) ||
		(len([]rune(b.Title)) == len([]rune(a.Title)) && b.RuleID < a.RuleID) {
		survivor, absorbed = b, a
	}
	merged := merge(survivor, absorbed)
	merged.Meta = withAlsoRuleIDs(merged.Meta, survivor.RuleID, absorbed.RuleID, absorbed.Meta["alsoRuleIds"])
	return merged
}

// withAlsoRuleIDs returns a copy of meta with the absorbed rule IDs folded
// into "alsoRuleIds" (sorted, comma-joined, deduplicated, survivor's own rule
// ID excluded). Copy-on-write: adapter Meta maps are shared with RawFinding.
func withAlsoRuleIDs(meta map[string]string, survivorRuleID string, absorbed ...string) map[string]string {
	set := map[string]bool{}
	add := func(csv string) {
		for _, id := range strings.Split(csv, ",") {
			if id = strings.TrimSpace(id); id != "" && id != survivorRuleID {
				set[id] = true
			}
		}
	}
	add(meta["alsoRuleIds"])
	for _, id := range absorbed {
		add(id)
	}
	if len(set) == 0 {
		return meta
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make(map[string]string, len(meta)+1)
	for k, v := range meta {
		out[k] = v
	}
	out["alsoRuleIds"] = strings.Join(ids, ",")
	return out
}

func rangesOverlap(a, b model.Location) bool {
	if a.StartLine == 0 || b.StartLine == 0 {
		return false // no line info: never fuzzy-merge
	}
	aEnd, bEnd := a.EndLine, b.EndLine
	if aEnd < a.StartLine {
		aEnd = a.StartLine
	}
	if bEnd < b.StartLine {
		bEnd = b.StartLine
	}
	return a.StartLine <= bEnd && b.StartLine <= aEnd
}

func sharesCWE(a, b []string) bool {
	set := map[string]bool{}
	for _, c := range a {
		set[c] = true
	}
	for _, c := range b {
		if set[c] {
			return true
		}
	}
	return false
}

// merge folds src into dst. dst stays the primary record; nothing that could
// change triage outcome (severity, CWEs, tools) is lost.
func merge(dst, src model.Finding) model.Finding {
	if src.Severity > dst.Severity {
		dst.Severity = src.Severity
		dst.RawSeverity = src.RawSeverity
		// Correlation runs pre-risk, where Severity == ToolSeverity; keeping
		// both means the max also drives the stage-1 risk baseline.
		dst.ToolSeverity = src.ToolSeverity
	}
	dst.Tools = unionStrings(dst.Tools, src.Tools)
	dst.CWEs = unionStrings(dst.CWEs, src.CWEs)
	if dst.CVE == "" {
		dst.CVE = src.CVE
	}
	if dst.Description == "" {
		dst.Description = src.Description
	}
	if dst.Remediation == "" {
		dst.Remediation = src.Remediation
	}
	// Widen the location to cover both reports.
	if src.Location.StartLine > 0 &&
		(dst.Location.StartLine == 0 || src.Location.StartLine < dst.Location.StartLine) {
		dst.Location.StartLine = src.Location.StartLine
	}
	if src.Location.EndLine > dst.Location.EndLine {
		dst.Location.EndLine = src.Location.EndLine
	}
	return dst
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
