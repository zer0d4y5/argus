// Package model defines the unified findings schema — the single contract
// every scanner adapter maps into and every reporter reads from.
// The schema is versioned; see docs/findings-model.md for the field reference
// and compatibility rules. Bump SchemaVersion on any breaking field change.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// SchemaVersion identifies the findings-model revision embedded in reports.
// 1.1.0: added optional Triage.Confidence (Phase 2 AI triage).
// 1.2.0: ComplianceControls is now populated ("<FRAMEWORK>:<control-id>"
// values, Phase 5 compliance mapping). Additive; the field existed empty
// since 1.0.0.
// 1.3.0: added optional RiskSignals (risk scoring v2 context evidence).
// Additive; see docs/risk-scoring.md.
// 1.4.0: added optional Location.Snippet (captured code frame, Scan Studio).
// Additive; capture rules in docs/findings-model.md and docs/console-ops.md S4.
// 2.0.0: severity semantics changed (MAJOR) — Severity is now the banded
// deterministic risk score (SeverityForScore, canonical table in
// docs/risk-scoring.md); the tool-normalized value moved to the new
// ToolSeverity field. Documents ≤1.4.0 stay readable (their severity is
// tool-normalized, displayed as-is, never re-banded); fingerprints never
// contained severity or title, so run deltas keep working. Migration note in
// docs/findings-model.md.
// 2.1.0: added the CLOUD category and optional Location.Resource (cloud
// resource UID/ARN — cloud posture findings have no file). Additive. The
// fingerprint algorithm stays v1: its file slot now takes
// firstNonEmpty(location.file, location.resource), which is byte-identical
// for every pre-2.1.0 finding (resource empty) and gives cloud findings a
// stable cross-run identity. Migration note in docs/findings-model.md.
const SchemaVersion = "2.1.0"

// Finding categories. String-typed (not iota) because they appear verbatim in
// JSON/SARIF output and in config files.
const (
	CategorySAST   = "SAST"   // static code analysis
	CategorySecret = "SECRET" // leaked credentials
	CategorySCA    = "SCA"    // vulnerable dependencies
	CategoryIaC    = "IAC"    // infrastructure-as-code (Phase 3)
	CategoryDAST   = "DAST"   // dynamic scanning (Phase 5)
	CategoryCloud  = "CLOUD"  // cloud security posture (schema 2.1.0)
)

// RawFinding is what an adapter emits: native tool data mapped to common
// fields, with the tool's ORIGINAL severity string left intact
// (normalization happens later, in Normalize).
type RawFinding struct {
	Tool        string // "semgrep" | "gitleaks" | "trivy"
	Category    string // CategorySAST | CategorySecret | CategorySCA | ...
	RuleID      string // check_id / RuleID / VulnerabilityID
	Title       string
	Description string
	RawSeverity string            // tool's native severity string, verbatim
	Confidence  string            // tool-reported confidence ("" if none)
	File        string            // path relative to scan root ("" if N/A)
	Resource    string            // cloud resource UID/ARN ("" if N/A, schema 2.1.0)
	StartLine   int               // 0 if N/A
	EndLine     int               // 0 if N/A
	CWEs        []string          // e.g. ["CWE-89"]
	CVE         string            // "" if N/A
	Package     string            // "" if N/A (SCA: name@version)
	Remediation string            // "" if unknown
	Meta        map[string]string // any extra tool fields worth keeping
	RawPayload  json.RawMessage   // the original per-result object, verbatim
}

// Location pins a finding to code, a package manifest, a cloud resource, or
// (later) a URL.
type Location struct {
	File string `json:"file,omitempty"`
	// Resource is the cloud resource UID/ARN a CLOUD finding is about (schema
	// 2.1.0). Cloud posture findings have no file; this is their place-slot,
	// including in the fingerprint (see Fingerprint).
	Resource  string `json:"resource,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	URL       string `json:"url,omitempty"` // DAST findings (Phase 5)
	// Snippet is the captured code frame (schema 1.4.0), set post-pipeline by
	// internal/snippet — never by adapters or Normalize, and never part of the
	// fingerprint. SECRET findings never carry one.
	Snippet *Snippet `json:"snippet,omitempty"`
}

// Snippet is a bounded frame of source lines around a finding. Lines are raw
// file text: hostile data, rendered escaped-only, capture bounds enforced by
// internal/snippet (docs/console-ops.md S4).
type Snippet struct {
	StartLine int      `json:"startLine"` // 1-based line number of Lines[0]
	Lines     []string `json:"lines"`
}

// Triage verdict values. String-typed: they appear verbatim in reports.
const (
	VerdictTruePositive  = "true-positive"
	VerdictFalsePositive = "false-positive"
	VerdictUncertain     = "uncertain"
)

// Triage is the AI-triage enrichment slot (Phase 2). Wired but optional.
// Confidence is the model's self-reported certainty in [0,1], validated and
// clamped at parse time; it bounds the risk-score adjustment
// (see docs/risk-scoring.md).
type Triage struct {
	Verdict    string  `json:"verdict"` // "true-positive" | "false-positive" | "uncertain"
	Confidence float64 `json:"confidence,omitempty"`
	Rationale  string  `json:"rationale,omitempty"`
	Model      string  `json:"model,omitempty"`
}

// RiskSignal is one named context-signal contribution to the risk score
// (stage 2 of docs/risk-scoring.md). Code and Note are fixed strings from the
// reviewed signal tables in internal/risk — never model output, never scanned
// file content. Deltas sum (with the synthetic cap/ceiling rows) to exactly
// the applied stage-2 change, so the score is evidence, not assertion.
type RiskSignal struct {
	Code  string  `json:"code"`
	Delta float64 `json:"delta"`
	Note  string  `json:"note,omitempty"`
}

// Finding is the normalized, enriched record. Everything downstream of the
// adapters — correlation, gating, every reporter — operates on this type only.
type Finding struct {
	ID          string   `json:"id"`              // stable fingerprint, see Fingerprint
	Tool        string   `json:"tool"`            // primary reporting tool
	Tools       []string `json:"tools,omitempty"` // all tools after correlation (>=1 entries)
	Category    string   `json:"category"`
	RuleID      string   `json:"ruleId"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	// Severity is the banded deterministic risk score (schema 2.0.0): set by
	// the pipeline via SeverityForScore after risk scoring, LLM-free by
	// construction. Normalize seeds it with the tool-normalized value so a
	// finding that never reaches risk scoring still has an honest severity.
	Severity Severity `json:"severity"`
	// ToolSeverity is what NormalizeSeverity produced (schema 2.0.0): the
	// stage-1 risk input and "tool said" audit trail. A pointer so documents
	// older than 2.0.0 — which have no such field — round-trip as absent
	// instead of a fabricated "info".
	ToolSeverity *Severity `json:"toolSeverity,omitempty"`
	RawSeverity  string    `json:"rawSeverity,omitempty"` // native string, for audit
	Confidence   string    `json:"confidence,omitempty"`
	Location     Location  `json:"location"`
	Package      string    `json:"package,omitempty"`
	CWEs         []string  `json:"cwes,omitempty"`
	CVE          string    `json:"cve,omitempty"`
	Remediation  string    `json:"remediation,omitempty"`

	Meta       map[string]string `json:"meta,omitempty"`
	RawPayload json.RawMessage   `json:"rawPayload,omitempty"`

	// Enrichment slots, populated by later phases.
	ComplianceControls []string `json:"complianceControls,omitempty"` // Phase 5: "<FRAMEWORK>:<control-id>" values, e.g. "ASVS:V5.3.4"
	Triage             *Triage  `json:"triage,omitempty"`             // Phase 2
	RiskScore          *float64 `json:"riskScore,omitempty"`          // Phase 2
	// RiskSignals is the stage-2 context evidence behind RiskScore (schema
	// 1.3.0, risk v2). Empty when no context signal fired.
	RiskSignals []RiskSignal `json:"riskSignals,omitempty"`
}

// Fingerprint computes the stable identity of a finding. Two runs over the
// same code must produce the same ID for the same issue, so the hash covers
// only identity fields — never description text, severity, or raw payloads,
// which tools reword between versions. The tool name IS included: cross-tool
// merging is correlation's job (it uses correlation keys, not the ID).
//
// The file slot takes firstNonEmpty(location.file, location.resource) —
// schema 2.1.0's documented overload of that hash position. Every pre-cloud
// finding has an empty resource, so its hash input is byte-identical to what
// algorithm v1 always produced (no version bump needed); a CLOUD finding,
// which has no file, gets its stable place from the resource UID/ARN, so run
// deltas work for cloud runs unchanged. Both properties are pinned by test.
func Fingerprint(f Finding) string {
	place := f.Location.File
	if place == "" {
		place = f.Location.Resource
	}
	h := sha256.New()
	for _, part := range []string{
		"v1", // fingerprint algorithm version, independent of SchemaVersion
		f.Tool,
		f.Category,
		f.RuleID,
		place,
		strconv.Itoa(f.Location.StartLine),
		f.Package,
		f.CVE,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0}) // field separator so "a"+"bc" != "ab"+"c"
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// titleMaxRunes bounds every finding title. Titles derive from tool rule
// messages — repo-adjacent hostile data — and render in reports, prompts and
// the console, so they pass through SanitizeTitle unconditionally.
const titleMaxRunes = 120

// ansiSequence matches ANSI CSI escape sequences (e.g. color codes). Dropping
// only the ESC control byte would leave visible "[31m" garbage in a title.
var ansiSequence = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// SanitizeTitle strips control characters and ANSI escape sequences,
// collapses whitespace runs, and caps the result at titleMaxRunes runes
// (ellipsis marks truncation). Deterministic; the single choke point every
// title passes through in Normalize regardless of which adapter produced it.
func SanitizeTitle(s string) string {
	if strings.ContainsRune(s, '\x1b') {
		s = ansiSequence.ReplaceAllString(s, "")
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = true
		case unicode.IsControl(r) || r == unicode.ReplacementChar:
			// dropped: control chars have no business in a title
		default:
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		}
	}
	out := b.String()
	if runes := []rune(out); len(runes) > titleMaxRunes {
		out = string(runes[:titleMaxRunes-1]) + "…"
	}
	return out
}

// HumanizeRuleID turns a rule identifier into a readable fallback title when
// a tool provides none: the last dot/slash segment, dash/underscore-split,
// sentence-cased — `python.flask.tainted-sql-string` → "Tainted sql string".
// Identifier-shaped IDs with no lowercase letters (CVE-2020-14343, DS-0031,
// CKV_AWS_20) stay verbatim: mangling them loses meaning. Deterministic,
// never LLM.
func HumanizeRuleID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	seg := id
	if i := strings.LastIndexAny(seg, "./"); i >= 0 && i+1 < len(seg) {
		seg = seg[i+1:]
	}
	if !strings.ContainsFunc(seg, func(r rune) bool { return r >= 'a' && r <= 'z' }) {
		return seg
	}
	words := strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' })
	if len(words) == 0 {
		return seg
	}
	out := strings.Join(words, " ")
	r := []rune(out)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// Normalize converts adapter output into normalized findings: severity
// mapping, fingerprinting, and defensive cleanup. This is the only place a
// RawFinding becomes a Finding.
//
// Quality floor (schema 2.0.0): every finding leaves here with a non-empty,
// sanitized, deterministic title (adapter title → humanized rule ID → tool
// name) and a non-empty description (falls back to the title). Remediation
// is NOT floored: when a tool provides nothing, empty is the honest value —
// inventing remediation text is out of scope by design.
func Normalize(raws []RawFinding) []Finding {
	findings := make([]Finding, 0, len(raws))
	for _, r := range raws {
		toolSev := NormalizeSeverity(r.Tool, r.RawSeverity)
		title := SanitizeTitle(firstNonEmpty(r.Title, HumanizeRuleID(r.RuleID), r.Tool+" finding"))
		f := Finding{
			Tool:         r.Tool,
			Tools:        []string{r.Tool},
			Category:     r.Category,
			RuleID:       r.RuleID,
			Title:        title,
			Description:  firstNonEmpty(r.Description, title),
			Severity:     toolSev,
			ToolSeverity: &toolSev,
			RawSeverity:  r.RawSeverity,
			Confidence:   r.Confidence,
			Location: Location{
				File:      filepathToSlash(r.File),
				Resource:  strings.TrimSpace(r.Resource),
				StartLine: maxInt(r.StartLine, 0),
				EndLine:   maxInt(r.EndLine, 0),
			},
			Package:     r.Package,
			CWEs:        normalizeCWEs(r.CWEs),
			CVE:         strings.TrimSpace(r.CVE),
			Remediation: r.Remediation,
			Meta:        r.Meta,
			RawPayload:  r.RawPayload,
		}
		if f.Location.EndLine < f.Location.StartLine {
			f.Location.EndLine = f.Location.StartLine
		}
		f.ID = Fingerprint(f)
		findings = append(findings, f)
	}
	return findings
}

// Summary is the severity/category/tool rollup embedded in reports.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
	ByCategory map[string]int `json:"byCategory"`
	ByTool     map[string]int `json:"byTool"`
}

func Summarize(findings []Finding) Summary {
	s := Summary{
		Total:      len(findings),
		BySeverity: map[string]int{},
		ByCategory: map[string]int{},
		ByTool:     map[string]int{},
	}
	for _, f := range findings {
		s.BySeverity[f.Severity.String()]++
		s.ByCategory[f.Category]++
		for _, t := range f.Tools {
			s.ByTool[t]++
		}
	}
	return s
}

// Sort orders findings deterministically: severity desc, then category, tool,
// file, line, rule. Reporters rely on this for stable, diffable output.
func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		// Cloud findings have no file; the resource UID keeps two resources
		// failing the same check deterministically ordered. Empty for every
		// non-cloud finding, so pre-2.1.0 ordering is untouched.
		if a.Location.Resource != b.Location.Resource {
			return a.Location.Resource < b.Location.Resource
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
}

// normalizeCWEs uppercases, prefixes bare numbers with "CWE-", dedups, and
// sorts, so "89", "cwe-89", and "CWE-89" all correlate.
func normalizeCWEs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		// Semgrep style: "CWE-89: SQL Injection ..." — keep the ID only.
		if idx := strings.IndexByte(c, ':'); idx > 0 {
			c = strings.TrimSpace(c[:idx])
		}
		if !strings.HasPrefix(c, "CWE-") {
			if _, err := strconv.Atoi(c); err == nil {
				c = "CWE-" + c
			}
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func filepathToSlash(p string) string { return strings.ReplaceAll(p, "\\", "/") }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
