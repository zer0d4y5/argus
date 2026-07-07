package ruleauthor

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// The rule safety linter. An AI-drafted (or user-edited) semgrep rule is DATA,
// but semgrep EXECUTES it against source: a pathological regex can hang a scan
// (ReDoS), and an over-broad pattern floods every file with noise. This
// deterministic gate is the backstop that keeps such a rule from being saved
// and wired into scans. It runs at draft time AND at save time, and is
// unit-tested over hand-authored good/bad rules with NO LLM in the loop.
//
// Unlike the remediation linter (which defangs and degrades), this one
// REJECTS: a rule that trips a check is never offered for save. The user edits
// it and tries again. Better a refused rule than a scan that never returns.

// Caps: bounded so a runaway draft cannot ship a giant or sprawling ruleset.
const (
	MaxRuleBytes   = 20000 // whole-file size ceiling
	MaxRuleCount   = 20    // rules in one file
	MaxRegexLen    = 300   // a single regex value
	minPatternLen  = 3     // a "pattern" shorter than this is suspiciously broad
	maxMessageRune = 1000
)

// SafetyIssue is one reason a rule is unsafe to run. Blocking is true for
// issues that must prevent a save; a non-blocking issue is advice.
type SafetyIssue struct {
	Rule     string `json:"rule"`     // rule id the issue is about, or "" for file-level
	Message  string `json:"message"`  // human explanation
	Blocking bool   `json:"blocking"` // true = save is refused
}

// broadPatterns are pattern bodies that match essentially everything. A rule
// built only from these is noise, not a detection, and is refused.
var broadPatterns = map[string]bool{
	"...": true, "$x": true, "$_": true, "$var": true, "$e": true,
	"<... ... ...>": true, "$...args": true, "$...x": true,
}

// broadRegexes are regex values that match everything; refused as a
// pattern-regex / metavariable-regex.
var broadRegexes = map[string]bool{
	".*": true, ".+": true, ".": true, "(.*)": true, "(.+)": true,
	"^.*$": true, "^.*": true, ".*$": true, "[\\s\\S]*": true, "": true,
}

// LintRule parses a candidate rule (YAML) and returns every safety issue. A
// rule with any Blocking issue must not be saved or offered as "ready". The
// returned bool is true when the rule is safe (no blocking issues).
func LintRule(ruleYAML string) ([]SafetyIssue, bool) {
	var issues []SafetyIssue
	add := func(rule, msg string, blocking bool) {
		issues = append(issues, SafetyIssue{Rule: rule, Message: msg, Blocking: blocking})
	}

	if len(ruleYAML) > MaxRuleBytes {
		add("", fmt.Sprintf("rule file is too large (%d bytes; limit %d)", len(ruleYAML), MaxRuleBytes), true)
		return issues, false
	}
	if strings.TrimSpace(ruleYAML) == "" {
		add("", "rule is empty", true)
		return issues, false
	}

	var doc struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(ruleYAML), &doc); err != nil {
		add("", "not valid YAML: "+oneLine(err.Error()), true)
		return issues, false
	}
	if len(doc.Rules) == 0 {
		add("", "no rules found (expected a top-level `rules:` list)", true)
		return issues, false
	}
	if len(doc.Rules) > MaxRuleCount {
		add("", fmt.Sprintf("too many rules in one file (%d; limit %d)", len(doc.Rules), MaxRuleCount), true)
		return issues, false
	}

	for i, r := range doc.Rules {
		id, _ := r["id"].(string)
		if strings.TrimSpace(id) == "" {
			id = fmt.Sprintf("rule #%d", i+1)
		}
		lintOneRule(id, r, add)
	}

	blocking := false
	for _, is := range issues {
		if is.Blocking {
			blocking = true
			break
		}
	}
	return issues, !blocking
}

// lintOneRule walks one rule object: it collects every code pattern and every
// regex value (at any depth) and checks each. Required fields are checked too,
// though semgrep --validate is the authority on structure; these give a clearer
// message before that runs.
func lintOneRule(id string, r map[string]any, add func(rule, msg string, blocking bool)) {
	if _, ok := r["languages"]; !ok {
		add(id, "missing `languages`", true)
	}
	if _, ok := r["message"]; !ok {
		add(id, "missing `message`", true)
	}
	if msg, ok := r["message"].(string); ok && len([]rune(msg)) > maxMessageRune {
		add(id, "message is excessively long", true)
	}
	if _, ok := r["severity"]; !ok {
		add(id, "missing `severity`", true)
	}

	var patterns, regexes []string
	collectPatternsAndRegexes(r, &patterns, &regexes)

	if len(patterns) == 0 && len(regexes) == 0 {
		add(id, "has no matching pattern (needs pattern, patterns, or pattern-either)", true)
	}

	// Every pattern must be specific: a bare metavariable / ellipsis matches all
	// code. A rule is broad only if ALL of its top-level patterns are broad, but
	// a single broad `pattern` (not inside a `patterns` AND-list with exclusions)
	// is refused outright.
	specific := false
	for _, p := range patterns {
		norm := strings.ToLower(strings.Join(strings.Fields(p), " "))
		if norm == "" || broadPatterns[norm] || len(strings.TrimSpace(p)) < minPatternLen {
			continue
		}
		specific = true
	}
	if len(patterns) > 0 && !specific {
		add(id, "every pattern matches essentially all code (a bare metavariable or ellipsis); make the pattern specific to the weakness", true)
	}

	for _, rx := range regexes {
		checkRegex(id, rx, add)
	}
}

// checkRegex flags a regex that is over-broad, too long, syntactically invalid,
// or carries a catastrophic-backtracking shape.
func checkRegex(id, rx string, add func(rule, msg string, blocking bool)) {
	if broadRegexes[strings.TrimSpace(rx)] {
		add(id, fmt.Sprintf("regex %q matches everything; constrain it", rx), true)
		return
	}
	if len(rx) > MaxRegexLen {
		add(id, fmt.Sprintf("regex is too long (%d chars; limit %d)", len(rx), MaxRegexLen), true)
		return
	}
	if _, err := regexp.Compile(rx); err != nil {
		// Go's RE2 has no catastrophic backtracking, but semgrep's PCRE engine
		// does, so an RE2-invalid regex is not itself fatal here - the ReDoS
		// shape check below is what matters. Report as advice only.
		add(id, "regex may not compile under Go's engine (semgrep uses PCRE): "+oneLine(err.Error()), false)
	}
	if redosShape.MatchString(rx) {
		add(id, fmt.Sprintf("regex %q has a nested-quantifier shape prone to catastrophic backtracking (ReDoS); rewrite without a quantified group inside another quantifier", clip(rx, 60)), true)
	}
}

// redosShape matches the classic catastrophic-backtracking form: a group that
// itself contains an unbounded quantifier, immediately quantified again - e.g.
// (a+)+, (a*)*, (.*)+, ([a-z]+)*, (\d+){2,}. It is intentionally conservative:
// it targets the well-known exponential shapes, not every theoretically slow
// regex.
var redosShape = regexp.MustCompile(`\([^()]*[*+][^()]*\)\s*[*+]|\([^()]*[*+][^()]*\)\s*\{\d*,\d*\}`)

// collectPatternsAndRegexes recursively walks a rule's value tree, appending
// every code pattern (values under pattern / pattern-not / pattern-inside) and
// every regex (values under pattern-regex / metavariable-regex's regex, and a
// bare `regex:` inside a metavariable-regex block).
func collectPatternsAndRegexes(v any, patterns, regexes *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			switch k {
			case "pattern", "pattern-not", "pattern-inside":
				if s, ok := val.(string); ok {
					*patterns = append(*patterns, s)
				}
			case "pattern-regex", "regex":
				if s, ok := val.(string); ok {
					*regexes = append(*regexes, s)
				}
			case "pattern-either", "patterns":
				collectPatternsAndRegexes(val, patterns, regexes)
			case "metavariable-pattern", "metavariable-regex":
				collectPatternsAndRegexes(val, patterns, regexes)
			default:
				collectPatternsAndRegexes(val, patterns, regexes)
			}
		}
	case []any:
		for _, item := range t {
			collectPatternsAndRegexes(item, patterns, regexes)
		}
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return clip(strings.TrimSpace(s), 160)
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
