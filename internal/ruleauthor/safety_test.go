package ruleauthor

import (
	"strings"
	"testing"
)

// TestLintRuleAccepts: well-formed, specific rules pass with no blocking issue.
func TestLintRuleAccepts(t *testing.T) {
	good := []string{
		`rules:
  - id: py-eval
    languages: [python]
    severity: ERROR
    message: eval on a variable runs arbitrary code
    patterns:
      - pattern: eval($X)
      - pattern-not: eval("...")
`,
		`rules:
  - id: java-hardcoded-secret
    languages: [java]
    severity: ERROR
    message: hardcoded credential
    patterns:
      - pattern: String $V = "$LIT";
      - metavariable-regex:
          metavariable: $V
          regex: (?i).*(password|secret).*
`,
	}
	for i, g := range good {
		issues, ok := LintRule(g)
		if !ok {
			t.Errorf("good rule %d rejected: %+v", i, issues)
		}
	}
}

// TestLintRuleRejectsReDoS: nested-quantifier regexes are blocked.
func TestLintRuleRejectsReDoS(t *testing.T) {
	redos := []string{`(a+)+`, `(a*)*`, `(.*)+`, `([a-z]+)*`, `(\d+){2,}`, `(x+x+)+y`}
	for _, rx := range redos {
		rule := `rules:
  - id: redos
    languages: [python]
    severity: WARNING
    message: test
    patterns:
      - pattern: foo($X)
      - metavariable-regex:
          metavariable: $X
          regex: '` + rx + `'
`
		issues, ok := LintRule(rule)
		if ok {
			t.Errorf("ReDoS regex %q was accepted", rx)
		}
		if !hasBlocking(issues, "backtracking") {
			t.Errorf("ReDoS regex %q missing catastrophic-backtracking issue: %+v", rx, issues)
		}
	}
}

// TestLintRuleRejectsBroad: rules that match everything are blocked.
func TestLintRuleRejectsBroad(t *testing.T) {
	broad := []string{
		`rules:
  - id: all-code
    languages: [python]
    severity: INFO
    message: matches everything
    pattern: $X
`,
		`rules:
  - id: all-ellipsis
    languages: [go]
    severity: INFO
    message: matches everything
    pattern: "..."
`,
		`rules:
  - id: broad-regex
    languages: [python]
    severity: INFO
    message: broad regex
    patterns:
      - pattern: foo($X)
      - metavariable-regex:
          metavariable: $X
          regex: '.*'
`,
	}
	for i, b := range broad {
		if _, ok := LintRule(b); ok {
			t.Errorf("broad rule %d accepted", i)
		}
	}
}

// TestLintRuleRejectsMalformed: non-YAML, no rules list, missing required
// fields, and over-cap files are blocked with a clear message.
func TestLintRuleRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"not yaml":       "this: is: not: valid: yaml: at all:",
		"no rules":       "foo: bar\n",
		"empty":          "   ",
		"missing fields": "rules:\n  - id: x\n    pattern: foo()\n",
	}
	for name, rule := range cases {
		if _, ok := LintRule(rule); ok {
			t.Errorf("%s: accepted a malformed rule", name)
		}
	}
	// Too many rules.
	var b strings.Builder
	b.WriteString("rules:\n")
	for i := 0; i < MaxRuleCount+1; i++ {
		b.WriteString("  - id: r\n    languages: [python]\n    severity: INFO\n    message: m\n    pattern: foo($X)\n")
	}
	if _, ok := LintRule(b.String()); ok {
		t.Error("accepted a file exceeding the rule-count cap")
	}
}

func hasBlocking(issues []SafetyIssue, substr string) bool {
	for _, i := range issues {
		if i.Blocking && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}
