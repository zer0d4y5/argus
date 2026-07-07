package scanner

import (
	"context"
	"os/exec"
	"testing"
)

func TestLangExtForRuleTest(t *testing.T) {
	if ext, ok := LangExtForRuleTest("Python"); !ok || ext != ".py" {
		t.Errorf("python: (%q, %v)", ext, ok)
	}
	if _, ok := LangExtForRuleTest("cobol"); ok {
		t.Error("unsupported language reported supported")
	}
}

// TestTestRuleAgainstSnippet exercises the full validate+run loop over a good
// rule (matches and misses) and a malformed rule (reported invalid, not run).
func TestTestRuleAgainstSnippet(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the semgrep binary")
	}
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH")
	}
	rule := `rules:
  - id: py-eval
    languages: [python]
    severity: ERROR
    message: eval on a variable
    patterns:
      - pattern: eval($X)
      - pattern-not: eval("...")
`
	// Matches: eval on a variable.
	res, err := TestRuleAgainstSnippet(context.Background(), rule, "def f(x):\n    return eval(x)\n", "python")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || !res.Matched || len(res.Matches) == 0 {
		t.Fatalf("expected a match: %+v", res)
	}
	if res.Matches[0].Check != "py-eval" || res.Matches[0].StartLine != 2 {
		t.Errorf("match detail wrong: %+v", res.Matches[0])
	}
	// Misses: eval on a constant is excluded by pattern-not.
	res, err = TestRuleAgainstSnippet(context.Background(), rule, "x = eval(\"1+1\")\n", "python")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.Matched {
		t.Errorf("constant eval should not match: %+v", res)
	}
	// Malformed rule: reported invalid, never run.
	bad := "rules:\n  - id: broken\n    languages: [python]\n    message: no severity or pattern\n"
	res, err = TestRuleAgainstSnippet(context.Background(), bad, "x = 1\n", "python")
	if err != nil {
		t.Fatalf("malformed rule should be a clean invalid result, not an error: %v", err)
	}
	if res.Valid {
		t.Error("malformed rule reported valid")
	}
	if res.ValidationError == "" {
		t.Error("no validation error message")
	}
}
