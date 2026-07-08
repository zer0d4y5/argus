package server

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/llm"
)

const goodRuleYAML = `rules:
  - id: py-eval
    languages: [python]
    severity: ERROR
    message: eval on a variable runs arbitrary code
    patterns:
      - pattern: eval($X)
      - pattern-not: eval("...")
`

// fakeRuleLLM injects an LLM that returns a fenced rule.
func fakeRuleLLM(f *consoleFixture, rule string) {
	f.srv.llmFactory = func(config.Config) llm.Client {
		return &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) {
			return "```yaml\n" + rule + "```", nil
		}}
	}
}

// TestDraftRuleEndpoint: an admin drafts a rule; the LLM output is extracted,
// safety-linted, and returned ready. An operator is refused.
func TestDraftRuleEndpoint(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	fakeRuleLLM(f, goodRuleYAML)

	if rec := f.do("POST", "/api/admin/rules/draft", `{"description":"flag eval on user input","language":"python"}`, oper); rec.Code != 403 {
		t.Errorf("operator draft = %d, want 403", rec.Code)
	}
	rec := f.do("POST", "/api/admin/rules/draft", `{"description":"flag eval on user input","language":"python"}`, admin)
	if rec.Code != 200 {
		t.Fatalf("draft: %d %s", rec.Code, rec.Body.String())
	}
	var d struct {
		Rule  string
		Ready bool
		Model string
	}
	json.Unmarshal(rec.Body.Bytes(), &d)
	if !d.Ready || !strings.Contains(d.Rule, "eval($X)") || strings.Contains(d.Rule, "```") {
		t.Errorf("draft wrong: %+v", d)
	}
}

// TestDraftRuleUnsafeReturned: an over-broad drafted rule comes back not-ready
// with issues, HTTP 200 (the human sees what to fix), never an error.
func TestDraftRuleUnsafeReturned(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	fakeRuleLLM(f, "rules:\n  - id: broad\n    languages: [python]\n    severity: INFO\n    message: all\n    pattern: $X\n")
	rec := f.do("POST", "/api/admin/rules/draft", `{"description":"x","language":"python"}`, admin)
	if rec.Code != 200 {
		t.Fatalf("draft: %d %s", rec.Code, rec.Body.String())
	}
	var d struct {
		Ready  bool
		Issues []struct{ Blocking bool }
	}
	json.Unmarshal(rec.Body.Bytes(), &d)
	if d.Ready || len(d.Issues) == 0 {
		t.Errorf("over-broad rule should be not-ready with issues: %+v", d)
	}
}

// TestSaveRuleLifecycle: save validates + lints, writes the file, activates it
// in the rulesets; list shows it active; delete removes both file and ruleset
// entry. Needs semgrep for the save-time validation.
func TestSaveRuleLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("save validates with semgrep")
	}
	if !semgrepAvailable() {
		t.Skip("semgrep not on PATH")
	}
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	// A hostile name cannot traverse out of the rules dir.
	if rec := f.do("POST", "/api/admin/rules", `{"name":"../evil","rule":"rules: []"}`, admin); rec.Code != 400 {
		t.Errorf("path-traversal name = %d, want 400", rec.Code)
	}
	// An unsafe rule is refused before it touches disk.
	if rec := f.do("POST", "/api/admin/rules", `{"name":"broad","rule":"rules:\n  - id: b\n    languages: [python]\n    severity: INFO\n    message: m\n    pattern: $X\n"}`, admin); rec.Code != 400 {
		t.Errorf("unsafe rule save = %d, want 400", rec.Code)
	}

	body, _ := json.Marshal(map[string]any{"name": "no-eval", "rule": goodRuleYAML})
	rec := f.do("POST", "/api/admin/rules", string(body), admin)
	if rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	// The file exists and the ruleset now references it (activated).
	if _, err := os.Stat(filepath.Join(f.dir, ".appsec", "rules", "no-eval.yml")); err != nil {
		t.Errorf("rule file not written: %v", err)
	}
	cfg := f.srv.effectiveConfig(f.dir)
	if !sliceHas(cfg.SemgrepRules, ".appsec/rules/no-eval.yml") {
		t.Errorf("saved rule not activated in rulesets: %v", cfg.SemgrepRules)
	}

	// List shows it active.
	rec = f.do("GET", "/api/admin/rules", "", admin)
	var list struct {
		Rules []struct {
			Name   string
			Active bool
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Rules) != 1 || list.Rules[0].Name != "no-eval" || !list.Rules[0].Active {
		t.Fatalf("list wrong: %+v", list.Rules)
	}

	// Delete removes the file and the ruleset entry.
	rec = f.do("DELETE", "/api/admin/rules/no-eval", "", admin)
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(f.dir, ".appsec", "rules", "no-eval.yml")); !os.IsNotExist(err) {
		t.Error("rule file survived delete")
	}
	cfg = f.srv.effectiveConfig(f.dir)
	if sliceHas(cfg.SemgrepRules, ".appsec/rules/no-eval.yml") {
		t.Errorf("deleted rule still in rulesets: %v", cfg.SemgrepRules)
	}
}

// TestTestRuleEndpoint: safety lint always runs; the snippet run reports a
// match. Needs semgrep.
func TestTestRuleEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("runs semgrep")
	}
	if !semgrepAvailable() {
		t.Skip("semgrep not on PATH")
	}
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	body, _ := json.Marshal(map[string]any{"rule": goodRuleYAML, "snippet": "def f(x):\n    return eval(x)\n", "language": "python"})
	rec := f.do("POST", "/api/admin/rules/test", string(body), admin)
	if rec.Code != 200 {
		t.Fatalf("test: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Safe    bool
		Valid   bool
		Matched bool
		Matches []struct{ StartLine int }
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Safe || !resp.Valid || !resp.Matched || len(resp.Matches) == 0 {
		t.Errorf("test result wrong: %+v", resp)
	}
}

func semgrepAvailable() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}
