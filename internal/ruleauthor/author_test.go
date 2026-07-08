package ruleauthor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/llm"
)

func fakeClient(resp string) *llm.Fake {
	return &llm.Fake{NameStr: "fake/test", IsLocal: true, Respond: func(llm.Request) (string, error) { return resp, nil }}
}

// TestDraftRuleExtractsFencedYAML: a model reply with prose around a fenced
// block yields a ready draft, and the prompt carried the nonce markers.
func TestDraftRuleExtractsFencedYAML(t *testing.T) {
	resp := "Sure! Here is a rule:\n```yaml\n" + `rules:
  - id: py-eval
    languages: [python]
    severity: ERROR
    message: eval on a variable runs arbitrary code
    patterns:
      - pattern: eval($X)
      - pattern-not: eval("...")
` + "```\nHope that helps."
	client := fakeClient(resp)
	d, err := DraftRule(context.Background(), client, DraftRequest{Description: "flag eval on user input", Language: "python"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Ready {
		t.Errorf("draft not ready: %+v", d.Issues)
	}
	if !strings.Contains(d.Rule, "eval($X)") || strings.Contains(d.Rule, "```") {
		t.Errorf("rule not cleanly extracted: %q", d.Rule)
	}
	if d.Model != "fake/test" {
		t.Errorf("model label wrong: %q", d.Model)
	}
	// The prompt is a security boundary: the request text must be inside the
	// nonce markers, and the system prompt must carry the grammar knowledge.
	reqs := client.Requests()
	if len(reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(reqs))
	}
	if !strings.Contains(reqs[0].User, "UNTRUSTED-DATA-") || !strings.Contains(reqs[0].User, "flag eval on user input") {
		t.Errorf("request not marker-wrapped: %q", reqs[0].User)
	}
	if !strings.Contains(reqs[0].System, "semgrep rule") || !strings.Contains(reqs[0].System, "FEW-SHOT EXAMPLES") {
		t.Error("system prompt missing the grammar knowledge base")
	}
}

// TestDraftRuleUnsafeIsReturnedNotErrored: a parsed-but-unsafe rule comes back
// as a not-ready Draft carrying the blocking issue, so the human can fix it.
func TestDraftRuleUnsafeIsReturnedNotErrored(t *testing.T) {
	resp := "```yaml\n" + `rules:
  - id: bad
    languages: [python]
    severity: INFO
    message: matches everything
    pattern: $X
` + "```"
	d, err := DraftRule(context.Background(), fakeClient(resp), DraftRequest{Description: "x", Language: "python"}, time.Second)
	if err != nil {
		t.Fatalf("unsafe rule should not be a hard error: %v", err)
	}
	if d.Ready {
		t.Error("over-broad rule marked ready")
	}
	if len(d.Issues) == 0 {
		t.Error("no issues reported for an over-broad rule")
	}
}

// TestDraftRuleRejectsNoRule: model output with no rule block is an error.
func TestDraftRuleRejectsNoRule(t *testing.T) {
	if _, err := DraftRule(context.Background(), fakeClient("I cannot help with that."), DraftRequest{Description: "x", Language: "go"}, time.Second); err == nil {
		t.Error("expected an error when the model emits no rule")
	}
}

// TestDraftRuleEditModeCarriesExistingRule: an edit request puts the existing
// rule into the prompt under the markers.
func TestDraftRuleEditModeCarriesExistingRule(t *testing.T) {
	existing := "rules:\n  - id: old\n    languages: [go]\n    severity: INFO\n    message: m\n    pattern: foo()\n"
	client := fakeClient("```yaml\nrules:\n  - id: new\n    languages: [go]\n    severity: WARNING\n    message: revised\n    pattern: foo($X)\n```")
	_, err := DraftRule(context.Background(), client, DraftRequest{Description: "tighten it", Language: "go", ExistingRule: existing, Instruction: "match an argument"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u := client.Requests()[0].User
	if !strings.Contains(u, "existing_rule:") || !strings.Contains(u, "id: old") {
		t.Errorf("edit prompt missing the existing rule: %q", u)
	}
	if !strings.Contains(u, "revision_instruction: match an argument") {
		t.Errorf("edit prompt missing the instruction: %q", u)
	}
}
