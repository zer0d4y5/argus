package triage

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/leaky-hub/argus/internal/llm"
	"github.com/leaky-hub/argus/internal/model"
)

func explainFinding() model.Finding {
	return model.Finding{
		ID: "f1", Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
		RuleID: "python.sql-injection", Title: "SQL injection", Severity: model.SeverityHigh,
		Location: model.Location{
			File: "src/db.py", StartLine: 5, EndLine: 5,
			Snippet: &model.Snippet{StartLine: 3, Lines: []string{"def q(uid):", "  # build", "  cur.execute(f\"SELECT {uid}\")"}},
		},
	}
}

func TestExplainBoundaryAndValidation(t *testing.T) {
	fake := &llm.Fake{IsLocal: true, Respond: func(req llm.Request) (string, error) {
		return `{"explanation":"The query interpolates uid.","remediation":"Use parameters."}`, nil
	}}
	ex, err := Explain(context.Background(), fake, explainFinding(), false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Explanation == "" || ex.Remediation == "" || ex.Model != fake.Name() {
		t.Fatalf("explanation shape: %+v", ex)
	}

	reqs := fake.Requests()
	if len(reqs) != 1 {
		t.Fatal("expected one request")
	}
	// The stored snippet rides inside per-request random boundary markers and
	// the flagged line carries the >> marker; a hard output cap is set.
	marker := regexp.MustCompile(`<<<UNTRUSTED-DATA-[0-9a-f]{24}>>>`)
	if !marker.MatchString(reqs[0].User) {
		t.Error("user prompt lacks CSPRNG boundary markers")
	}
	if !strings.Contains(reqs[0].User, ">>    5 |") || !strings.Contains(reqs[0].User, "cur.execute") {
		t.Errorf("prompt lacks the marked stored snippet:\n%s", reqs[0].User)
	}
	if reqs[0].MaxTokens != explainMaxTokens || reqs[0].MaxTokens <= 0 {
		t.Errorf("MaxTokens = %d, want the hard cap", reqs[0].MaxTokens)
	}
}

func TestExplainSecretRules(t *testing.T) {
	secret := explainFinding()
	secret.Category = model.CategorySecret
	secret.Location.Snippet = nil // capture already refuses; belt and braces below

	// Cloud provider without opt-in: refused outright.
	cloud := &llm.Fake{IsLocal: false, Respond: func(llm.Request) (string, error) {
		return `{"explanation":"x"}`, nil
	}}
	if _, err := Explain(context.Background(), cloud, secret, false, time.Second); !errors.Is(err, ErrSecretCloud) {
		t.Fatalf("secret+cloud err = %v, want ErrSecretCloud", err)
	}

	// Local provider: metadata-only prompt, and even a lingering snippet on
	// the finding must not enter it.
	withSnippet := secret
	withSnippet.Location.Snippet = &model.Snippet{StartLine: 1, Lines: []string{"AWS_KEY=AKIAsecretvalue"}}
	local := &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) {
		return `{"explanation":"metadata only"}`, nil
	}}
	if _, err := Explain(context.Background(), local, withSnippet, false, time.Second); err != nil {
		t.Fatal(err)
	}
	req := local.Requests()[0]
	if strings.Contains(req.User, "AKIAsecretvalue") {
		t.Fatal("secret file content entered an explain prompt")
	}
	if !strings.Contains(req.User, "withheld") {
		t.Errorf("secret prompt should say context is withheld:\n%s", req.User)
	}
}

func TestExplainRejectsGarbageOutput(t *testing.T) {
	for _, out := range []string{"", "not json", `{"remediation":"only"}`, `{"explanation":""}`} {
		fake := &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) { return out, nil }}
		if _, err := Explain(context.Background(), fake, explainFinding(), false, time.Second); err == nil {
			t.Errorf("output %q accepted", out)
		}
	}
	// Control characters and unbounded length never reach the caller raw.
	long := strings.Repeat("A", 10000)
	fake := &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) {
		return `{"explanation":"line1\u0007bell ` + long + `"}`, nil
	}}
	ex, err := Explain(context.Background(), fake, explainFinding(), false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(ex.Explanation, 0x07) {
		t.Error("control character survived sanitization")
	}
	if len([]rune(ex.Explanation)) > maxExplanationRunes+1 {
		t.Errorf("explanation length %d exceeds cap", len([]rune(ex.Explanation)))
	}
}
