// Package ruleauthor is the AI-assisted semgrep-rule authoring seam: a user
// describes a detection in natural language (or pastes a rule to edit), the
// LOCAL LLM drafts a rule, and this package extracts, bounds, and safety-lints
// it. The result is always a DRAFT: never validated-as-runnable here, never
// saved. The caller (the console) runs semgrep --validate, lets the human test
// it against a pasted snippet and edit it freely, and only saves it as a custom
// local rule (Workstream C) on explicit human confirmation.
//
// Security posture mirrors internal/triage: prompt assembly wraps untrusted
// input in per-request CSPRNG markers (prompt.go); output is isolated and
// bounded (parse.go); a deterministic linter rejects ReDoS and over-broad
// rules with no LLM in the loop (safety.go). The LLM never decides a rule is
// safe and never authors anything that runs without human confirmation.
package ruleauthor

import (
	"context"
	"fmt"
	"time"

	"github.com/leaky-hub/argus/internal/llm"
)

// Draft is a candidate rule plus the safety issues found in it. Ready is true
// only when the draft parsed and carries no blocking safety issue; even then
// the human must validate and confirm before it is saved.
type Draft struct {
	Rule   string        `json:"rule"`   // the rule YAML, for display and editing
	Issues []SafetyIssue `json:"issues"` // safety-linter findings (may be advisory)
	Ready  bool          `json:"ready"`  // parsed + no blocking issue
	Model  string        `json:"model"`  // provider/model that produced it, for the UI label
}

// DraftRule asks the client to draft or revise a rule for req, then extracts,
// bounds, and safety-lints the output. A provider or parse failure is an honest
// error (like the other seams). A parsed-but-unsafe rule is NOT an error: it is
// returned as a Draft with Ready=false and the blocking issues, so the human
// sees what to fix.
func DraftRule(ctx context.Context, client llm.Client, req DraftRequest, timeout time.Duration) (Draft, error) {
	nonce, err := newNonce()
	if err != nil {
		return Draft{}, fmt.Errorf("no randomness source")
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := client.Complete(reqCtx, llm.Request{
		System:      systemPrompt(nonce),
		User:        buildUserPrompt(req, nonce),
		MaxTokens:   draftMaxTokens,
		Temperature: 0,
		// The output is YAML in a fence, not JSON, so ForceJSON stays off.
	})
	if err != nil {
		return Draft{}, fmt.Errorf("rule drafting failed: %.120s", err.Error())
	}
	rule, err := extractRule(raw)
	if err != nil {
		return Draft{}, err
	}
	issues, safe := LintRule(rule)
	return Draft{Rule: rule, Issues: issues, Ready: safe, Model: client.Name()}, nil
}
