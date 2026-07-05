package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
)

// Gitleaks implements the Adapter interface for the gitleaks secret scanner.
type Gitleaks struct{}

// Name returns the tool name.
func (g *Gitleaks) Name() string {
	return "gitleaks"
}

// Category returns the finding category.
func (g *Gitleaks) Category() string {
	return model.CategorySecret
}

// Available checks if gitleaks is installed on the PATH.
func (g *Gitleaks) Available() bool {
	return toolOnPath("gitleaks")
}

// Scan executes gitleaks and returns normalized raw findings: always the
// worktree pass (--no-git), plus — when the target directory is a git
// repository — a history pass over the commits (schema 2.0.0, locked
// decision 5). Secrets found ONLY in history are labeled meta.gitHistory
// (with the commit hash) because the fix is rotation, not a code edit;
// shallow workspaces have a single commit of history and say so. Both passes
// share the same --redact + re-scrub pipeline: history scanning must never
// become a secret-exfiltration path into run files.
func (g *Gitleaks) Scan(ctx context.Context, target string) ([]model.RawFinding, error) {
	worktree, err := g.detect(ctx, target, false)
	if err != nil {
		return nil, err
	}
	if !GitHistoryEligible(target) {
		return worktree, nil
	}
	history, err := g.detect(ctx, target, true)
	if err != nil {
		// History is additive enrichment: a repository whose history gitleaks
		// cannot walk (corrupt objects, exotic packfiles) must not lose its
		// worktree findings. Coverage accounting reports history mode per run.
		return worktree, nil
	}
	return mergeGitHistory(worktree, history, GitShallow(target)), nil
}

// detect runs one gitleaks pass. The JSON report goes to a temp file (not
// /dev/stdout, which gitleaks cannot always open) that is removed before
// returning.
func (g *Gitleaks) detect(ctx context.Context, target string, gitMode bool) ([]model.RawFinding, error) {
	reportFile, err := os.CreateTemp("", "appsec-gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("gitleaks scan: temp report: %w", err)
	}
	reportPath := reportFile.Name()
	reportFile.Close()
	defer os.Remove(reportPath)

	args := []string{
		"detect",
		"--source", target,
	}
	if !gitMode {
		args = append(args, "--no-git")
	}
	args = append(args,
		"--report-format", "json",
		"--report-path", reportPath,
		"--redact",
		"--exit-code", "0",
	)

	if _, err := runJSON(ctx, "gitleaks", args...); err != nil {
		return nil, fmt.Errorf("gitleaks scan: %w", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("gitleaks scan: read report: %w", err)
	}
	return parseGitleaks(data)
}

// GitHistoryEligible: history mode runs when the scan target is a directory
// containing .git (a dir entry for normal repos, a file for linked
// worktrees). File targets and plain directories scan the worktree only.
// Exported for the coverage accounting, which reports the same facts.
func GitHistoryEligible(target string) bool {
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		return false
	}
	_, err := os.Stat(filepath.Join(target, ".git"))
	return err == nil
}

// GitShallow reports whether the repo is a shallow clone (console git
// workspaces clone --depth 1): its "history" is a single commit, and the
// finding says so instead of implying full-history coverage.
func GitShallow(target string) bool {
	_, err := os.Stat(filepath.Join(target, ".git", "shallow"))
	return err == nil
}

// mergeGitHistory folds the history pass into the worktree findings.
// History occurrences of a secret that still exists in the worktree (same
// rule + file) are dropped — the worktree finding already reports it, at the
// current line. Survivors are history-only: labeled, deduplicated on
// (rule, file, line), and their description says plainly what to do.
func mergeGitHistory(worktree, history []model.RawFinding, shallow bool) []model.RawFinding {
	inWorktree := make(map[string]bool, len(worktree))
	for _, f := range worktree {
		inWorktree[f.RuleID+"\x00"+f.File] = true
	}
	out := worktree
	seen := map[string]bool{}
	for _, f := range history {
		if inWorktree[f.RuleID+"\x00"+f.File] {
			continue
		}
		key := fmt.Sprintf("%s\x00%s\x00%d", f.RuleID, f.File, f.StartLine)
		if seen[key] {
			continue
		}
		seen[key] = true
		if f.Meta == nil {
			f.Meta = map[string]string{}
		}
		f.Meta["gitHistory"] = "true"
		note := "Found in git history, not in the current worktree: rotate the credential — deleting the file does not revoke it."
		if commit := f.Meta["commit"]; commit != "" {
			note = fmt.Sprintf("Found in git history (commit %s), not in the current worktree: rotate the credential — deleting the file does not revoke it.", shortCommit(commit))
		}
		if shallow {
			f.Meta["gitShallow"] = "true"
			note += " History coverage was limited to the shallow clone's single commit."
		}
		f.Description = strings.TrimSpace(f.Description + " " + note)
		out = append(out, f)
	}
	return out
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// gitleaksTitles maps common gitleaks rule IDs to human finding titles
// (schema 2.0.0, Q2). Curated and deterministic — never LLM output. A rule
// missing here falls back to model.HumanizeRuleID in Normalize (dash-split,
// sentence case), never to the raw ID. Each row says what the rule detects.
var gitleaksTitles = map[string]string{
	"generic-api-key":         "Hard-coded API key",                          // entropy-gated catch-all: assignments like api_key = "..."
	"aws-access-token":        "AWS access key",                              // AKIA…/ASIA… access key IDs
	"private-key":             "Private key material",                        // PEM "BEGIN … PRIVATE KEY" blocks
	"github-pat":              "GitHub personal access token",                // ghp_…
	"github-fine-grained-pat": "GitHub fine-grained personal access token",   // github_pat_…
	"github-oauth":            "GitHub OAuth access token",                   // gho_…
	"github-app-token":        "GitHub App token",                            // ghu_…/ghs_…
	"github-refresh-token":    "GitHub refresh token",                        // ghr_…
	"gitlab-pat":              "GitLab personal access token",                // glpat-…
	"slack-bot-token":         "Slack bot token",                             // xoxb-…
	"slack-user-token":        "Slack user token",                            // xoxp-…
	"slack-webhook-url":       "Slack webhook URL",                           // hooks.slack.com/services/…
	"stripe-access-token":     "Stripe API key",                              // sk_live_…/rk_live_…
	"gcp-api-key":             "Google Cloud API key",                        // AIza…
	"jwt":                     "Hard-coded JWT",                              // eyJ… signed token literals
	"openai-api-key":          "OpenAI API key",                              // sk-…
	"anthropic-api-key":       "Anthropic API key",                           // sk-ant-…
	"npm-access-token":        "npm access token",                            // npm_…
	"pypi-upload-token":       "PyPI upload token",                           // pypi-AgEIcHlwaS5vcmc…
	"sendgrid-api-token":      "SendGrid API key",                            // SG.…
	"twilio-api-key":          "Twilio API key",                              // SK… account keys
	"jdbc-connection-string":  "Database connection string with credentials", // jdbc:…user/password URLs
	"hashicorp-tf-api-token":  "HashiCorp Terraform API token",               // …atlasv1…
	"heroku-api-key":          "Heroku API key",                              // UUID-shaped platform keys
	"telegram-bot-api-token":  "Telegram bot token",                          // digits:AA… bot credentials
}

// gitleaksResult mirrors the JSON structure returned by gitleaks.
type gitleaksResult struct {
	Description string  `json:"Description"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	RuleID      string  `json:"RuleID"`
	Match       string  `json:"Match"`
	Secret      string  `json:"Secret"`
	Commit      string  `json:"Commit"`
	Line        string  `json:"Line"`
	Entropy     float64 `json:"Entropy"`
}

// parseGitleaks converts raw JSON output into model.RawFinding slices.
func parseGitleaks(data []byte) ([]model.RawFinding, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	var results []gitleaksResult
	if err := json.Unmarshal([]byte(trimmed), &results); err != nil {
		return nil, fmt.Errorf("parse gitleaks json: %w", err)
	}

	findings := make([]model.RawFinding, 0, len(results))
	for _, r := range results {
		// Defense in depth: --redact should already mask the secret in Match,
		// but scrub it ourselves too so a plaintext report can never leak
		// secret material into findings.
		match := r.Match
		if r.Secret != "" {
			match = strings.ReplaceAll(match, r.Secret, "[REDACTED]")
		}

		// Build sanitized payload without Secret or Line to prevent leakage.
		sanitized := map[string]interface{}{
			"Description": r.Description,
			"File":        r.File,
			"StartLine":   r.StartLine,
			"EndLine":     r.EndLine,
			"RuleID":      r.RuleID,
			"Match":       match,
			"Commit":      r.Commit,
			"Entropy":     r.Entropy,
		}
		payloadBytes, err := json.Marshal(sanitized)
		if err != nil {
			// Should not happen with simple types, but handle gracefully.
			continue
		}

		finding := model.RawFinding{
			Tool:     "gitleaks",
			Category: model.CategorySecret,
			RuleID:   r.RuleID,
			// Curated human title; unmapped rules fall back to the
			// deterministic humanizer in Normalize, never the raw ID.
			Title:       gitleaksTitles[r.RuleID],
			Description: r.Description,
			RawSeverity: "HIGH",
			File:        r.File,
			StartLine:   r.StartLine,
			EndLine:     r.EndLine,
			Meta: map[string]string{
				"match":   match,
				"entropy": formatEntropy(r.Entropy),
			},
			RawPayload: json.RawMessage(payloadBytes),
		}
		// Git-mode results carry the commit that introduced the secret;
		// worktree (--no-git) results have none. mergeGitHistory reads it.
		if r.Commit != "" {
			finding.Meta["commit"] = r.Commit
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// formatEntropy formats the entropy value to 2 decimal places.
func formatEntropy(e float64) string {
	if e == 0 {
		return "0.00"
	}
	return fmt.Sprintf("%.2f", e)
}
