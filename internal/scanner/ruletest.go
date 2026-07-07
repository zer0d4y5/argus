package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Testing a candidate rule against a pasted snippet. This backs the console's
// "does my rule match this example?" loop: write the rule and the snippet to
// temp files, validate the rule, then run semgrep over the snippet and report
// whether (and where) it fired. The snippet is untrusted example code, but
// semgrep only STATICALLY analyzes it; nothing in it executes.

// ruleTestLangExt maps a semgrep language name to a file extension so the
// snippet lands in a file semgrep will parse as that language. Only the
// languages the profiles claim (plus the curated/BYO set) are offered.
var ruleTestLangExt = map[string]string{
	"python": ".py", "py": ".py",
	"javascript": ".js", "js": ".js",
	"typescript": ".ts", "ts": ".ts",
	"go": ".go", "golang": ".go",
	"java":   ".java",
	"csharp": ".cs", "c#": ".cs",
	"ruby": ".rb", "rb": ".rb",
	"php":    ".php",
	"kotlin": ".kt", "kt": ".kt",
	"rust": ".rs", "rs": ".rs",
	"scala": ".scala",
	"c":     ".c",
	"swift": ".swift",
	"json":  ".json",
	"yaml":  ".yaml", "yml": ".yaml",
	"generic": ".txt",
}

// RuleTestMatch is one place the rule fired in the snippet.
type RuleTestMatch struct {
	Check     string `json:"check"`     // rule id (stable form)
	StartLine int    `json:"startLine"` // 1-based
	EndLine   int    `json:"endLine"`
}

// RuleTestResult is the outcome of validating and running a rule on a snippet.
type RuleTestResult struct {
	Valid           bool            `json:"valid"`           // rule passed semgrep --validate
	ValidationError string          `json:"validationError"` // why not, when invalid
	Matched         bool            `json:"matched"`         // fired at least once
	Matches         []RuleTestMatch `json:"matches"`
}

// LangExtForRuleTest reports the file extension a snippet in lang should use,
// and whether the language is supported for testing.
func LangExtForRuleTest(lang string) (string, bool) {
	ext, ok := ruleTestLangExt[strings.ToLower(strings.TrimSpace(lang))]
	return ext, ok
}

// TestRuleAgainstSnippet validates ruleYAML and, if valid, runs it over snippet
// (written as a lang-appropriate temp file) and reports the matches. A rule
// that fails validation returns Valid=false with the reason and never runs. An
// unsupported language, or a missing semgrep binary, is a hard error (the
// caller could not have tested otherwise).
func TestRuleAgainstSnippet(ctx context.Context, ruleYAML, snippet, lang string) (RuleTestResult, error) {
	ext, ok := LangExtForRuleTest(lang)
	if !ok {
		return RuleTestResult{}, fmt.Errorf("unsupported language %q for testing", lang)
	}
	if strings.TrimSpace(ruleYAML) == "" {
		return RuleTestResult{}, fmt.Errorf("rule is empty")
	}

	dir, err := os.MkdirTemp("", "argus-ruletest-*")
	if err != nil {
		return RuleTestResult{}, err
	}
	defer os.RemoveAll(dir)

	rulePath := filepath.Join(dir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleYAML), 0o600); err != nil {
		return RuleTestResult{}, err
	}
	// Validate first: an invalid rule is a clean, informative result, not a run.
	if err := semgrepValidate(ctx, rulePath); err != nil {
		return RuleTestResult{Valid: false, ValidationError: err.Error()}, nil
	}

	snippetPath := filepath.Join(dir, "snippet"+ext)
	if err := os.WriteFile(snippetPath, []byte(snippet), 0o600); err != nil {
		return RuleTestResult{}, err
	}

	data, err := runJSON(ctx, "semgrep", "--json", "--quiet", "--metrics=off", "--timeout", "10",
		"--config", rulePath, snippetPath)
	if err != nil {
		return RuleTestResult{}, fmt.Errorf("semgrep run failed: %w", err)
	}
	var out struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
			} `json:"end"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return RuleTestResult{}, fmt.Errorf("semgrep output parse: %w", err)
	}
	res := RuleTestResult{Valid: true, Matched: len(out.Results) > 0}
	for _, r := range out.Results {
		id := r.CheckID
		// The temp path prefixes the id (rule.<id>); show just the rule id.
		if i := strings.LastIndex(id, "."); i >= 0 {
			id = id[i+1:]
		}
		res.Matches = append(res.Matches, RuleTestMatch{Check: id, StartLine: r.Start.Line, EndLine: r.End.Line})
	}
	return res, nil
}
