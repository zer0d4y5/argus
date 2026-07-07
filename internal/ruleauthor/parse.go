package ruleauthor

// Extracting the rule from model output is a security boundary: the model is
// told to emit only a fenced YAML block, but real models wrap it in prose or
// several fences. We pull the first plausible rule document, bound its size,
// and confirm it parses as YAML with a `rules:` list. Structural safety is the
// linter's job (safety.go); semgrep --validate is the final authority.

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// fencedBlock matches a ```yaml … ``` or ``` … ``` code fence, capturing the
// body. Non-greedy so the FIRST complete fence wins.
var fencedBlock = regexp.MustCompile("(?s)```(?:ya?ml)?\\s*\\n(.*?)```")

// extractRule pulls the rule YAML out of raw model output and returns it
// normalized (trailing whitespace trimmed). It prefers a fenced block; failing
// that, it falls back to the first `rules:`-rooted document in the text. It
// does NOT judge safety - it only isolates a bounded candidate.
func extractRule(raw string) (string, error) {
	if len(raw) > MaxRuleBytes*2 {
		raw = raw[:MaxRuleBytes*2]
	}
	var candidate string
	if m := fencedBlock.FindStringSubmatch(raw); m != nil {
		candidate = m[1]
	} else if i := strings.Index(raw, "rules:"); i >= 0 {
		// No fence; take from the first `rules:` to the end and let YAML parsing
		// decide. Trim a leading indent run if the whole block is indented.
		candidate = raw[i:]
	} else {
		return "", fmt.Errorf("model output contained no rule (expected a fenced YAML block with a `rules:` list)")
	}

	candidate = strings.TrimRight(candidate, " \t\r\n")
	if strings.TrimSpace(candidate) == "" {
		return "", fmt.Errorf("model produced an empty rule")
	}
	if len(candidate) > MaxRuleBytes {
		return "", fmt.Errorf("model produced an oversized rule (%d bytes; limit %d)", len(candidate), MaxRuleBytes)
	}

	// Confirm it is YAML with a rules list before returning; a candidate that
	// does not even parse is a failure, not a draft to show.
	var probe struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(candidate), &probe); err != nil {
		return "", fmt.Errorf("model output did not parse as a YAML rule: %s", oneLine(err.Error()))
	}
	if len(probe.Rules) == 0 {
		return "", fmt.Errorf("model output has no `rules:` list")
	}
	return candidate, nil
}
