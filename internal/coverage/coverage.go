// Package coverage proves the platform's multi-language detection breadth.
//
// It loads the canary manifest (testdata/polyglot/labels.json), runs the real
// semgrep adapter with the curated profile rulesets against the polyglot
// fixtures, and reports what was detected. The accompanying test asserts every
// canary is caught under the `standard` profile and regenerates
// docs/coverage.md — the "eagle eye" artifact — from live scan data so the
// published matrix can never drift from reality.
package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/scanner"
)

// Canary is a single planted vulnerability that must be detected.
type Canary struct {
	CWE  string `json:"cwe"`
	Name string `json:"name"`
}

// Label ties a fixture file to the canaries it must yield.
type Label struct {
	Language string   `json:"language"`
	File     string   `json:"file"` // relative to the polyglot root, e.g. "python/vuln.py"
	Canaries []Canary `json:"canaries"`
}

type labelsDoc struct {
	Languages []Label `json:"languages"`
}

// LoadLabels reads and parses the canary manifest at path.
func LoadLabels(path string) ([]Label, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("coverage: read labels %s: %w", path, err)
	}
	var doc labelsDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("coverage: parse labels %s: %w", path, err)
	}
	if len(doc.Languages) == 0 {
		return nil, fmt.Errorf("coverage: labels %s has no languages", path)
	}
	return doc.Languages, nil
}

// Scan runs the semgrep adapter with the given profile's curated rulesets
// against root and returns normalized findings. It exercises the exact
// detection path a real scan uses (ResolveSemgrepRulesets → Semgrep adapter →
// Normalize), so the matrix reflects production behavior, not a test shortcut.
func Scan(ctx context.Context, profile, root string) ([]model.Finding, error) {
	packs := scanner.ResolveSemgrepRulesets(profile, nil)
	adapter := &scanner.Semgrep{Rulesets: packs}
	raw, err := adapter.Scan(ctx, root)
	if err != nil {
		return nil, err
	}
	return model.Normalize(raw), nil
}

// DetectedCWEs returns, per fixture-relative path, the set of CWEs detected.
// Paths are reduced to their component after the "polyglot/" segment so they
// match the manifest's relative File values regardless of the scan root.
func DetectedCWEs(findings []model.Finding) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, f := range findings {
		rel := relPath(f.Location.File)
		if rel == "" {
			continue
		}
		set := out[rel]
		if set == nil {
			set = map[string]bool{}
			out[rel] = set
		}
		for _, c := range f.CWEs {
			set[c] = true
		}
	}
	return out
}

// relPath extracts the fixture-relative path ("python/vuln.py") from a scan
// location file, tolerating any scan root prefix.
func relPath(file string) string {
	file = filepath.ToSlash(file)
	const marker = "polyglot/"
	if i := strings.LastIndex(file, marker); i >= 0 {
		return file[i+len(marker):]
	}
	return file
}

// MissingCanaries returns, for the given detection map, every canary from the
// manifest that was NOT detected. An empty result means full canary coverage.
func MissingCanaries(labels []Label, detected map[string]map[string]bool) []string {
	var missing []string
	for _, l := range labels {
		got := detected[l.File]
		for _, c := range l.Canaries {
			if got == nil || !got[c.CWE] {
				missing = append(missing, fmt.Sprintf("%s (%s): %s %s", l.Language, l.File, c.CWE, c.Name))
			}
		}
	}
	sort.Strings(missing)
	return missing
}
