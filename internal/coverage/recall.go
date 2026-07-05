// Profile recall eval (deep-scan session): recall is proven, never asserted.
// Every planted vulnerability in testdata/polyglot carries an in-fixture
// label
//
//	PLANT(<id>, min-profile=<fast|standard|max>, <CWE-n>)
//
// naming the MINIMUM profile that must catch it. TestProfileRecall scans the
// fixtures under every profile and asserts each plant is caught by its
// minimum profile and every superset, and that the caught-plant sets form
// the inclusion chain fast ⊆ standard ⊆ max — on plant IDs, not counts.
// Plants no profile catches are labeled PLANT-GAP (parsed by nothing here;
// they are documentation, tracked in docs/coverage.md as known gaps).
package coverage

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Plant is one labeled planted vulnerability.
type Plant struct {
	ID         string // unique, kebab-case, e.g. "py-sqli"
	File       string // fixture-relative path, e.g. "python/vuln.py"
	CWE        string // the CWE semgrep actually emits on detection
	MinProfile string // fast | standard | max
	Line       int    // 1-based label line, for humans reading failures
}

// plantLabel matches the structured plant tag inside any comment syntax.
var plantLabel = regexp.MustCompile(`PLANT\(([a-z0-9-]+),\s*min-profile=(fast|standard|max),\s*(CWE-\d+)\)`)

// ParsePlants walks the fixture root and extracts every structured plant
// label. It fails loudly on label mistakes — a duplicate ID or a duplicate
// (file, CWE) pair would make the recall eval silently ambiguous.
func ParsePlants(root string) ([]Plant, error) {
	var plants []Plant
	byID := map[string]string{}
	byFileCWE := map[string]string{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("recall: read %s: %w", path, err)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		for i, line := range strings.Split(string(data), "\n") {
			m := plantLabel.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			p := Plant{ID: m[1], File: rel, CWE: m[3], MinProfile: m[2], Line: i + 1}
			if prev, dup := byID[p.ID]; dup {
				return fmt.Errorf("recall: duplicate plant ID %q (%s and %s)", p.ID, prev, rel)
			}
			key := p.File + "\x00" + p.CWE
			if prev, dup := byFileCWE[key]; dup {
				return fmt.Errorf("recall: plants %q and %q share (file, CWE) %s %s — detection matching cannot tell them apart", prev, p.ID, p.File, p.CWE)
			}
			byID[p.ID] = rel
			byFileCWE[key] = p.ID
			plants = append(plants, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(plants) == 0 {
		return nil, fmt.Errorf("recall: no PLANT labels under %s", root)
	}
	sort.Slice(plants, func(i, j int) bool { return plants[i].ID < plants[j].ID })
	return plants, nil
}

// CaughtPlants returns the IDs of plants whose (file, CWE) appears in the
// detection map (from DetectedCWEs).
func CaughtPlants(plants []Plant, detected map[string]map[string]bool) map[string]bool {
	caught := map[string]bool{}
	for _, p := range plants {
		if set := detected[p.File]; set != nil && set[p.CWE] {
			caught[p.ID] = true
		}
	}
	return caught
}
