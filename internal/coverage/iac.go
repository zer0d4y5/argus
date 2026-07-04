package coverage

// IaC coverage guard (Phase 4). Same philosophy as the polyglot guard: the
// canary manifest (testdata/iac/labels.json) lists planted misconfigurations,
// the real adapters are run against the fixtures, and every canary must be
// detected. The IaC engines emit rule IDs rather than CWEs, so IaC canaries
// key on rule IDs: a canary counts as detected when ANY of its listed rules
// (checkov CKV_* / trivy AVD IDs naming the same plant) fires on the file.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/scanner"
)

// IaCCanary is a single planted misconfiguration that must be detected by at
// least one of its rule IDs.
type IaCCanary struct {
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

// IaCLabel ties a fixture file to the canaries it must yield.
type IaCLabel struct {
	Kind     string      `json:"kind"` // Terraform | Kubernetes | Dockerfile
	File     string      `json:"file"` // relative to the iac root, e.g. "terraform/main.tf"
	Canaries []IaCCanary `json:"canaries"`
}

type iacLabelsDoc struct {
	Files []IaCLabel `json:"files"`
}

// LoadIaCLabels reads and parses the IaC canary manifest at path.
func LoadIaCLabels(path string) ([]IaCLabel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("coverage: read iac labels %s: %w", path, err)
	}
	var doc iacLabelsDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("coverage: parse iac labels %s: %w", path, err)
	}
	if len(doc.Files) == 0 {
		return nil, fmt.Errorf("coverage: iac labels %s has no files", path)
	}
	return doc.Files, nil
}

// ScanIaC runs the real IaC adapters (checkov + trivy-config) against root and
// returns normalized findings — the exact detection path a production scan
// uses. Adapters missing from PATH are skipped; the caller decides whether
// that invalidates the run (the coverage test requires both).
func ScanIaC(ctx context.Context, root string) ([]model.Finding, error) {
	var raw []model.RawFinding
	for _, a := range []scanner.Adapter{&scanner.Checkov{}, &scanner.TrivyConfig{}} {
		if !a.Available() {
			continue
		}
		findings, err := a.Scan(ctx, root)
		if err != nil {
			return nil, fmt.Errorf("coverage: %s: %w", a.Name(), err)
		}
		raw = append(raw, findings...)
	}
	return model.Normalize(raw), nil
}

// DetectedRules returns, per fixture-relative path, the set of rule IDs that
// fired. Paths are reduced to their component after the "iac/" segment so they
// match the manifest's relative File values regardless of the scan root.
func DetectedRules(findings []model.Finding) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, f := range findings {
		rel := iacRelPath(f.Location.File)
		if rel == "" || f.RuleID == "" {
			continue
		}
		set := out[rel]
		if set == nil {
			set = map[string]bool{}
			out[rel] = set
		}
		set[f.RuleID] = true
	}
	return out
}

// iacRelPath extracts the fixture-relative path ("terraform/main.tf") from a
// scan location file, tolerating any scan root prefix.
func iacRelPath(file string) string {
	file = filepath.ToSlash(file)
	const marker = "iac/"
	if i := strings.LastIndex(file, marker); i >= 0 {
		return file[i+len(marker):]
	}
	return file
}

// MissingIaCCanaries returns every canary from the manifest that no listed
// rule detected. An empty result means full IaC canary coverage.
func MissingIaCCanaries(labels []IaCLabel, detected map[string]map[string]bool) []string {
	var missing []string
	for _, l := range labels {
		got := detected[l.File]
		for _, c := range l.Canaries {
			if !anyRule(got, c.Rules) {
				missing = append(missing, fmt.Sprintf("%s (%s): %s [%s]",
					l.Kind, l.File, c.Name, strings.Join(c.Rules, ", ")))
			}
		}
	}
	sort.Strings(missing)
	return missing
}

func anyRule(got map[string]bool, rules []string) bool {
	for _, r := range rules {
		if got[r] {
			return true
		}
	}
	return false
}
