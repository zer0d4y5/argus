// Package runstore persists scan reports as timestamped run files and computes
// run-to-run deltas. It is the file-based history the `argus serve` console
// reads (no database in this phase).
//
// SECURITY-CRITICAL: the delta logic is the one place a finding can silently
// disappear from the operator's view. "New" and "resolved" are derived strictly
// from stable fingerprints (model.Finding.ID); a finding present in both runs is
// unchanged, present only in the new run is new, present only in the old run is
// resolved. A bug here would hide a live vulnerability, so the rules are kept
// deliberately simple and are unit-tested with adversarial cases.
package runstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/coverage"

	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/report"
)

// runsSubdir is the directory, under a scanned repo, where runs are stored.
const runsSubdir = ".appsec/runs"

// fileExt is the run file extension.
const fileExt = ".json"

// RunMeta identifies a stored run without loading its findings.
type RunMeta struct {
	ID        string    `json:"id"`        // the RFC3339 filename stem
	CreatedAt time.Time `json:"createdAt"` // parsed from the ID
	Path      string    `json:"-"`         // absolute path on disk
}

// Store is a run directory. Dir is the `.appsec/runs` path.
type Store struct {
	Dir string
}

// ForRepo returns a Store rooted at <repo>/.appsec/runs.
func ForRepo(repoRoot string) Store {
	return Store{Dir: filepath.Join(repoRoot, runsSubdir)}
}

// Save writes findings as a run file named <RFC3339>.json and returns its
// metadata. The timestamp is supplied by the caller (never read from the clock
// here) so saves are deterministic and testable. Colons in RFC3339 are replaced
// with dashes in the filename for cross-filesystem safety; the ID preserves the
// sanitized stem and round-trips back to CreatedAt.
func (s Store) Save(findings []model.Finding, t time.Time) (RunMeta, error) {
	return s.SaveWithCoverage(findings, nil, t)
}

// SaveWithCoverage is Save plus the scan's skip accounting (schema 2.0.0),
// which the console surfaces on the run detail. nil means "not accounted"
// (older callers, tests) and is stored as an absent field, never zeros.
func (s Store) SaveWithCoverage(findings []model.Finding, cov *coverage.Accounting, t time.Time) (RunMeta, error) {
	return s.save(findings, cov, nil, t)
}

// SaveWithTools is Save plus external-tool provenance: which scanner version
// produced the raw findings (e.g. the prowler release behind a cloud run).
// An empty map is stored as an absent field.
func (s Store) SaveWithTools(findings []model.Finding, tools map[string]string, t time.Time) (RunMeta, error) {
	return s.save(findings, nil, tools, t)
}

func (s Store) save(findings []model.Finding, cov *coverage.Accounting, tools map[string]string, t time.Time) (RunMeta, error) {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return RunMeta{}, fmt.Errorf("runstore: mkdir %s: %w", s.Dir, err)
	}
	id := idFromTime(t)
	path := filepath.Join(s.Dir, id+fileExt)

	doc := report.BuildDocument(findings)
	doc.Coverage = cov
	if len(tools) > 0 {
		doc.ToolVersions = tools
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return RunMeta{}, fmt.Errorf("runstore: marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return RunMeta{}, fmt.Errorf("runstore: write %s: %w", path, err)
	}
	return RunMeta{ID: id, CreatedAt: t.UTC(), Path: path}, nil
}

// List returns run metadata sorted oldest-first (chronological, for trends).
// A malformed filename is skipped, never fatal — one bad file must not blind
// the whole console.
func (s Store) List() ([]RunMeta, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no runs yet is not an error
		}
		return nil, fmt.Errorf("runstore: read dir %s: %w", s.Dir, err)
	}
	var runs []RunMeta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), fileExt) {
			continue
		}
		id := strings.TrimSuffix(e.Name(), fileExt)
		t, err := timeFromID(id)
		if err != nil {
			continue // skip files that aren't run timestamps
		}
		runs = append(runs, RunMeta{ID: id, CreatedAt: t, Path: filepath.Join(s.Dir, e.Name())})
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.Before(runs[j].CreatedAt) })
	return runs, nil
}

// Load reads a single run by ID. The ID is validated as a run timestamp and the
// path is confined to the store directory, so a crafted ID cannot escape it
// (path traversal defense for the API layer).
func (s Store) Load(id string) (report.Document, error) {
	var doc report.Document
	if _, err := timeFromID(id); err != nil {
		return doc, fmt.Errorf("runstore: invalid run id %q", id)
	}
	// Reject any id containing path separators before it reaches the filesystem.
	if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return doc, fmt.Errorf("runstore: invalid run id %q", id)
	}
	path := filepath.Join(s.Dir, id+fileExt)
	data, err := os.ReadFile(path)
	if err != nil {
		return doc, fmt.Errorf("runstore: read run %s: %w", id, err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("runstore: parse run %s: %w", id, err)
	}
	return doc, nil
}

// Delete removes a single run file by ID. The ID is validated as a run
// timestamp and confined to the store directory — the same path-traversal
// defense as Load, since this is reachable from the API. A missing file is
// reported as not-found so the caller can return 404 rather than 500.
func (s Store) Delete(id string) error {
	if _, err := timeFromID(id); err != nil {
		return fmt.Errorf("runstore: invalid run id %q", id)
	}
	if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return fmt.Errorf("runstore: invalid run id %q", id)
	}
	path := filepath.Join(s.Dir, id+fileExt)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("runstore: delete run %s: %w", id, err)
	}
	return nil
}

// Latest returns the most recent run's metadata, or ok=false if none exist.
func (s Store) Latest() (RunMeta, bool, error) {
	runs, err := s.List()
	if err != nil || len(runs) == 0 {
		return RunMeta{}, false, err
	}
	return runs[len(runs)-1], true, nil
}

// idFromTime formats a timestamp as a filesystem-safe run id.
func idFromTime(t time.Time) string {
	return strings.ReplaceAll(t.UTC().Format(time.RFC3339), ":", "-")
}

// timeFromID parses a run id back to a time, accepting the sanitized form.
func timeFromID(id string) (time.Time, error) {
	// Restore the two colons in the time component (HH-MM-SS and the zone
	// offset) that idFromTime replaced. RFC3339 UTC uses a trailing 'Z', so
	// only the time separators were dashed: 2006-01-02T15-04-05Z.
	restored := restoreColons(id)
	return time.Parse(time.RFC3339, restored)
}

// restoreColons turns "2006-01-02T15-04-05Z" back into RFC3339 by re-inserting
// the colons in the time-of-day component. It operates only on the substring
// after 'T', leaving the date (which legitimately uses dashes) untouched.
func restoreColons(id string) string {
	i := strings.IndexByte(id, 'T')
	if i < 0 {
		return id
	}
	date, rest := id[:i+1], id[i+1:]
	// rest looks like 15-04-05Z or 15-04-05+07-00; the first two dashes in the
	// HH-MM-SS block become colons. Replace the first two '-' with ':'.
	var b strings.Builder
	replaced := 0
	for _, r := range rest {
		if r == '-' && replaced < 2 {
			b.WriteByte(':')
			replaced++
			continue
		}
		b.WriteRune(r)
	}
	return date + b.String()
}
