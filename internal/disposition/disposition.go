// Package disposition is the finding-workflow store: a durable, per-finding
// human judgment (open / in-progress / accepted-risk / false-positive /
// fixed) with a note and an owner, keyed by the finding's STABLE FINGERPRINT
// (model.Finding.ID). Because the fingerprint is stable across scans, a
// disposition set on a finding in one run automatically applies to the same
// finding in every later run — that is the whole point: the console becomes a
// tool you work in, not just a report you look at.
//
// This is the ONE place the console persists human state about findings. It is
// deliberately separate from run files (which stay immutable historical
// records) and from LLM triage (which is advisory, per-run, and never human).
// A disposition never changes a severity, the gate, or a compliance mapping —
// it is a workflow overlay the console joins onto findings at read time.
package disposition

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const fileName = "dispositions.json"

// noteMax bounds a disposition note (justification / context). Human text,
// rendered inert by the console like any finding text.
const noteMax = 2000

// Status is the closed set of finding dispositions.
const (
	StatusOpen          = "open"           // active/unresolved (the default; usually no record)
	StatusInProgress    = "in-progress"    // being worked on
	StatusAcceptedRisk  = "accepted-risk"  // acknowledged, accepted with justification
	StatusFalsePositive = "false-positive" // human judgment: not a real issue
	StatusFixed         = "fixed"          // believed fixed — a re-scan confirms (or flags a regression)
)

// settable are the statuses a caller may write. "open" is represented by the
// ABSENCE of a record, so it is cleared, not set.
var settable = map[string]bool{
	StatusInProgress: true, StatusAcceptedRisk: true,
	StatusFalsePositive: true, StatusFixed: true,
}

// ValidStatus reports whether s is a settable disposition status.
func ValidStatus(s string) bool { return settable[s] }

// Record is one finding's disposition.
type Record struct {
	FindingID string    `json:"findingId"` // the stable fingerprint
	Status    string    `json:"status"`
	Note      string    `json:"note,omitempty"`
	Actor     string    `json:"actor"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type file struct {
	Schema  int      `json:"schema"`
	Records []Record `json:"records"`
}

// Store is the file-backed disposition store for one run history. Like the
// user/target stores it re-reads on mtime change so a concurrent writer (or a
// future CLI) is picked up, and writes atomically.
type Store struct {
	path string

	mu      sync.Mutex
	byID    map[string]Record
	modTime time.Time
	loaded  bool
}

// At returns the store whose file lives in dir (the directory that also holds
// the runs/ subdir — i.e. `<root>/.appsec`). Dispositions sit beside runs so
// they travel with the target's history.
func At(dir string) *Store {
	return &Store{path: filepath.Join(dir, fileName)}
}

// Get returns the disposition for a finding id, or ok=false when it is open
// (no record).
func (s *Store) Get(findingID string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return Record{}, false
	}
	r, ok := s.byID[findingID]
	return r, ok
}

// All returns a copy of every disposition record keyed by finding id. The
// console overlays these onto a run's findings.
func (s *Store) All() (map[string]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return nil, err
	}
	out := make(map[string]Record, len(s.byID))
	for k, v := range s.byID {
		out[k] = v
	}
	return out, nil
}

// Set writes (or overwrites) a finding's disposition. status must be settable;
// "open" is cleared via Clear, not set here. note is trimmed and length-capped.
// t is supplied by the caller (never read from the clock here) so writes are
// testable and deterministic.
func (s *Store) Set(findingID, status, note, actor string, t time.Time) (Record, error) {
	findingID = strings.TrimSpace(findingID)
	if findingID == "" {
		return Record{}, fmt.Errorf("findingId is required")
	}
	if !settable[status] {
		return Record{}, fmt.Errorf("invalid status %q (want in-progress|accepted-risk|false-positive|fixed; clear to open)", status)
	}
	note = strings.TrimSpace(note)
	if len([]rune(note)) > noteMax {
		note = string([]rune(note)[:noteMax])
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return Record{}, err
	}
	rec := Record{FindingID: findingID, Status: status, Note: note, Actor: actor, UpdatedAt: t.UTC()}
	s.byID[findingID] = rec
	if err := s.save(); err != nil {
		s.loaded = false
		return Record{}, err
	}
	return rec, nil
}

// Clear removes a finding's disposition, returning it to open. Clearing an
// already-open finding is a no-op success.
func (s *Store) Clear(findingID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return err
	}
	if _, ok := s.byID[findingID]; !ok {
		return nil
	}
	delete(s.byID, findingID)
	if err := s.save(); err != nil {
		s.loaded = false
		return err
	}
	return nil
}

// Counts rolls up dispositions by status over the given finding IDs present in
// a run (ids not in the store count as open). Handy for a console summary.
func (s *Store) Counts(findingIDs []string) map[string]int {
	all, err := s.All()
	if err != nil {
		all = map[string]Record{}
	}
	out := map[string]int{StatusOpen: 0, StatusInProgress: 0, StatusAcceptedRisk: 0, StatusFalsePositive: 0, StatusFixed: 0}
	for _, id := range findingIDs {
		if r, ok := all[id]; ok {
			out[r.Status]++
		} else {
			out[StatusOpen]++
		}
	}
	return out
}

func (s *Store) refresh() error {
	fi, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			if !s.loaded {
				s.byID = map[string]Record{}
				s.loaded = true
			}
			return nil
		}
		return fmt.Errorf("disposition: stat %s: %w", s.path, err)
	}
	if s.loaded && fi.ModTime().Equal(s.modTime) {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("disposition: read %s: %w", s.path, err)
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("disposition: parse %s: %w", s.path, err)
	}
	s.byID = make(map[string]Record, len(f.Records))
	for _, r := range f.Records {
		s.byID[r.FindingID] = r
	}
	s.modTime, s.loaded = fi.ModTime(), true
	return nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("disposition: mkdir: %w", err)
	}
	recs := make([]Record, 0, len(s.byID))
	for _, r := range s.byID {
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].FindingID < recs[j].FindingID })
	data, err := json.MarshalIndent(file{Schema: 1, Records: recs}, "", "  ")
	if err != nil {
		return fmt.Errorf("disposition: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("disposition: write: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("disposition: replace: %w", err)
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.modTime = fi.ModTime()
	}
	return nil
}
