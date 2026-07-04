package runstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/report"
)

func writeFile(dir, name, content string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}

func mkFinding(id string, sev model.Severity) model.Finding {
	return model.Finding{ID: id, Tool: "semgrep", Category: model.CategorySAST, RuleID: "r-" + id, Severity: sev}
}

func TestSaveListLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}

	t1 := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 7, 4, 12, 30, 15, 0, time.UTC)

	f1 := []model.Finding{mkFinding("aaa", model.SeverityHigh)}
	f2 := []model.Finding{mkFinding("aaa", model.SeverityHigh), mkFinding("bbb", model.SeverityLow)}

	m1, err := s.Save(f1, t1)
	if err != nil {
		t.Fatalf("save 1: %v", err)
	}
	m2, err := s.Save(f2, t2)
	if err != nil {
		t.Fatalf("save 2: %v", err)
	}
	if m1.ID == m2.ID {
		t.Fatal("distinct timestamps must yield distinct ids")
	}

	runs, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(runs))
	}
	// Oldest first.
	if !runs[0].CreatedAt.Equal(t1) || !runs[1].CreatedAt.Equal(t2) {
		t.Errorf("runs not chronological: %v", []time.Time{runs[0].CreatedAt, runs[1].CreatedAt})
	}

	doc, err := s.Load(m2.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(doc.Findings) != 2 {
		t.Errorf("expected 2 findings in run 2, got %d", len(doc.Findings))
	}
	if doc.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema version = %q, want %q", doc.SchemaVersion, model.SchemaVersion)
	}
}

func TestLatest(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, ok, _ := s.Latest(); ok {
		t.Fatal("empty store should report no latest run")
	}
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	_, _ = s.Save([]model.Finding{mkFinding("x", model.SeverityInfo)}, late)
	_, _ = s.Save([]model.Finding{mkFinding("y", model.SeverityInfo)}, early)
	m, ok, err := s.Latest()
	if err != nil || !ok {
		t.Fatalf("latest: ok=%v err=%v", ok, err)
	}
	if !m.CreatedAt.Equal(late) {
		t.Errorf("latest = %v, want %v", m.CreatedAt, late)
	}
}

func TestListSkipsMalformed(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	_, _ = s.Save([]model.Finding{mkFinding("a", model.SeverityHigh)}, time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC))
	// Drop non-run files that must be ignored.
	if err := writeFile(dir, "notes.txt", "hi"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(dir, "garbage.json", "{not a run}"); err != nil {
		t.Fatal(err)
	}
	runs, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("expected 1 valid run, got %d", len(runs))
	}
}

func TestLoadRejectsTraversal(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	for _, bad := range []string{"../secret", "..", "a/b", `..\win`, "not-a-timestamp"} {
		if _, err := s.Load(bad); err == nil {
			t.Errorf("Load(%q) should have errored", bad)
		}
	}
}

func TestComputeDelta_FirstRun(t *testing.T) {
	curr := report.Document{Findings: []model.Finding{
		mkFinding("a", model.SeverityHigh), mkFinding("b", model.SeverityLow),
	}}
	d := ComputeDelta(nil, curr)
	if len(d.New) != 2 || len(d.Resolved) != 0 || len(d.Unchanged) != 0 {
		t.Fatalf("first run: new=%d resolved=%d unchanged=%d", len(d.New), len(d.Resolved), len(d.Unchanged))
	}
	c := d.Counts()
	if c.New != 2 || c.Total != 2 {
		t.Errorf("counts wrong: %+v", c)
	}
}

func TestComputeDelta_NewAndResolved(t *testing.T) {
	prev := report.Document{Findings: []model.Finding{
		mkFinding("keep", model.SeverityHigh),
		mkFinding("gone", model.SeverityMedium),
	}}
	curr := report.Document{Findings: []model.Finding{
		mkFinding("keep", model.SeverityHigh),
		mkFinding("fresh", model.SeverityCritical),
	}}
	d := ComputeDelta(&prev, curr)

	if len(d.New) != 1 || d.New[0].ID != "fresh" {
		t.Errorf("expected [fresh] new, got %v", ids(d.New))
	}
	if len(d.Resolved) != 1 || d.Resolved[0].ID != "gone" {
		t.Errorf("expected [gone] resolved, got %v", ids(d.Resolved))
	}
	if len(d.Unchanged) != 1 || d.Unchanged[0].ID != "keep" {
		t.Errorf("expected [keep] unchanged, got %v", ids(d.Unchanged))
	}
	c := d.Counts()
	if c.New != 1 || c.Resolved != 1 || c.Unchanged != 1 || c.Total != 2 {
		t.Errorf("counts wrong: %+v", c)
	}
}

// A finding must never be both new and resolved, and the current run must never
// lose a finding through the delta — the failure this logic exists to prevent.
func TestComputeDelta_NoFindingLostOrDoubleCounted(t *testing.T) {
	prev := report.Document{Findings: []model.Finding{mkFinding("x", model.SeverityHigh)}}
	curr := report.Document{Findings: []model.Finding{
		mkFinding("x", model.SeverityHigh),
		mkFinding("y", model.SeverityHigh),
		mkFinding("z", model.SeverityHigh),
	}}
	d := ComputeDelta(&prev, curr)
	// Every current finding is accounted for exactly once as new or unchanged.
	if len(d.New)+len(d.Unchanged) != len(curr.Findings) {
		t.Fatalf("current findings lost: new+unchanged=%d, want %d", len(d.New)+len(d.Unchanged), len(curr.Findings))
	}
	seen := map[string]int{}
	for _, f := range append(append([]model.Finding{}, d.New...), d.Unchanged...) {
		seen[f.ID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("finding %q counted %d times", id, n)
		}
	}
}

func ids(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}
