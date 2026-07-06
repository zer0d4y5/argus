package disposition

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSetGetClear(t *testing.T) {
	dir := t.TempDir()
	s := At(dir)
	now := time.Unix(1700000000, 0)

	if _, ok := s.Get("f1"); ok {
		t.Fatal("unset finding must be open (no record)")
	}
	rec, err := s.Set("f1", StatusAcceptedRisk, "known, low blast radius", "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != StatusAcceptedRisk || rec.Actor != "alice" || rec.Note == "" {
		t.Errorf("record = %+v", rec)
	}

	// Persisted across a fresh store (re-read from disk).
	got, ok := At(dir).Get("f1")
	if !ok || got.Status != StatusAcceptedRisk || got.Note != "known, low blast radius" {
		t.Errorf("reload = %+v ok=%v", got, ok)
	}

	// Overwrite.
	if _, err := s.Set("f1", StatusFixed, "patched in #123", "bob", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.Get("f1"); g.Status != StatusFixed || g.Actor != "bob" {
		t.Errorf("overwrite = %+v", g)
	}

	// Clear → back to open.
	if err := s.Clear("f1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("f1"); ok {
		t.Error("cleared finding must be open again")
	}
	if err := s.Clear("f1"); err != nil {
		t.Errorf("clearing an open finding must be a no-op, got %v", err)
	}
}

func TestSetValidation(t *testing.T) {
	s := At(t.TempDir())
	now := time.Unix(1700000000, 0)
	if _, err := s.Set("", StatusFixed, "", "a", now); err == nil {
		t.Error("empty findingId must error")
	}
	for _, bad := range []string{"open", "nonsense", ""} {
		if _, err := s.Set("f", bad, "", "a", now); err == nil {
			t.Errorf("status %q must be rejected (open is cleared, not set)", bad)
		}
	}
	// Note is length-capped.
	long := make([]rune, noteMax+500)
	for i := range long {
		long[i] = 'x'
	}
	rec, err := s.Set("f", StatusInProgress, string(long), "a", now)
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(rec.Note)) > noteMax {
		t.Errorf("note not capped: %d runes", len([]rune(rec.Note)))
	}
}

func TestCounts(t *testing.T) {
	s := At(t.TempDir())
	now := time.Unix(1700000000, 0)
	s.Set("a", StatusFixed, "", "u", now)
	s.Set("b", StatusAcceptedRisk, "", "u", now)
	// c, d have no record → open.
	c := s.Counts([]string{"a", "b", "c", "d"})
	if c[StatusFixed] != 1 || c[StatusAcceptedRisk] != 1 || c[StatusOpen] != 2 {
		t.Errorf("counts = %v", c)
	}
}

// TestPersistedPath: the file lands beside runs (dispositions.json in the
// given dir), the atomic write leaves no .tmp behind.
func TestPersistedPath(t *testing.T) {
	dir := t.TempDir()
	At(dir).Set("f", StatusFixed, "", "u", time.Unix(1, 0))
	if _, err := os.Stat(filepath.Join(dir, "dispositions.json")); err != nil {
		t.Errorf("dispositions.json not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dispositions.json.tmp")); err == nil {
		t.Error(".tmp left behind after atomic write")
	}
}
