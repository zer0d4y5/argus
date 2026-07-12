package engagement

import (
	"testing"
	"time"
)

func validOpts() Options {
	return Options{AuthorizationRef: "CVP-1234", Contact: "op@example.com"}
}

func TestNewValidates(t *testing.T) {
	scope := Scope{InScope: []string{"staging.example.com"}}

	if _, err := New("", scope, validOpts()); err == nil {
		t.Error("empty name must be rejected")
	}
	if _, err := New("ok", Scope{}, validOpts()); err == nil {
		t.Error("empty scope must be rejected")
	}
	if _, err := New("ok", scope, Options{}); err == nil {
		t.Error("missing authorization reference must be rejected")
	}
	end := time.Now()
	start := end.Add(time.Hour)
	if _, err := New("ok", scope, Options{AuthorizationRef: "x", Window: Window{Start: start, End: end}}); err == nil {
		t.Error("window end before start must be rejected")
	}

	e, err := New("Prod Pentest", scope, validOpts())
	if err != nil {
		t.Fatalf("valid engagement rejected: %v", err)
	}
	if !idRe.MatchString(e.ID) {
		t.Errorf("id %q does not match the expected shape", e.ID)
	}
	if e.Destructive {
		t.Error("destructive must default off")
	}
}

func TestEffectiveIntensityDefaults(t *testing.T) {
	e := &Engagement{}
	in := e.EffectiveIntensity()
	if in.RatePerSec != defaultRatePerSec || in.PerHostConcurrency != defaultPerHostConcurrency || in.RequestBudget != defaultRequestBudget {
		t.Errorf("zero intensity must fall back to the conservative defaults, got %+v", in)
	}
	// Operator-set values are never widened.
	e2 := &Engagement{Intensity: Intensity{RatePerSec: 2, PerHostConcurrency: 1, RequestBudget: 50}}
	in2 := e2.EffectiveIntensity()
	if in2.RatePerSec != 2 || in2.PerHostConcurrency != 1 || in2.RequestBudget != 50 {
		t.Errorf("operator ceiling must be preserved, got %+v", in2)
	}
}

func TestWindowOpen(t *testing.T) {
	now := time.Now()
	open := &Engagement{} // no bounds
	if !open.WindowOpen(now) {
		t.Error("an unbounded window is always open")
	}
	past := &Engagement{Window: Window{End: now.Add(-time.Hour)}}
	if past.WindowOpen(now) {
		t.Error("a window that has ended is closed")
	}
	future := &Engagement{Window: Window{Start: now.Add(time.Hour)}}
	if future.WindowOpen(now) {
		t.Error("a window that has not started is closed")
	}
	active := &Engagement{Window: Window{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}
	if !active.WindowOpen(now) {
		t.Error("a window spanning now is open")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	store := &Store{Dir: t.TempDir()}
	e, err := New("Engagement A", Scope{InScope: []string{"a.example.com"}}, validOpts())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(e); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Engagement A" || got.AuthorizationRef != "CVP-1234" || len(got.Scope.InScope) != 1 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	if _, err := store.Load("e-doesnotexist000"); err != ErrNotFound {
		t.Errorf("unknown id must be ErrNotFound, got %v", err)
	}
	if _, err := store.Load("../etc/passwd"); err != ErrNotFound {
		t.Errorf("malformed id must be ErrNotFound (no traversal), got %v", err)
	}
}

func TestStoreActivePointer(t *testing.T) {
	store := &Store{Dir: t.TempDir()}
	if a, err := store.Active(); err != nil || a != nil {
		t.Fatalf("no active engagement should be (nil,nil), got (%v,%v)", a, err)
	}
	e, _ := New("A", Scope{InScope: []string{"a.example.com"}}, validOpts())
	store.Save(e)
	if err := store.SetActive(e.ID); err != nil {
		t.Fatal(err)
	}
	got, err := store.Active()
	if err != nil || got == nil || got.ID != e.ID {
		t.Fatalf("active must resolve to the set engagement, got (%v,%v)", got, err)
	}
	if err := store.SetActive("e-0000000000000000"); err != ErrNotFound {
		t.Errorf("activating an unknown id must fail, got %v", err)
	}
}

func TestStoreListNewestFirst(t *testing.T) {
	store := &Store{Dir: t.TempDir()}
	older, _ := New("older", Scope{InScope: []string{"a.example.com"}}, validOpts())
	older.CreatedAt = time.Now().Add(-time.Hour)
	newer, _ := New("newer", Scope{InScope: []string{"b.example.com"}}, validOpts())
	store.Save(older)
	store.Save(newer)
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != newer.ID {
		t.Fatalf("List must return newest first, got %d entries head=%v", len(list), list)
	}
}
