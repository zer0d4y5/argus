package ticket

import (
	"sync"
	"testing"
	"time"

	"github.com/leaky-hub/argus/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db)
}

var t0 = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

func TestCreateGetListUpdate(t *testing.T) {
	s := newStore(t)
	tk, err := s.Create(CreateInput{Title: "SQLi in login", Priority: "high", TargetID: "t-1"}, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if tk.ID == "" || tk.Status != "open" || tk.Priority != "high" {
		t.Fatalf("bad create: %+v", tk)
	}

	got, err := s.Get(tk.ID)
	if err != nil || got.Title != "SQLi in login" {
		t.Fatalf("get: %+v %v", got, err)
	}

	// Default priority when omitted.
	tk2, _ := s.Create(CreateInput{Title: "second"}, "bob", t0)
	if tk2.Priority != "medium" {
		t.Errorf("default priority = %q, want medium", tk2.Priority)
	}

	// List newest-updated first; the just-created tk2 leads.
	list, err := s.List(ListFilter{})
	if err != nil || len(list) != 2 {
		t.Fatalf("list len = %d, %v", len(list), err)
	}

	// Filter by target.
	if got, _ := s.List(ListFilter{TargetID: "t-1"}); len(got) != 1 || got[0].ID != tk.ID {
		t.Errorf("target filter wrong: %+v", got)
	}

	// Update status + patch semantics: only provided fields change.
	done := "done"
	up, err := s.Update(tk.ID, UpdateInput{Status: &done}, t0.Add(time.Hour))
	if err != nil || up.Status != "done" || up.Title != "SQLi in login" {
		t.Fatalf("update: %+v %v", up, err)
	}
	if up.UpdatedAt == tk.UpdatedAt {
		t.Error("updated_at not bumped")
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	s := newStore(t)
	if _, err := s.Create(CreateInput{Title: "  "}, "a", t0); err == nil {
		t.Error("empty title must be rejected")
	}
	if _, err := s.Create(CreateInput{Title: "x", Priority: "bogus"}, "a", t0); err == nil {
		t.Error("invalid priority must be rejected")
	}
	tk, _ := s.Create(CreateInput{Title: "x"}, "a", t0)
	if _, err := s.Update(tk.ID, UpdateInput{Status: strptr("nope")}, t0); err == nil {
		t.Error("invalid status must be rejected")
	}
}

func TestLinksAndIndex(t *testing.T) {
	s := newStore(t)
	tk, _ := s.Create(CreateInput{Title: "batch"}, "a", t0)
	if err := s.Link(tk.ID, "fp-aaa", "t-1"); err != nil {
		t.Fatal(err)
	}
	// Idempotent: linking the same finding twice is a no-op, not an error.
	if err := s.Link(tk.ID, "fp-aaa", "t-1"); err != nil {
		t.Fatalf("relink: %v", err)
	}
	s.Link(tk.ID, "fp-bbb", "t-1")
	if links, _ := s.Links(tk.ID); len(links) != 2 {
		t.Errorf("links = %d, want 2", len(links))
	}
	// Linking to a missing ticket fails.
	if err := s.Link("tk-missing", "fp", "t-1"); err == nil {
		t.Error("link to missing ticket should fail")
	}
	// Finding index for the Findings view.
	idx, _ := s.TicketsForFindings("t-1")
	if len(idx["fp-aaa"]) != 1 || idx["fp-aaa"][0] != tk.ID {
		t.Errorf("finding index wrong: %+v", idx)
	}
	// Unlink.
	s.Unlink(tk.ID, "fp-aaa", "t-1")
	if links, _ := s.Links(tk.ID); len(links) != 1 {
		t.Errorf("after unlink = %d, want 1", len(links))
	}
}

func TestCommentsTimeline(t *testing.T) {
	s := newStore(t)
	tk, _ := s.Create(CreateInput{Title: "x"}, "a", t0)
	if _, err := s.AddComment(tk.ID, "comment", "alice", "looking into this", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddComment(tk.ID, "event", "", "status → done", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Empty human comment is rejected; empty event body is allowed elsewhere but
	// events always carry a body here.
	if _, err := s.AddComment(tk.ID, "comment", "a", "   ", t0); err == nil {
		t.Error("empty comment body must be rejected")
	}
	cs, _ := s.Comments(tk.ID)
	if len(cs) != 2 || cs[0].Body != "looking into this" || cs[1].Kind != "event" {
		t.Errorf("timeline wrong: %+v", cs)
	}
}

func TestDeleteCascades(t *testing.T) {
	s := newStore(t)
	tk, _ := s.Create(CreateInput{Title: "x"}, "a", t0)
	s.Link(tk.ID, "fp", "t-1")
	s.AddComment(tk.ID, "comment", "a", "note", t0)
	if err := s.Delete(tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(tk.ID); err != ErrNotFound {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
	if links, _ := s.Links(tk.ID); len(links) != 0 {
		t.Error("links not cascaded on delete")
	}
	if err := s.Delete("tk-missing"); err != ErrNotFound {
		t.Errorf("delete missing = %v, want ErrNotFound", err)
	}
}

func strptr(s string) *string { return &s }

// TestConcurrentPatchesBothApply: Update is read-modify-write over every
// column, so two concurrent patches of DIFFERENT fields must not revert each
// other (the classic lost update). The transaction serializes them.
func TestConcurrentPatchesBothApply(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 40; i++ {
		tk, err := s.Create(CreateInput{Title: "orig title", Description: "orig desc"}, "a", t0)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			s.Update(tk.ID, UpdateInput{Title: strptr("new title")}, t0.Add(time.Minute))
		}()
		go func() {
			defer wg.Done()
			<-start
			s.Update(tk.ID, UpdateInput{Description: strptr("new desc")}, t0.Add(time.Minute))
		}()
		close(start)
		wg.Wait()
		got, err := s.Get(tk.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Title != "new title" || got.Description != "new desc" {
			t.Fatalf("iteration %d lost a patch: title=%q desc=%q", i, got.Title, got.Description)
		}
	}
}
