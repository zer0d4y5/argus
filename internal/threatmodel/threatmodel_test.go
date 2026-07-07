package threatmodel

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

func TestModelComponentEnumerate(t *testing.T) {
	s := newStore(t)
	m, err := s.CreateModel("t-1", "Checkout service", "", "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.AddComponent(m.ID, "component", "Web frontend", "web-app", "", "manual", -1, -1, t0)
	if err != nil {
		t.Fatal(err)
	}

	// Enumerate pulls the curated STRIDE threats for web-app.
	n, err := s.EnumerateComponent(c.ID, t0)
	if err != nil || n == 0 {
		t.Fatalf("enumerate = %d, %v", n, err)
	}
	threats, _ := s.Threats(m.ID)
	if len(threats) != n {
		t.Errorf("threats = %d, want %d", len(threats), n)
	}
	// Every enumerated threat is curated and open, and one is a spoofing threat
	// wired to the auth-session mitigation.
	foundSpoof := false
	for _, th := range threats {
		if th.Source != "curated" || th.Status != "open" {
			t.Errorf("bad enumerated threat: %+v", th)
		}
		if th.Category == "spoofing" && th.Mitigation == "auth-session" {
			foundSpoof = true
		}
	}
	if !foundSpoof {
		t.Error("expected a spoofing threat wired to auth-session")
	}

	// Enumerate is idempotent: a second pass adds nothing.
	if n2, _ := s.EnumerateComponent(c.ID, t0); n2 != 0 {
		t.Errorf("re-enumerate added %d, want 0", n2)
	}
}

func TestThreatStatusAndLinks(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	th, err := s.AddThreat(m.ID, "", "tampering", "SQLi at the query layer", "", "manual", "sqli", "a", t0)
	if err != nil {
		t.Fatal(err)
	}
	// Status transitions are validated.
	if err := s.SetThreatStatus(m.ID, th.ID, "mitigated", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetThreatStatus(m.ID, th.ID, "bogus", t0); err == nil {
		t.Error("invalid status must be rejected")
	}
	// Link to a finding, a control, and a mitigation.
	if err := s.LinkThreat(m.ID, th.ID, "finding", "fp-123", "t-1"); err != nil {
		t.Fatal(err)
	}
	s.LinkThreat(m.ID, th.ID, "control", "ASVS:V5.3.4", "")
	s.LinkThreat(m.ID, th.ID, "mitigation", "sqli", "")
	if err := s.LinkThreat(m.ID, th.ID, "bogus", "x", ""); err == nil {
		t.Error("invalid link kind must be rejected")
	}
	links, _ := s.LinksForModel(m.ID)
	if len(links[th.ID]) != 3 {
		t.Errorf("links = %d, want 3", len(links[th.ID]))
	}
}

// TestCrossModelScoping: a threat can only be moved, linked, or attached to a
// component through its OWN model — addressing it via another model's id is
// refused, so the audit trail can't record the wrong model.
func TestCrossModelScoping(t *testing.T) {
	s := newStore(t)
	mA, _ := s.CreateModel("", "A", "", "a", t0)
	mB, _ := s.CreateModel("", "B", "", "a", t0)
	compB, _ := s.AddComponent(mB.ID, "component", "DB", "database", "", "manual", -1, -1, t0)
	th, err := s.AddThreat(mA.ID, "", "tampering", "T", "", "manual", "", "a", t0)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetThreatStatus(mB.ID, th.ID, "mitigated", t0); err != ErrNotFound {
		t.Errorf("cross-model status = %v, want ErrNotFound", err)
	}
	if got, _ := s.Threats(mA.ID); got[0].Status != "open" {
		t.Errorf("cross-model status write landed: %q", got[0].Status)
	}
	if err := s.LinkThreat(mB.ID, th.ID, "control", "ASVS:V1.1.1", ""); err != ErrNotFound {
		t.Errorf("cross-model link = %v, want ErrNotFound", err)
	}
	if err := s.UnlinkThreat(mB.ID, th.ID, "control", "ASVS:V1.1.1", ""); err != ErrNotFound {
		t.Errorf("cross-model unlink = %v, want ErrNotFound", err)
	}
	// A threat may not point at a component from another model.
	if _, err := s.AddThreat(mA.ID, compB.ID, "tampering", "X", "", "manual", "", "a", t0); err == nil {
		t.Error("threat attached to another model's component")
	}
}

// TestThreatSourceProvenance: "curated" means the threatlib library wrote it.
// A hand-authored threat is "manual" even if the caller claims otherwise; only
// "assisted" (human-confirmed LLM suggestion) passes through.
func TestThreatSourceProvenance(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	for _, tc := range []struct{ give, want string }{
		{"curated", "manual"}, {"", "manual"}, {"llm", "manual"},
		{"manual", "manual"}, {"assisted", "assisted"},
	} {
		th, err := s.AddThreat(m.ID, "", "spoofing", "src "+tc.give, "", tc.give, "", "a", t0)
		if err != nil {
			t.Fatal(err)
		}
		if th.Source != tc.want {
			t.Errorf("AddThreat source %q stored %q, want %q", tc.give, th.Source, tc.want)
		}
	}
}

func TestModelCascadeAndValidation(t *testing.T) {
	s := newStore(t)
	if _, err := s.CreateModel("", "  ", "", "a", t0); err == nil {
		t.Error("empty model name must be rejected")
	}
	m, _ := s.CreateModel("", "M", "", "a", t0)
	c, _ := s.AddComponent(m.ID, "component", "DB", "database", "", "manual", -1, -1, t0)
	s.EnumerateComponent(c.ID, t0)
	// Deleting the model cascades components and threats.
	if err := s.DeleteModel(m.ID); err != nil {
		t.Fatal(err)
	}
	if comps, _ := s.Components(m.ID); len(comps) != 0 {
		t.Error("components not cascaded")
	}
	if threats, _ := s.Threats(m.ID); len(threats) != 0 {
		t.Error("threats not cascaded")
	}
	if _, err := s.GetModel(m.ID); err != ErrNotFound {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
}

// TestConcurrentEnumerateNoDuplicates: EnumerateComponent reads the existing
// threats and inserts what's missing; two racing enumerations of the same
// component must not double-insert the curated set. The transaction makes the
// read-then-insert atomic.
func TestConcurrentEnumerateNoDuplicates(t *testing.T) {
	s := newStore(t)
	m, err := s.CreateModel("t-1", "Race", "", "a", t0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.AddComponent(m.ID, "component", "API", "api-service", "", "manual", -1, -1, t0)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.EnumerateComponent(c.ID, t0)
		}()
	}
	close(start)
	wg.Wait()

	threats, err := s.Threats(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, th := range threats {
		key := th.Category + "\x00" + th.Title
		if seen[key] {
			t.Fatalf("duplicate threat from racing enumerations: %s / %s", th.Category, th.Title)
		}
		seen[key] = true
	}
}

// TestComponentSourceProvenance: "detected" belongs to the IaC scan, "assisted"
// to a confirmed LLM proposal, everything else is a hand-add.
func TestComponentSourceProvenance(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	for _, tc := range []struct{ give, want string }{
		{"", "manual"}, {"manual", "manual"}, {"detected", "detected"},
		{"assisted", "assisted"}, {"llm", "manual"},
	} {
		c, err := s.AddComponent(m.ID, "component", "n-"+tc.give, "database", "", tc.give, -1, -1, t0)
		if err != nil {
			t.Fatal(err)
		}
		if c.Source != tc.want {
			t.Errorf("source %q stored %q, want %q", tc.give, c.Source, tc.want)
		}
	}
	comps, _ := s.Components(m.ID)
	if len(comps) != 5 || comps[0].Source == "" {
		t.Errorf("source not read back: %+v", comps[0])
	}
}

// TestDeleteComponentCascadesItsThreats: removing a component removes the
// threats enumerated over it (and their links via FK), scoped to the model.
func TestDeleteComponentCascadesItsThreats(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	c, _ := s.AddComponent(m.ID, "component", "DB", "database", "", "manual", -1, -1, t0)
	n, err := s.EnumerateComponent(c.ID, t0)
	if err != nil || n == 0 {
		t.Fatalf("enumerate: %d %v", n, err)
	}
	// Cross-model delete is refused.
	mB, _ := s.CreateModel("", "B", "", "a", t0)
	if err := s.DeleteComponent(mB.ID, c.ID, t0); err != ErrNotFound {
		t.Errorf("cross-model component delete = %v, want ErrNotFound", err)
	}
	if err := s.DeleteComponent(m.ID, c.ID, t0); err != nil {
		t.Fatal(err)
	}
	if comps, _ := s.Components(m.ID); len(comps) != 0 {
		t.Error("component not deleted")
	}
	if threats, _ := s.Threats(m.ID); len(threats) != 0 {
		t.Errorf("threats survived their component: %d", len(threats))
	}
}

// TestDeleteThreatScoped: single-threat delete is scoped to the model.
func TestDeleteThreatScoped(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	mB, _ := s.CreateModel("", "B", "", "a", t0)
	th, _ := s.AddThreat(m.ID, "", "tampering", "T", "", "manual", "", "a", t0)
	if err := s.DeleteThreat(mB.ID, th.ID, t0); err != ErrNotFound {
		t.Errorf("cross-model threat delete = %v, want ErrNotFound", err)
	}
	if err := s.DeleteThreat(m.ID, th.ID, t0); err != nil {
		t.Fatal(err)
	}
	if threats, _ := s.Threats(m.ID); len(threats) != 0 {
		t.Error("threat not deleted")
	}
}

// TestFlowsAndPositions: flows connect components of the SAME model only,
// cascade with their components, and canvas positions clamp and persist.
func TestFlowsAndPositions(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	mB, _ := s.CreateModel("", "B", "", "a", t0)
	a, _ := s.AddComponent(m.ID, "component", "API", "api-service", "", "manual", -1, -1, t0)
	b, _ := s.AddComponent(m.ID, "component", "DB", "database", "", "manual", -1, -1, t0)
	foreign, _ := s.AddComponent(mB.ID, "component", "X", "", "", "manual", -1, -1, t0)

	if _, err := s.AddFlow(m.ID, a.ID, foreign.ID, "x", t0); err == nil {
		t.Error("cross-model flow accepted")
	}
	if _, err := s.AddFlow(m.ID, a.ID, a.ID, "self", t0); err == nil {
		t.Error("self-flow accepted")
	}
	fl, err := s.AddFlow(m.ID, a.ID, b.ID, "queries", t0)
	if err != nil {
		t.Fatal(err)
	}
	if flows, _ := s.Flows(m.ID); len(flows) != 1 || flows[0].Label != "queries" {
		t.Errorf("flows wrong: %+v", flows)
	}

	// Positions: new components are unplaced (-1); set + clamp + scope.
	if a.X != -1 || a.Y != -1 {
		t.Errorf("new component placed: %v,%v", a.X, a.Y)
	}
	if err := s.SetComponentGeometry(m.ID, a.ID, 120.5, 999999, -1, -1, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetComponentGeometry(mB.ID, a.ID, 1, 1, -1, -1, t0); err != ErrNotFound {
		t.Errorf("cross-model position = %v, want ErrNotFound", err)
	}
	comps, _ := s.Components(m.ID)
	for _, c := range comps {
		if c.ID == a.ID && (c.X != 120.5 || c.Y != 100000) {
			t.Errorf("position not persisted/clamped: %v,%v", c.X, c.Y)
		}
	}

	// Deleting a component removes its flows (FK cascade).
	if err := s.DeleteComponent(m.ID, b.ID, t0); err != nil {
		t.Fatal(err)
	}
	if flows, _ := s.Flows(m.ID); len(flows) != 0 {
		t.Errorf("flow survived its component: %+v (flow %s)", flows, fl.ID)
	}
}

// TestComponentGeometry: canvas geometry (x/y/w/h) persists and clamps, and a
// canvas-placed component keeps its initial position.
func TestComponentGeometry(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	// Placed on creation.
	c, err := s.AddComponent(m.ID, "boundary", "VPC", "", "", "manual", 40, 60, t0)
	if err != nil {
		t.Fatal(err)
	}
	if c.X != 40 || c.Y != 60 || c.W != -1 || c.H != -1 {
		t.Errorf("placed component geometry wrong: %+v", c)
	}
	// Resize (boundary w/h).
	if err := s.SetComponentGeometry(m.ID, c.ID, 40, 60, 320, 240, t0); err != nil {
		t.Fatal(err)
	}
	// Clamp: negative < -1 → -1; huge → 100000.
	if err := s.SetComponentGeometry(m.ID, c.ID, -50, 60, 1e9, 240, t0); err != nil {
		t.Fatal(err)
	}
	comps, _ := s.Components(m.ID)
	got := comps[0]
	if got.X != -1 || got.W != 100000 || got.H != 240 {
		t.Errorf("geometry not clamped/persisted: %+v", got)
	}
	// Cross-model geometry write is refused.
	mB, _ := s.CreateModel("", "B", "", "a", t0)
	if err := s.SetComponentGeometry(mB.ID, c.ID, 1, 1, 1, 1, t0); err != ErrNotFound {
		t.Errorf("cross-model geometry = %v, want ErrNotFound", err)
	}
}

// TestUpdateComponent: edits name/kind/tech; scoped to the model; threats and
// geometry survive.
func TestUpdateComponent(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	c, _ := s.AddComponent(m.ID, "component", "old", "web-app", "", "manual", 10, 20, t0)
	s.EnumerateComponent(c.ID, t0) // give it threats
	beforeThreats, _ := s.Threats(m.ID)

	up, err := s.UpdateComponent(m.ID, c.ID, "asset", "new name", "database", "note", t0)
	if err != nil {
		t.Fatal(err)
	}
	if up.Name != "new name" || up.Kind != "asset" || up.Tech != "database" || up.X != 10 || up.Y != 20 {
		t.Errorf("update wrong (geometry must survive): %+v", up)
	}
	if after, _ := s.Threats(m.ID); len(after) != len(beforeThreats) {
		t.Errorf("update changed threats: %d → %d", len(beforeThreats), len(after))
	}
	// Validation + scope.
	if _, err := s.UpdateComponent(m.ID, c.ID, "component", "  ", "", "", t0); err == nil {
		t.Error("empty name accepted")
	}
	mB, _ := s.CreateModel("", "B", "", "a", t0)
	if _, err := s.UpdateComponent(mB.ID, c.ID, "component", "x", "", "", t0); err != ErrNotFound {
		t.Errorf("cross-model update = %v, want ErrNotFound", err)
	}
}
