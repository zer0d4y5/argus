package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leaky-hub/argus/internal/disposition"
	"github.com/leaky-hub/argus/internal/model"
)

func TestDispositionSetClearAndOverlay(t *testing.T) {
	f := newConsole(t, nil)
	runID, sastID, _ := seedRun(t, f.dir)
	oper := f.mustLogin("oscar")
	view := f.mustLogin("vera")

	// Viewer cannot set a disposition.
	body := fmt.Sprintf(`{"findingId":%q,"status":"accepted-risk","note":"known"}`, sastID)
	if r := f.do("POST", "/api/dispositions", body, view); r.Code != http.StatusForbidden {
		t.Errorf("viewer set got %d, want 403", r.Code)
	}
	// Invalid status rejected.
	if r := f.do("POST", "/api/dispositions", fmt.Sprintf(`{"findingId":%q,"status":"open"}`, sastID), oper); r.Code != http.StatusBadRequest {
		t.Errorf("status=open must be rejected (clear instead), got %d", r.Code)
	}

	// Operator sets accepted-risk.
	if r := f.do("POST", "/api/dispositions", body, oper); r.Code != http.StatusOK {
		t.Fatalf("set disposition: %d %s", r.Code, r.Body.String())
	}

	// It overlays onto the run detail, keyed by finding id. (Fresh struct per
	// GET: Dispositions is omitempty, so an empty overlay is absent from the
	// JSON and reusing a struct would leave a stale value.)
	var afterSet RunDetail
	json.Unmarshal(f.do("GET", "/api/runs/"+runID, "", oper).Body.Bytes(), &afterSet)
	rec, ok := afterSet.Dispositions[sastID]
	if !ok || rec.Status != disposition.StatusAcceptedRisk || rec.Actor != "oscar" || rec.Note != "known" {
		t.Fatalf("disposition overlay = %+v ok=%v", rec, ok)
	}

	// Audit recorded the change with the status, not the note.
	auditBody := f.do("GET", "/api/audit", "", f.mustLogin("alice")).Body.String()
	if !strings.Contains(auditBody, "finding.dispose") || !strings.Contains(auditBody, "accepted-risk") {
		t.Error("finding.dispose audit event missing")
	}
	if strings.Contains(auditBody, `"known"`) {
		t.Error("disposition note leaked into the audit log")
	}

	// Clear → back to open (no record in the overlay).
	if r := f.do("DELETE", "/api/dispositions/"+sastID, "", oper); r.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", r.Code, r.Body.String())
	}
	var afterClear RunDetail
	json.Unmarshal(f.do("GET", "/api/runs/"+runID, "", oper).Body.Bytes(), &afterClear)
	if _, ok := afterClear.Dispositions[sastID]; ok {
		t.Error("cleared disposition still overlaid")
	}
}

// TestDispositionRegressionOverlay: the overlay is keyed by the stable
// fingerprint, so a finding marked "fixed" that is STILL present in a run is a
// regression the overlay surfaces (fixed + present). The cross-run carry
// itself is proven at the store level (disposition_test); the overlay is what
// the run-detail endpoint adds.
func TestDispositionRegressionOverlay(t *testing.T) {
	f := newConsole(t, nil)
	runID, sastID, _ := seedRun(t, f.dir)
	oper := f.mustLogin("oscar")

	body := fmt.Sprintf(`{"findingId":%q,"status":"fixed","note":"patched"}`, sastID)
	if r := f.do("POST", "/api/dispositions", body, oper); r.Code != http.StatusOK {
		t.Fatalf("set fixed: %d %s", r.Code, r.Body.String())
	}

	var detail RunDetail
	json.Unmarshal(f.do("GET", "/api/runs/"+runID, "", oper).Body.Bytes(), &detail)
	rec, ok := detail.Dispositions[sastID]
	if !ok || rec.Status != disposition.StatusFixed {
		t.Fatalf("disposition overlay = %+v ok=%v", rec, ok)
	}
	// The finding it was set "fixed" on is still in the run → regression.
	present := false
	for _, fnd := range detail.Findings {
		if fnd.ID == sastID {
			present = true
		}
	}
	if !present {
		t.Fatal("a fixed finding still present in the run is the regression the UI badges")
	}
}

// TestGateSuppressedByDisposition: accepted-risk and false-positive
// dispositions drop a finding from the gate (but not the report); the count
// is surfaced. in-progress and fixed still gate.
func TestGateSuppressedByDisposition(t *testing.T) {
	high := model.SeverityHigh
	f1 := model.Finding{ID: "a", Severity: model.SeverityHigh}
	f2 := model.Finding{ID: "b", Severity: model.SeverityHigh}
	findings := []model.Finding{f1, f2}

	// No dispositions → gate fails (two high findings).
	if g := gateFor(findings, nil, &high, "high"); !g.Failed || g.Suppressed != 0 {
		t.Errorf("no-disposition gate = %+v, want failed, 0 suppressed", g)
	}
	// Accept the risk on both → gate passes, 2 suppressed.
	disp := map[string]disposition.Record{
		"a": {Status: disposition.StatusAcceptedRisk},
		"b": {Status: disposition.StatusFalsePositive},
	}
	if g := gateFor(findings, disp, &high, "high"); g.Failed || g.Suppressed != 2 {
		t.Errorf("all-dispositioned gate = %+v, want passed, 2 suppressed", g)
	}
	// in-progress still gates (a fix isn't confirmed until re-scan clears it).
	inprog := map[string]disposition.Record{"a": {Status: disposition.StatusInProgress}, "b": {Status: disposition.StatusFixed}}
	if g := gateFor(findings, inprog, &high, "high"); !g.Failed || g.Suppressed != 0 {
		t.Errorf("in-progress/fixed gate = %+v, want failed, 0 suppressed", g)
	}
}

func TestDispositionsBulkEndpoint(t *testing.T) {
	f := newConsole(t, nil)
	runID, sastID, secretID := seedRun(t, f.dir)
	oper := f.mustLogin("oscar")
	view := f.mustLogin("vera")

	body := fmt.Sprintf(`{"findingIds":[%q,%q],"status":"accepted-risk"}`, sastID, secretID)
	// Viewer denied.
	if r := f.do("POST", "/api/dispositions/bulk", body, view); r.Code != http.StatusForbidden {
		t.Errorf("viewer bulk got %d, want 403", r.Code)
	}
	// Operator applies to both in one call.
	r := f.do("POST", "/api/dispositions/bulk", body, oper)
	if r.Code != http.StatusOK {
		t.Fatalf("bulk: %d %s", r.Code, r.Body.String())
	}
	var got map[string]int
	json.Unmarshal(r.Body.Bytes(), &got)
	if got["updated"] != 2 {
		t.Errorf("updated = %d, want 2", got["updated"])
	}
	// Both overlay on the run detail.
	var detail RunDetail
	json.Unmarshal(f.do("GET", "/api/runs/"+runID, "", oper).Body.Bytes(), &detail)
	if detail.Dispositions[sastID].Status != disposition.StatusAcceptedRisk || detail.Dispositions[secretID].Status != disposition.StatusAcceptedRisk {
		t.Errorf("bulk overlay missing: %+v", detail.Dispositions)
	}
	// Clear both (empty status).
	clearBody := fmt.Sprintf(`{"findingIds":[%q,%q]}`, sastID, secretID)
	if r := f.do("POST", "/api/dispositions/bulk", clearBody, oper); r.Code != http.StatusOK {
		t.Fatalf("bulk clear: %d", r.Code)
	}
	var after RunDetail
	json.Unmarshal(f.do("GET", "/api/runs/"+runID, "", oper).Body.Bytes(), &after)
	if len(after.Dispositions) != 0 {
		t.Errorf("expected all cleared, got %+v", after.Dispositions)
	}
}

// TestAggregateSummary: with no registered targets the portfolio (@all)
// summary equals the served repo's; the endpoint routes @all to it.
func TestAggregateSummary(t *testing.T) {
	f := newConsole(t, nil)
	seedRun(t, f.dir)
	oper := f.mustLogin("oscar")

	var scoped, agg SummaryResponse
	json.Unmarshal(f.do("GET", "/api/summary", "", oper).Body.Bytes(), &scoped)
	json.Unmarshal(f.do("GET", "/api/summary?target=@all", "", oper).Body.Bytes(), &agg)
	if agg.Total == 0 || agg.Total != scoped.Total {
		t.Errorf("aggregate total = %d, want = served repo total %d", agg.Total, scoped.Total)
	}
	if agg.BySeverity["high"] != scoped.BySeverity["high"] {
		t.Errorf("aggregate severity mix diverged: %v vs %v", agg.BySeverity, scoped.BySeverity)
	}
}

// TestAggregateDeduplicatesServedRoot: registering the served repo itself as a
// target must not double-count its findings in the portfolio. Its run store
// resolves to the same directory as the served store and is collapsed (F1).
func TestAggregateDeduplicatesServedRoot(t *testing.T) {
	f := newConsole(t, nil)
	seedRun(t, f.dir)
	if _, err := f.registry.Add("dupe", f.dir, nil, ""); err != nil {
		t.Fatal(err)
	}
	oper := f.mustLogin("oscar")

	var scoped, agg SummaryResponse
	json.Unmarshal(f.do("GET", "/api/summary", "", oper).Body.Bytes(), &scoped)
	json.Unmarshal(f.do("GET", "/api/summary?target=@all", "", oper).Body.Bytes(), &agg)
	if scoped.Total == 0 {
		t.Fatal("served summary is empty; fixture seeding failed")
	}
	if agg.Total != scoped.Total {
		t.Errorf("served root registered as a target double-counted: agg=%d scoped=%d", agg.Total, scoped.Total)
	}
}

// TestAggregateCorruptRunFailsClosed: a target whose latest run cannot be read
// must not silently vanish into a passing portfolio. The gate fails and the
// scanned/total counts show the gap (F2).
func TestAggregateCorruptRunFailsClosed(t *testing.T) {
	f := newConsole(t, nil)
	seedRun(t, f.dir) // served store: one readable HIGH run

	// A second dir target with its own run, which we then corrupt.
	other := t.TempDir()
	seedRun(t, other)
	if _, err := f.registry.Add("other", other, nil, ""); err != nil {
		t.Fatal(err)
	}
	runsDir := filepath.Join(other, ".appsec", "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no run files to corrupt in %s: %v", runsDir, err)
	}
	if err := os.WriteFile(filepath.Join(runsDir, entries[0].Name()), []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	oper := f.mustLogin("oscar")
	var agg SummaryResponse
	json.Unmarshal(f.do("GET", "/api/summary?target=@all", "", oper).Body.Bytes(), &agg)
	if !agg.Gate.Failed {
		t.Error("aggregate gate passed despite an unreadable target run; must fail closed")
	}
	if agg.ScannedTargets >= agg.TotalTargets {
		t.Errorf("scanned=%d total=%d: an unreadable target should widen the gap", agg.ScannedTargets, agg.TotalTargets)
	}
}
