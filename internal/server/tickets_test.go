package server

import (
	"encoding/json"
	"testing"

	"github.com/leaky-hub/argus/internal/disposition"
)

// TestTicketLifecycle drives the ticket endpoints end to end: create from a
// finding selection, list with a computed severity rollup, comment, update,
// and the close-fixed bridge that writes a "fixed" disposition. Then admin-only
// delete.
func TestTicketLifecycle(t *testing.T) {
	f := newConsole(t, nil)
	_, sastID, _ := seedRun(t, f.dir) // a HIGH SQLi finding in the served store
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	viewer := f.mustLogin("vera")

	// Operator creates a ticket linking the seeded finding (served store => target "").
	body := `{"title":"Fix the SQLi","priority":"high","targetId":"","findingIds":["` + sastID + `"]}`
	rec := f.do("POST", "/api/tickets", body, oper)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatal("no ticket id returned")
	}

	// Viewer can read; the list rollup resolves the linked finding's severity.
	rec = f.do("GET", "/api/tickets", "", viewer)
	if rec.Code != 200 {
		t.Fatalf("list: %d", rec.Code)
	}
	var list struct {
		Tickets []struct {
			ID        string
			LinkCount int
			Rollup    struct {
				Total, Resolved int
				Max             string
			}
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Tickets) != 1 {
		t.Fatalf("list len = %d, want 1", len(list.Tickets))
	}
	tk := list.Tickets[0]
	if tk.LinkCount != 1 || tk.Rollup.Resolved != 1 || tk.Rollup.Max != "high" {
		t.Errorf("rollup wrong: %+v", tk.Rollup)
	}

	// Operator comments and updates.
	if rec := f.do("POST", "/api/tickets/"+created.ID+"/comments", `{"body":"on it"}`, oper); rec.Code != 201 {
		t.Errorf("comment: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("PATCH", "/api/tickets/"+created.ID, `{"status":"in-progress"}`, oper); rec.Code != 200 {
		t.Errorf("update: %d %s", rec.Code, rec.Body.String())
	}

	// Viewer cannot mutate.
	if rec := f.do("PATCH", "/api/tickets/"+created.ID, `{"status":"done"}`, viewer); rec.Code != 403 {
		t.Errorf("viewer update = %d, want 403", rec.Code)
	}

	// close-fixed marks the linked finding fixed via the disposition store.
	rec = f.do("POST", "/api/tickets/"+created.ID+"/close-fixed", "{}", oper)
	if rec.Code != 200 {
		t.Fatalf("close-fixed: %d %s", rec.Code, rec.Body.String())
	}
	var cf struct{ MarkedFixed int }
	json.Unmarshal(rec.Body.Bytes(), &cf)
	if cf.MarkedFixed != 1 {
		t.Errorf("markedFixed = %d, want 1", cf.MarkedFixed)
	}
	// The disposition store (served repo) now records the finding as fixed.
	disp, _ := dispositionStore(f.srv.store).All()
	if rec, ok := disp[sastID]; !ok || rec.Status != disposition.StatusFixed {
		t.Errorf("finding not marked fixed via ticket: %+v ok=%v", rec, ok)
	}

	// Operator cannot delete; admin can.
	if rec := f.do("DELETE", "/api/tickets/"+created.ID, "", oper); rec.Code != 403 {
		t.Errorf("operator delete = %d, want 403", rec.Code)
	}
	if rec := f.do("DELETE", "/api/tickets/"+created.ID, "", admin); rec.Code != 200 {
		t.Errorf("admin delete = %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("GET", "/api/tickets/"+created.ID, "", viewer); rec.Code != 404 {
		t.Errorf("get after delete = %d, want 404", rec.Code)
	}
}

// TestTicketLinkRequiresRealFinding: a link is only accepted for a finding
// present in the target's latest run. Links feed the close-fixed bridge (they
// become "fixed" dispositions), so a garbage fingerprint or an unknown target
// must be rejected at the API, with no half-created ticket left behind.
func TestTicketLinkRequiresRealFinding(t *testing.T) {
	f := newConsole(t, nil)
	_, sastID, _ := seedRun(t, f.dir)
	oper := f.mustLogin("oscar")

	// A fingerprint that exists in no run is rejected at creation…
	rec := f.do("POST", "/api/tickets", `{"title":"x","findingIds":["not-a-real-fingerprint"]}`, oper)
	if rec.Code != 400 {
		t.Errorf("create with garbage finding = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	// …and the ticket must not have been created before validation failed.
	rec = f.do("GET", "/api/tickets", "", oper)
	var list struct{ Tickets []struct{ ID string } }
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Tickets) != 0 {
		t.Errorf("bad create left %d ticket(s) behind", len(list.Tickets))
	}

	// An unknown target is rejected even with a real-looking fingerprint.
	rec = f.do("POST", "/api/tickets", `{"title":"x","targetId":"tg-nope","findingIds":["`+sastID+`"]}`, oper)
	if rec.Code != 400 {
		t.Errorf("create with unknown target = %d, want 400", rec.Code)
	}

	// The link subresource enforces the same rule.
	rec = f.do("POST", "/api/tickets", `{"title":"x","findingIds":["`+sastID+`"]}`, oper)
	if rec.Code != 201 {
		t.Fatalf("valid create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &created)
	if rec := f.do("POST", "/api/tickets/"+created.ID+"/links", `{"findingId":"garbage"}`, oper); rec.Code != 400 {
		t.Errorf("link garbage finding = %d, want 400", rec.Code)
	}
	// Removing a link never requires validation (cleanup must always work).
	if rec := f.do("POST", "/api/tickets/"+created.ID+"/links", `{"findingId":"garbage","remove":true}`, oper); rec.Code != 200 {
		t.Errorf("unlink garbage finding = %d, want 200", rec.Code)
	}
}

// TestTicketCloseFixedGuards pins the close-fixed bridge's two guards: it never
// overwrites a gate-suppressing human disposition (accepted-risk /
// false-positive), and it never writes a disposition for a fingerprint that is
// not in the target's latest run (a stale or CLI-injected garbage link). Both
// are reported honestly instead of silently dropped.
func TestTicketCloseFixedGuards(t *testing.T) {
	f := newConsole(t, nil)
	_, sastID, secretID := seedRun(t, f.dir)
	oper := f.mustLogin("oscar")

	// A human already accepted the risk of the secret finding, with a note.
	rec := f.do("POST", "/api/dispositions", `{"findingId":"`+secretID+`","status":"accepted-risk","note":"known dev key"}`, oper)
	if rec.Code != 200 && rec.Code != 201 {
		t.Fatalf("seed disposition: %d %s", rec.Code, rec.Body.String())
	}

	rec = f.do("POST", "/api/tickets", `{"title":"x","findingIds":["`+sastID+`","`+secretID+`"]}`, oper)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &created)

	// A garbage link injected below the API (the CLI writes straight to the
	// domain store) must be skipped at close time, not turned into a disposition.
	if err := f.srv.tickets.Link(created.ID, "gone-fingerprint", ""); err != nil {
		t.Fatal(err)
	}

	rec = f.do("POST", "/api/tickets/"+created.ID+"/close-fixed", "{}", oper)
	if rec.Code != 200 {
		t.Fatalf("close-fixed: %d %s", rec.Code, rec.Body.String())
	}
	var cf struct{ MarkedFixed, Skipped, Kept int }
	json.Unmarshal(rec.Body.Bytes(), &cf)
	if cf.MarkedFixed != 1 || cf.Skipped != 1 || cf.Kept != 1 {
		t.Errorf("close-fixed = %+v, want markedFixed 1, skipped 1, kept 1", cf)
	}

	disp, _ := dispositionStore(f.srv.store).All()
	if rec := disp[sastID]; rec.Status != disposition.StatusFixed {
		t.Errorf("sast finding = %q, want fixed", rec.Status)
	}
	if rec := disp[secretID]; rec.Status != disposition.StatusAcceptedRisk || rec.Note != "known dev key" {
		t.Errorf("accepted-risk was clobbered: %+v", rec)
	}
	if _, ok := disp["gone-fingerprint"]; ok {
		t.Error("garbage link produced a disposition record")
	}
}

// TestTicketValidation: bad input is rejected with 400.
func TestTicketValidation(t *testing.T) {
	f := newConsole(t, nil)
	oper := f.mustLogin("oscar")
	if rec := f.do("POST", "/api/tickets", `{"title":"  "}`, oper); rec.Code != 400 {
		t.Errorf("empty title = %d, want 400", rec.Code)
	}
	if rec := f.do("POST", "/api/tickets", `{"title":"x","priority":"bogus"}`, oper); rec.Code != 400 {
		t.Errorf("bad priority = %d, want 400", rec.Code)
	}
	rec := f.do("POST", "/api/tickets", `{"title":"x"}`, oper)
	var tk struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &tk)
	if rec := f.do("PATCH", "/api/tickets/"+tk.ID, `{"status":"nope"}`, oper); rec.Code != 400 {
		t.Errorf("bad status = %d, want 400", rec.Code)
	}
}
