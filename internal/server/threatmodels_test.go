package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/leaky-hub/argus/internal/config"
	"github.com/leaky-hub/argus/internal/llm"
)

// TestThreatModelLifecycle drives the threat-model endpoints: create a model,
// add a component, enumerate STRIDE from the curated library, set a threat's
// status, link it to a finding, then admin delete.
func TestThreatModelLifecycle(t *testing.T) {
	f := newConsole(t, nil)
	_, sastID, _ := seedRun(t, f.dir)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	viewer := f.mustLogin("vera")

	// The library lists component types for the picker.
	rec := f.do("GET", "/api/threat-library", "", viewer)
	if rec.Code != 200 || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("threat-library: %d", rec.Code)
	}

	// Operator creates a model.
	rec = f.do("POST", "/api/threat-models", `{"name":"Checkout","targetId":""}`, oper)
	if rec.Code != 201 {
		t.Fatalf("create model: %d %s", rec.Code, rec.Body.String())
	}
	var m struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &m)

	// Add a web-app component.
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"name":"Web frontend","tech":"web-app","kind":"component"}`, oper)
	if rec.Code != 201 {
		t.Fatalf("add component: %d %s", rec.Code, rec.Body.String())
	}
	var c struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &c)

	// Enumerate STRIDE for it.
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/enumerate", `{"componentId":"`+c.ID+`"}`, oper)
	if rec.Code != 200 {
		t.Fatalf("enumerate: %d %s", rec.Code, rec.Body.String())
	}
	var en struct{ Added int }
	json.Unmarshal(rec.Body.Bytes(), &en)
	if en.Added == 0 {
		t.Error("enumerate added no threats")
	}

	// Detail carries the enumerated threats.
	rec = f.do("GET", "/api/threat-models/"+m.ID, "", viewer)
	var detail struct {
		Threats []struct {
			ID       string
			Category string
			Status   string
			Source   string
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &detail)
	if len(detail.Threats) != en.Added {
		t.Fatalf("detail threats = %d, want %d", len(detail.Threats), en.Added)
	}
	th := detail.Threats[0]
	if th.Source != "curated" || th.Status != "open" {
		t.Errorf("bad enumerated threat: %+v", th)
	}

	// Set a status and link a finding.
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/threat-status", `{"threatId":"`+th.ID+`","status":"mitigated"}`, oper); rec.Code != 200 {
		t.Errorf("status: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/links", `{"threatId":"`+th.ID+`","kind":"finding","ref":"`+sastID+`","targetId":""}`, oper); rec.Code != 200 {
		t.Errorf("link: %d %s", rec.Code, rec.Body.String())
	}
	// A finding link must reference a real finding in the target's latest run.
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/links", `{"threatId":"`+th.ID+`","kind":"finding","ref":"fp-bogus","targetId":""}`, oper); rec.Code != 400 {
		t.Errorf("garbage finding link = %d, want 400", rec.Code)
	}

	// A threat is only addressable through its own model: another model's URL
	// cannot move its status or attach links to it.
	rec = f.do("POST", "/api/threat-models", `{"name":"Other"}`, oper)
	var other struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &other)
	if rec := f.do("POST", "/api/threat-models/"+other.ID+"/threat-status", `{"threatId":"`+th.ID+`","status":"accepted"}`, oper); rec.Code != 404 {
		t.Errorf("cross-model status = %d, want 404", rec.Code)
	}
	if rec := f.do("POST", "/api/threat-models/"+other.ID+"/links", `{"threatId":"`+th.ID+`","kind":"control","ref":"ASVS:V1.1.1"}`, oper); rec.Code != 404 {
		t.Errorf("cross-model link = %d, want 404", rec.Code)
	}
	f.do("DELETE", "/api/threat-models/"+other.ID, "", admin)

	// A hand-authored threat records source=manual, whatever the caller claims.
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/threats", `{"category":"tampering","title":"Hand-typed","source":"curated"}`, oper)
	if rec.Code != 201 {
		t.Fatalf("add threat: %d %s", rec.Code, rec.Body.String())
	}
	var handmade struct{ Source string }
	json.Unmarshal(rec.Body.Bytes(), &handmade)
	if handmade.Source != "manual" {
		t.Errorf("hand-authored source = %q, want manual", handmade.Source)
	}

	// Viewer cannot mutate; only admin deletes.
	if rec := f.do("POST", "/api/threat-models", `{"name":"x"}`, viewer); rec.Code != 403 {
		t.Errorf("viewer create = %d, want 403", rec.Code)
	}
	if rec := f.do("DELETE", "/api/threat-models/"+m.ID, "", oper); rec.Code != 403 {
		t.Errorf("operator delete = %d, want 403", rec.Code)
	}
	if rec := f.do("DELETE", "/api/threat-models/"+m.ID, "", admin); rec.Code != 200 {
		t.Errorf("admin delete = %d %s", rec.Code, rec.Body.String())
	}
}

// TestThreatModelFromTargetIaC: scanning a target dir with IaC builds a baseline
// model with the detected components and enumerated STRIDE, deterministically.
func TestThreatModelFromTargetIaC(t *testing.T) {
	f := newConsole(t, nil)
	oper := f.mustLogin("oscar")
	// The fixture's registered target points at f.scanDir; drop some IaC there.
	writeFile(t, f.scanDir, "main.tf", `
resource "aws_db_instance" "primary" {}
resource "aws_s3_bucket" "assets" {}
`)
	rec := f.do("POST", "/api/threat-models/from-target", `{"targetId":"`+f.targetID+`","name":"Prod baseline"}`, oper)
	if rec.Code != 201 {
		t.Fatalf("from-target: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ModelID    string
		Components int
		Threats    int
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Components != 2 || out.Threats == 0 {
		t.Errorf("baseline: components=%d threats=%d, want 2 components and some threats", out.Components, out.Threats)
	}
}

// TestThreatSuggest: the assisted pass returns validated candidates (STRIDE only,
// injection text inert) without persisting them; a confirm adds one as assisted.
func TestThreatSuggest(t *testing.T) {
	f := newConsole(t, nil)
	f.srv.llmFactory = func(config.Config) llm.Client {
		return &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) {
			return `{"threats":[
				{"category":"tampering","title":"CI pipeline poisoning","description":"An attacker with commit access alters the build."},
				{"category":"not-stride","title":"dropped","description":"x"}
			]}`, nil
		}}
	}
	oper := f.mustLogin("oscar")
	rec := f.do("POST", "/api/threat-models", `{"name":"Svc"}`, oper)
	var m struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &m)

	rec = f.do("POST", "/api/threat-models/"+m.ID+"/suggest", "{}", oper)
	if rec.Code != 200 {
		t.Fatalf("suggest: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Suggestions []struct{ Category, Title string }
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Suggestions) != 1 || out.Suggestions[0].Category != "tampering" {
		t.Fatalf("suggestions filtered wrong: %+v", out.Suggestions)
	}

	// Suggestions are NOT persisted until confirmed.
	det := f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	var d struct{ Threats []any }
	json.Unmarshal(det.Body.Bytes(), &d)
	if len(d.Threats) != 0 {
		t.Errorf("suggestions were persisted without confirmation: %d", len(d.Threats))
	}

	// Confirming adds it as source=assisted.
	body := `{"category":"tampering","title":"CI pipeline poisoning","description":"x","source":"assisted"}`
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/threats", body, oper); rec.Code != 201 {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	det = f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	var d2 struct {
		Threats []struct{ Source string }
	}
	json.Unmarshal(det.Body.Bytes(), &d2)
	if len(d2.Threats) != 1 || d2.Threats[0].Source != "assisted" {
		t.Errorf("confirmed threat not assisted: %+v", d2.Threats)
	}
}

// TestSuggestComponents: the assisted component pass returns validated
// candidates built from the repo outline, persists nothing, and a confirm
// stores source=assisted. Off-enum tech from the model is dropped.
func TestSuggestComponents(t *testing.T) {
	f := newConsole(t, nil)
	var gotPrompt string
	f.srv.llmFactory = func(config.Config) llm.Client {
		return &llm.Fake{IsLocal: true, Respond: func(req llm.Request) (string, error) {
			gotPrompt = req.User
			return `{"components":[
				{"name":"Payments DB","tech":"database","kind":"component","rationale":"compose file"},
				{"name":"Nonsense","tech":"quantum","kind":"component","rationale":"dropped"}
			]}`, nil
		}}
	}
	oper := f.mustLogin("oscar")
	// Give the served repo something for the outline and the IaC scan.
	writeFile(t, f.dir, "go.mod", "module demo\n")
	writeFile(t, f.dir, "main.tf", `resource "aws_s3_bucket" "assets" {}`)

	rec := f.do("POST", "/api/threat-models", `{"name":"Svc"}`, oper)
	var m struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &m)

	rec = f.do("POST", "/api/threat-models/"+m.ID+"/suggest-components", "{}", oper)
	if rec.Code != 200 {
		t.Fatalf("suggest-components: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Suggestions []struct{ Name, Tech, Kind string }
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Suggestions) != 1 || out.Suggestions[0].Tech != "database" {
		t.Fatalf("suggestions filtered wrong: %+v", out.Suggestions)
	}
	// The prompt carried the outline and the deterministic detection.
	if !strings.Contains(gotPrompt, "go.mod") {
		t.Error("repo outline missing from prompt")
	}
	if !strings.Contains(gotPrompt, "assets (object-store)") {
		t.Error("iacdetect result missing from prompt")
	}

	// Nothing persisted until confirmed.
	det := f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	var d struct{ Components []struct{ Source string } }
	json.Unmarshal(det.Body.Bytes(), &d)
	if len(d.Components) != 0 {
		t.Errorf("suggestions were persisted without confirmation: %d", len(d.Components))
	}

	// Confirming stores source=assisted; a caller cannot claim "detected".
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"name":"Payments DB","tech":"database","source":"assisted"}`, oper); rec.Code != 201 {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"name":"Fake","tech":"database","source":"detected"}`, oper); rec.Code != 201 {
		t.Fatalf("add: %d", rec.Code)
	}
	det = f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	json.Unmarshal(det.Body.Bytes(), &d)
	if len(d.Components) != 2 || d.Components[1].Source != "assisted" || d.Components[0].Source != "manual" {
		t.Errorf("component sources wrong: %+v", d.Components)
	}
}

// TestComponentAndThreatRemove: the Remove flag on the POST subresources
// deletes a component (with its threats) or a single threat, operator-level.
func TestComponentAndThreatRemove(t *testing.T) {
	f := newConsole(t, nil)
	oper := f.mustLogin("oscar")
	viewer := f.mustLogin("vera")
	rec := f.do("POST", "/api/threat-models", `{"name":"Svc"}`, oper)
	var m struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &m)
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"name":"DB","tech":"database"}`, oper)
	var c struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &c)
	f.do("POST", "/api/threat-models/"+m.ID+"/enumerate", `{"componentId":"`+c.ID+`"}`, oper)

	// Viewer cannot remove.
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"remove":true,"componentId":"`+c.ID+`"}`, viewer); rec.Code != 403 {
		t.Errorf("viewer remove = %d, want 403", rec.Code)
	}
	// Operator removes the component; its threats go with it.
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"remove":true,"componentId":"`+c.ID+`"}`, oper); rec.Code != 200 {
		t.Fatalf("remove component: %d %s", rec.Code, rec.Body.String())
	}
	det := f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	var d struct {
		Components []any
		Threats    []any
	}
	json.Unmarshal(det.Body.Bytes(), &d)
	if len(d.Components) != 0 || len(d.Threats) != 0 {
		t.Errorf("after remove: %d components, %d threats; want 0, 0", len(d.Components), len(d.Threats))
	}

	// Single-threat remove.
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/threats", `{"category":"tampering","title":"T"}`, oper)
	var th struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &th)
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/threats", `{"remove":true,"threatId":"`+th.ID+`"}`, oper); rec.Code != 200 {
		t.Fatalf("remove threat: %d %s", rec.Code, rec.Body.String())
	}
	det = f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	json.Unmarshal(det.Body.Bytes(), &d)
	if len(d.Threats) != 0 {
		t.Errorf("threat not removed: %d", len(d.Threats))
	}
}

// TestRepoOutlineBounded: the outline lists manifests and shallow dirs, skips
// vendored trees, and never exceeds its cap.
func TestRepoOutlineBounded(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module x\n")
	writeFile(t, dir, "src/api/handler.go", "package api\n")
	writeFile(t, dir, "node_modules/dep/package.json", "{}")
	writeFile(t, dir, ".git/config", "")
	for i := 0; i < 200; i++ {
		writeFile(t, dir, fmt.Sprintf("zfiller/d%03d/x.txt", i), "")
	}
	lines := repoOutline(dir)
	if len(lines) > outlineMaxEntries {
		t.Errorf("outline %d lines, cap %d", len(lines), outlineMaxEntries)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "file: go.mod") {
		t.Error("manifest missing from outline")
	}
	if !strings.Contains(joined, "dir: src/api/") {
		t.Error("shallow dir missing from outline")
	}
	if strings.Contains(joined, "node_modules") || strings.Contains(joined, ".git") {
		t.Error("outline walked a skip dir")
	}
}

// TestCanvasComponentEditing: create a component at a canvas position, update
// it (rename/re-tech), and save geometry (position + boundary size) — all via
// the components/positions endpoints the canvas uses.
func TestCanvasComponentEditing(t *testing.T) {
	f := newConsole(t, nil)
	oper := f.mustLogin("oscar")
	rec := f.do("POST", "/api/threat-models", `{"name":"Arch"}`, oper)
	var m struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &m)

	// Placed on creation via the canvas (x/y).
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"name":"API","tech":"api-service","kind":"component","x":120,"y":80}`, oper)
	if rec.Code != 201 {
		t.Fatalf("create placed: %d %s", rec.Code, rec.Body.String())
	}
	var c struct {
		ID      string
		X, Y    float64
	}
	json.Unmarshal(rec.Body.Bytes(), &c)
	if c.X != 120 || c.Y != 80 {
		t.Errorf("placement not kept: %+v", c)
	}

	// Update (rename + re-tech + re-kind) via the same endpoint with componentId.
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"componentId":"`+c.ID+`","name":"Gateway","tech":"web-app","kind":"boundary"}`, oper)
	if rec.Code != 200 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	var up struct{ Name, Kind, Tech string; X, Y float64 }
	json.Unmarshal(rec.Body.Bytes(), &up)
	if up.Name != "Gateway" || up.Kind != "boundary" || up.Tech != "web-app" || up.X != 120 {
		t.Errorf("update wrong (geometry must survive): %+v", up)
	}

	// Save geometry with a boundary size.
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/positions", `{"positions":[{"componentId":"`+c.ID+`","x":200,"y":100,"w":340,"h":260}]}`, oper)
	if rec.Code != 200 {
		t.Fatalf("positions: %d %s", rec.Code, rec.Body.String())
	}
	det := f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	var d struct{ Components []struct{ X, Y, W, H float64 } }
	json.Unmarshal(det.Body.Bytes(), &d)
	if len(d.Components) != 1 || d.Components[0].W != 340 || d.Components[0].H != 260 || d.Components[0].X != 200 {
		t.Errorf("geometry not persisted: %+v", d.Components)
	}
}
