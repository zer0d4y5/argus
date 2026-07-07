package server

import (
	"encoding/json"
	"testing"
)

// TestRuleCatalogAndToggle: the catalog lists packs with active/in-profile
// flags, and the toggle endpoint adds/removes a pack from the rulesets and
// activates a saved rule's path the same way.
func TestRuleCatalogAndToggle(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")

	// Operator cannot reach the admin catalog.
	if rec := f.do("GET", "/api/admin/rule-catalog", "", oper); rec.Code != 403 {
		t.Errorf("operator catalog = %d, want 403", rec.Code)
	}

	rec := f.do("GET", "/api/admin/rule-catalog", "", admin)
	if rec.Code != 200 {
		t.Fatalf("catalog: %d %s", rec.Code, rec.Body.String())
	}
	var cat struct {
		Categories []string
		Packs      []struct {
			ID        string
			Category  string
			Active    bool
			InProfile bool
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &cat)
	if len(cat.Categories) == 0 || len(cat.Packs) < 10 {
		t.Fatalf("catalog looks empty: %+v", cat)
	}
	// A language pack in the standard profile is flagged inProfile; nothing is
	// active until toggled.
	var py *struct {
		ID        string
		Category  string
		Active    bool
		InProfile bool
	}
	for i := range cat.Packs {
		if cat.Packs[i].ID == "p/python" {
			py = &cat.Packs[i]
		}
		if cat.Packs[i].Active {
			t.Errorf("pack %s active before any toggle", cat.Packs[i].ID)
		}
	}
	if py == nil || !py.InProfile {
		t.Errorf("p/python should be present and in-profile: %+v", py)
	}

	// Enable a framework pack (not in the profile), confirm it lands in the rulesets.
	if rec := f.do("POST", "/api/admin/rulesets/toggle", `{"entry":"p/react","enabled":true}`, admin); rec.Code != 200 {
		t.Fatalf("enable p/react: %d %s", rec.Code, rec.Body.String())
	}
	cfg := f.srv.effectiveConfig(f.dir)
	if !sliceHas(cfg.SemgrepRules, "+") || !sliceHas(cfg.SemgrepRules, "p/react") {
		t.Errorf("p/react not added additively: %v", cfg.SemgrepRules)
	}
	// The catalog now reports it active.
	rec = f.do("GET", "/api/admin/rule-catalog", "", admin)
	json.Unmarshal(rec.Body.Bytes(), &cat)
	activeReact := false
	for _, p := range cat.Packs {
		if p.ID == "p/react" {
			activeReact = p.Active
		}
	}
	if !activeReact {
		t.Error("p/react not reported active after enable")
	}

	// Disable it, confirm it leaves the rulesets.
	if rec := f.do("POST", "/api/admin/rulesets/toggle", `{"entry":"p/react","enabled":false}`, admin); rec.Code != 200 {
		t.Fatalf("disable p/react: %d %s", rec.Code, rec.Body.String())
	}
	cfg = f.srv.effectiveConfig(f.dir)
	if sliceHas(cfg.SemgrepRules, "p/react") {
		t.Errorf("p/react still present after disable: %v", cfg.SemgrepRules)
	}

	// A remote-URL entry is refused (reuses the ruleset validator).
	if rec := f.do("POST", "/api/admin/rulesets/toggle", `{"entry":"https://evil/x.yml","enabled":true}`, admin); rec.Code != 400 {
		t.Errorf("remote URL toggle = %d, want 400", rec.Code)
	}
}
