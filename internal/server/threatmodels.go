package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/leaky-hub/argus/internal/audit"
	"github.com/leaky-hub/argus/internal/config"
	"github.com/leaky-hub/argus/internal/iacdetect"
	"github.com/leaky-hub/argus/internal/llm"
	"github.com/leaky-hub/argus/internal/pipeline"
	"github.com/leaky-hub/argus/internal/targets"
	"github.com/leaky-hub/argus/internal/threatlib"
	"github.com/leaky-hub/argus/internal/threatmodel"
	"github.com/leaky-hub/argus/internal/triage"
)

// Threat-modeling endpoints. A model is scoped to a target; its components drive
// deterministic STRIDE enumeration from the curated library (internal/threatlib),
// and its threats link to real findings, controls, and mitigations. Operators
// create and edit, admins delete, every mutation is audited. The LLM never sets
// a threat's status (no assisted pass in v1); content is curated or hand-authored.

// handleThreatLibrary: GET the curated component types, for the "add component"
// tech picker.
func (s *Server) handleThreatLibrary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": threatlib.Components()})
}

// ThreatModelDetail is the full model payload.
type ThreatModelDetail struct {
	threatmodel.Model
	Components []threatmodel.Component       `json:"components"`
	Threats    []threatmodel.Threat          `json:"threats"`
	Links      map[string][]threatmodel.Link `json:"links"`
	Flows      []threatmodel.Flow            `json:"flows"`
}

func (s *Server) handleThreatModels(w http.ResponseWriter, r *http.Request) {
	if s.threats == nil {
		writeErr(w, http.StatusNotFound, "threat modeling is not enabled")
		return
	}
	switch r.Method {
	case http.MethodGet:
		models, err := s.threats.ListModels(r.URL.Query().Get("target"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list models")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"models": models})
	case http.MethodPost:
		var req struct{ TargetID, Name, Description string }
		if err := decodeBody(w, r, &req, 1<<20); err != nil {
			return
		}
		m, err := s.threats.CreateModel(req.TargetID, req.Name, req.Description, actorFrom(r), time.Now())
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(audit.EventThreatModel, actorFrom(r), map[string]string{"model": m.ID, "target": req.TargetID, "action": "create"})
		writeJSON(w, http.StatusCreated, m)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleThreatModelByID(w http.ResponseWriter, r *http.Request) {
	if s.threats == nil {
		writeErr(w, http.StatusNotFound, "threat modeling is not enabled")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/threat-models/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid model id")
		return
	}
	actor := actorFrom(r)
	now := time.Now()

	// from-target is a create-like action (operator, under the POST /… rule):
	// scan a target's IaC and build a baseline model with enumerated STRIDE.
	if id == "from-target" && sub == "" && r.Method == http.MethodPost {
		s.threatModelFromTarget(w, r, actor, now)
		return
	}

	switch {
	case sub == "" && r.Method == http.MethodGet:
		m, err := s.threats.GetModel(id)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		comps, _ := s.threats.Components(id)
		threats, _ := s.threats.Threats(id)
		links, _ := s.threats.LinksForModel(id)
		if links == nil {
			links = map[string][]threatmodel.Link{}
		}
		flows, _ := s.threats.Flows(id)
		writeJSON(w, http.StatusOK, ThreatModelDetail{Model: m, Components: comps, Threats: threats, Links: links, Flows: flows})

	case sub == "" && r.Method == http.MethodDelete:
		if err := s.threats.DeleteModel(id); err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatModel, actor, map[string]string{"model": id, "action": "delete"})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case sub == "components" && r.Method == http.MethodPost:
		var req struct {
			Kind, Name, Tech, Notes, Source, ComponentID string
			X, Y                                         *float64
			Remove                                       bool
		}
		if err := decodeBody(w, r, &req, 1<<20); err != nil {
			return
		}
		// Remove follows the links endpoint's pattern: an operator-level edit
		// on the POST subresource. Deleting a component removes its threats.
		if req.Remove {
			if err := s.threats.DeleteComponent(id, req.ComponentID, now); err != nil {
				s.writeThreatErr(w, err)
				return
			}
			s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "remove-component"})
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		// An existing component id (without remove) is an edit: rename / re-kind
		// / re-tech from the canvas or list.
		if req.ComponentID != "" {
			c, err := s.threats.UpdateComponent(id, req.ComponentID, req.Kind, req.Name, req.Tech, req.Notes, now)
			if err != nil {
				s.writeThreatErr(w, err)
				return
			}
			s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "update-component"})
			writeJSON(w, http.StatusOK, c)
			return
		}
		// API callers add by hand or confirm an LLM proposal; "detected" is
		// reserved for the server's own IaC scan.
		source := "manual"
		if req.Source == "assisted" {
			source = "assisted"
		}
		x, y := -1.0, -1.0
		if req.X != nil && req.Y != nil {
			x, y = *req.X, *req.Y
		}
		c, err := s.threats.AddComponent(id, req.Kind, req.Name, req.Tech, req.Notes, source, x, y, now)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "add-component", "source": source})
		writeJSON(w, http.StatusCreated, c)

	case sub == "enumerate" && r.Method == http.MethodPost:
		var req struct{ ComponentID string }
		if err := decodeBody(w, r, &req, 8192); err != nil {
			return
		}
		n, err := s.threats.EnumerateComponent(req.ComponentID, now)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "enumerate", "added": itoa(n)})
		writeJSON(w, http.StatusOK, map[string]int{"added": n})

	case sub == "threats" && r.Method == http.MethodPost:
		var req struct {
			ComponentID, Category, Title, Description, Mitigation, Source, ThreatID string
			Remove                                                                  bool
		}
		if err := decodeBody(w, r, &req, 1<<20); err != nil {
			return
		}
		if req.Remove {
			if err := s.threats.DeleteThreat(id, req.ThreatID, now); err != nil {
				s.writeThreatErr(w, err)
				return
			}
			s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "remove-threat"})
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		source := "manual" // hand-authored; confirming an AI suggestion sends source="assisted"
		if req.Source == "assisted" {
			source = "assisted"
		}
		t, err := s.threats.AddThreat(id, req.ComponentID, req.Category, req.Title, req.Description, source, req.Mitigation, actor, now)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "add-threat", "source": source})
		writeJSON(w, http.StatusCreated, t)

	case sub == "positions" && r.Method == http.MethodPost:
		// Batch layout save (drag end). Presentation state only: never touches
		// enumeration, status, or the gate. Unknown component ids are skipped.
		var req struct {
			Positions []struct {
				ComponentID string
				X, Y        float64
				W, H        *float64
			}
		}
		if err := decodeBody(w, r, &req, 1<<20); err != nil {
			return
		}
		if len(req.Positions) > 500 {
			writeErr(w, http.StatusBadRequest, "too many positions")
			return
		}
		saved := 0
		for _, p := range req.Positions {
			w2, h2 := -1.0, -1.0
			if p.W != nil {
				w2 = *p.W
			}
			if p.H != nil {
				h2 = *p.H
			}
			if err := s.threats.SetComponentGeometry(id, p.ComponentID, p.X, p.Y, w2, h2, now); err == nil {
				saved++
			}
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "layout", "nodes": itoa(saved)})
		writeJSON(w, http.StatusOK, map[string]int{"saved": saved})

	case sub == "flows" && r.Method == http.MethodPost:
		var req struct {
			FromID, ToID, Label, FlowID string
			Remove                      bool
		}
		if err := decodeBody(w, r, &req, 8192); err != nil {
			return
		}
		if req.Remove {
			if err := s.threats.DeleteFlow(id, req.FlowID, now); err != nil {
				s.writeThreatErr(w, err)
				return
			}
			s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "remove-flow"})
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		fl, err := s.threats.AddFlow(id, req.FromID, req.ToID, req.Label, now)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "add-flow"})
		writeJSON(w, http.StatusCreated, fl)

	case sub == "suggest" && r.Method == http.MethodPost:
		s.suggestThreats(w, r, id)

	case sub == "suggest-components" && r.Method == http.MethodPost:
		s.suggestComponents(w, r, id)

	case sub == "threat-status" && r.Method == http.MethodPost:
		var req struct{ ThreatID, Status string }
		if err := decodeBody(w, r, &req, 8192); err != nil {
			return
		}
		if err := s.threats.SetThreatStatus(id, req.ThreatID, req.Status, now); err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "status", "status": req.Status})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case sub == "links" && r.Method == http.MethodPost:
		var req struct {
			ThreatID, Kind, Ref, TargetID string
			Remove                        bool
		}
		if err := decodeBody(w, r, &req, 8192); err != nil {
			return
		}
		var err error
		if req.Remove {
			err = s.threats.UnlinkThreat(id, req.ThreatID, req.Kind, req.Ref, req.TargetID)
		} else {
			// A finding link must reference a real finding, same rule as ticket
			// links; control/mitigation refs are curated ids, checked on render.
			if req.Kind == "finding" {
				if msg := s.validateFindingLink(req.TargetID, req.Ref, nil); msg != "" {
					writeErr(w, http.StatusBadRequest, msg)
					return
				}
			}
			err = s.threats.LinkThreat(id, req.ThreatID, req.Kind, req.Ref, req.TargetID)
		}
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "link", "kind": req.Kind})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	default:
		writeErr(w, http.StatusNotFound, "unknown threat-model action")
	}
}

// threatModelFromTarget scans a target's infrastructure-as-code, creates a
// baseline model with the detected components, and enumerates STRIDE over each —
// deterministic, no LLM. Bootstraps a threat model from what the repo declares.
func (s *Server) threatModelFromTarget(w http.ResponseWriter, r *http.Request, actor string, now time.Time) {
	var req struct{ TargetID, Name string }
	if err := decodeBody(w, r, &req, 8192); err != nil {
		return
	}
	dir, ok := s.targetDir(req.TargetID)
	if !ok {
		writeErr(w, http.StatusBadRequest, "target has no local directory to scan")
		return
	}
	comps, err := iacdetect.Scan(dir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to scan target")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Baseline threat model"
	}
	m, err := s.threats.CreateModel(req.TargetID, name, "Generated from infrastructure-as-code in the target. Review and refine.", actor, now)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	threatCount := 0
	for _, c := range comps {
		comp, err := s.threats.AddComponent(m.ID, "component", c.Name, c.Tech, "from "+c.Source, "detected", -1, -1, now)
		if err != nil {
			continue
		}
		if n, err := s.threats.EnumerateComponent(comp.ID, now); err == nil {
			threatCount += n
		}
	}
	s.audit(audit.EventThreatModel, actor, map[string]string{
		"model": m.ID, "target": req.TargetID, "action": "from-target",
		"components": itoa(len(comps)), "threats": itoa(threatCount),
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"modelId": m.ID, "components": len(comps), "threats": threatCount,
	})
}

// suggestThreats asks the target's configured LLM to propose additional STRIDE
// threats for a model. Advisory only: the candidates are returned, never
// persisted — the human confirms each via POST .../threats with source=assisted.
// Same seam discipline as explain: config comes from the target tree, request
// input can't pick the provider, output is validated against the STRIDE enum.
func (s *Server) suggestThreats(w http.ResponseWriter, r *http.Request, id string) {
	m, err := s.threats.GetModel(id)
	if err != nil {
		s.writeThreatErr(w, err)
		return
	}
	comps, _ := s.threats.Components(id)
	existing, _ := s.threats.Threats(id)

	in := triage.SuggestInput{AppName: m.Name}
	for _, c := range comps {
		in.Components = append(in.Components, triage.SuggestComponent{Name: c.Name, Tech: c.Tech})
	}
	for _, t := range existing {
		in.ExistingTitles = append(in.ExistingTitles, t.Title)
	}
	in.FindingCategories = s.findingCategoriesFor(m.TargetID)

	client, cfg, ok := s.llmClientForTarget(w, r, m.TargetID)
	if !ok {
		return
	}
	suggestions, err := triage.SuggestThreats(r.Context(), client, in, time.Duration(cfg.Triage.TimeoutSec)*time.Second)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(audit.EventThreatUpdate, actorFrom(r), map[string]string{"model": id, "action": "suggest", "count": itoa(len(suggestions))})
	writeJSON(w, http.StatusOK, map[string]any{"suggestions": suggestions, "model": client.Name()})
}

// suggestComponents asks the target's configured LLM to propose architecture
// components from a bounded repo outline plus what the deterministic IaC scan
// already found. Advisory only: candidates are returned, never persisted — the
// human confirms each via POST .../components with source=assisted. Same seam
// discipline as suggest: config from the target tree, request input can't pick
// the provider, output validated against the tech/kind enums.
func (s *Server) suggestComponents(w http.ResponseWriter, r *http.Request, id string) {
	m, err := s.threats.GetModel(id)
	if err != nil {
		s.writeThreatErr(w, err)
		return
	}
	comps, _ := s.threats.Components(id)

	in := triage.SuggestComponentsInput{AppName: m.Name}
	for _, c := range comps {
		in.Existing = append(in.Existing, c.Name)
	}
	root, hasDir := s.targetDir(m.TargetID)
	if hasDir {
		in.Outline = repoOutline(root)
		if detected, derr := iacdetect.Scan(root); derr == nil {
			for _, d := range detected {
				in.Detected = append(in.Detected, d.Name+" ("+d.Tech+") from "+d.Source)
			}
		}
	}

	client, cfg, ok := s.llmClientForTarget(w, r, m.TargetID)
	if !ok {
		return
	}
	suggestions, err := triage.SuggestComponents(r.Context(), client, in, time.Duration(cfg.Triage.TimeoutSec)*time.Second)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(audit.EventThreatUpdate, actorFrom(r), map[string]string{"model": id, "action": "suggest-components", "count": itoa(len(suggestions))})
	writeJSON(w, http.StatusOK, map[string]any{"suggestions": suggestions, "model": client.Name()})
}

// llmClientForTarget builds the LLM client for a target's configured provider
// and pings it, writing the 503 itself when unreachable. Provider, model, and
// endpoint come from the target tree's appsec.yml, never the request; a
// cloud/absent dir falls back to defaults (local Ollama).
func (s *Server) llmClientForTarget(w http.ResponseWriter, r *http.Request, targetID string) (llm.Client, config.Config, bool) {
	root, _ := s.targetDir(targetID)
	cfg := s.effectiveConfig(root)
	factory := s.llmFactory
	if factory == nil {
		factory = pipeline.NewLLMClient
	}
	client := factory(cfg)
	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(r.Context()); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "no reachable LLM provider — configure triage in the target's appsec.yml")
			return nil, cfg, false
		}
	}
	return client, cfg, true
}

// findingCategoriesFor returns the distinct finding categories in a target's
// latest run, as extra context for the suggestion prompt (best-effort).
func (s *Server) findingCategoriesFor(targetID string) []string {
	rs, ok := s.resolveRunStore(targetID)
	if !ok {
		return nil
	}
	runs, err := rs.List()
	if err != nil || len(runs) == 0 {
		return nil
	}
	doc, err := rs.Load(runs[len(runs)-1].ID)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range doc.Findings {
		if f.Category != "" && !seen[f.Category] {
			seen[f.Category] = true
			out = append(out, f.Category)
		}
	}
	return out
}

// targetDir resolves a target's local directory ("" = the served repo). A cloud
// target has no directory to scan.
func (s *Server) targetDir(targetID string) (string, bool) {
	if targetID == "" {
		return s.dir, true
	}
	if s.targets == nil {
		return "", false
	}
	t, err := s.targets.Get(targetID)
	if err != nil || t.Kind() == targets.TypeCloud {
		return "", false
	}
	return s.targets.Root(t), true
}

func (s *Server) writeThreatErr(w http.ResponseWriter, err error) {
	if errors.Is(err, threatmodel.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "threat model not found")
		return
	}
	writeErr(w, http.StatusBadRequest, err.Error())
}

// decodeBody is the shared JSON body reader with a byte cap.
func decodeBody(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return err
	}
	return nil
}
