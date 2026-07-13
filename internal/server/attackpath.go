package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/compliance"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/targets"
	"github.com/zer0d4y5/argus/internal/triage"
)

// On-demand attack-path analysis (Workstream D). Advisory only: the model
// reasons about how a dynamic run's confirmed findings could be chained and
// what to verify next. It reads only the deterministic class/location/severity
// of each finding (never a response body or proof), is never persisted, and the
// UI labels it AI-generated. It executes nothing. Operator+.

// AttackPathRequest is POST /api/attack-path.
type AttackPathRequest struct {
	TargetID string `json:"targetId"`
	RunID    string `json:"runId"`
}

// AttackPathResponse is the advisory analysis.
type AttackPathResponse struct {
	Summary   string   `json:"summary"`
	Chains    []string `json:"chains"`
	NextSteps []string `json:"nextSteps"`
	Model     string   `json:"model"`
}

func (s *Server) handleAttackPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req AttackPathRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TargetID == "" || req.RunID == "" {
		writeErr(w, http.StatusBadRequest, "targetId and runId are required")
		return
	}
	if s.targets == nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return
	}
	t, err := s.targets.Get(req.TargetID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return
	}
	if t.Kind() != targets.TypeDAST {
		writeErr(w, http.StatusBadRequest, "attack-path analysis is only available for dynamic (DAST) targets")
		return
	}
	dir, ok := s.targets.NonFSRunStore(t)
	if !ok {
		writeErr(w, http.StatusBadRequest, "target has no dynamic run history")
		return
	}
	store := runstore.Store{Dir: dir}
	doc, err := store.Load(req.RunID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	_ = compliance.Apply(doc.Findings) // idempotent; keeps older runs consistent

	cfg := s.effectiveConfig(s.dir)
	factory := s.llmFactory
	if factory == nil {
		factory = pipeline.NewLLMClient
	}
	client := factory(cfg)
	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(r.Context()); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "no reachable LLM provider — configure triage in appsec.yml")
			return
		}
	}

	in := triage.BuildAttackPathInput(t.URL, doc.Findings)
	res, err := triage.AttackPath(r.Context(), client, in, time.Duration(cfg.Triage.TimeoutSec)*time.Second)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(audit.EventScanExplain, actorFrom(r), map[string]string{
		"target": req.TargetID, "run": req.RunID, "kind": "attack-path",
	})
	writeJSON(w, http.StatusOK, AttackPathResponse{
		Summary: res.Summary, Chains: res.Chains, NextSteps: res.NextSteps, Model: res.Model,
	})
}
