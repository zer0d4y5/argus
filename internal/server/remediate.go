package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/config"
	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/pipeline"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/targets"
	"github.com/leaky-hub/appsec/internal/triage"
)

// On-demand AI-assisted remediation (POST /api/remediate, operator+). Mirrors
// the explain endpoint: run store + LLM provider resolved from the registered
// target / served repo (never request input), SECRET-to-cloud gate, and the
// result returned to the browser and **never** written to a run file. The
// audit line records that a remediation was requested — never its content. A
// finding's status is never changed here; only a re-scan clears a finding.

// RemediateRequest is POST /api/remediate.
type RemediateRequest struct {
	TargetID  string `json:"targetId"`
	RunID     string `json:"runId"`
	FindingID string `json:"findingId"`
}

func (s *Server) handleRemediate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req RemediateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RunID == "" || req.FindingID == "" {
		writeErr(w, http.StatusBadRequest, "runId and findingId are required")
		return
	}

	// Resolve the run store + config root exactly like explain: served repo, or
	// a registered target by opaque ID; cloud targets use their per-target
	// store. Config (LLM provider) always comes from the served repo/target
	// tree, never the request.
	store := s.store
	root := s.dir
	if req.TargetID != "" {
		if s.targets == nil {
			writeErr(w, http.StatusNotFound, "target not found")
			return
		}
		t, err := s.targets.Get(req.TargetID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "target not found")
			return
		}
		if t.Kind() == targets.TypeCloud {
			store = runstore.Store{Dir: s.targets.CloudRunStore(t)}
		} else {
			root = s.targets.Root(t)
			store = runstore.ForRepo(root)
		}
	}

	rem, code, err := s.computeRemediation(r.Context(), store, req)
	s.audit(audit.EventScanRemediate, actorFrom(r), map[string]string{
		"target": req.TargetID, "run": req.RunID, "finding": req.FindingID,
	})
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rem)
}

// computeRemediation loads the finding from the run file and runs the
// remediation boundary against the target repo's configured provider. Never
// persists anything.
func (s *Server) computeRemediation(ctx context.Context, store runstore.Store, req RemediateRequest) (triage.Remediation, int, error) {
	doc, err := store.Load(req.RunID)
	if err != nil {
		return triage.Remediation{}, http.StatusNotFound, errors.New("run not found")
	}
	var found *model.Finding
	for i := range doc.Findings {
		if doc.Findings[i].ID == req.FindingID {
			found = &doc.Findings[i]
			break
		}
	}
	if found == nil {
		return triage.Remediation{}, http.StatusNotFound, errors.New("finding not found in this run")
	}

	cfg, err := repoConfig(s.dir)
	if err != nil {
		cfg = config.Default()
	}
	factory := s.llmFactory
	if factory == nil {
		factory = pipeline.NewLLMClient
	}
	client := factory(cfg)
	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			return triage.Remediation{}, http.StatusServiceUnavailable,
				errors.New("no reachable LLM provider — configure triage in appsec.yml")
		}
	}

	rem, err := triage.Remediate(ctx, client, *found, cfg.Triage.AllowSecretCloud,
		time.Duration(cfg.Triage.TimeoutSec)*time.Second)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, triage.ErrSecretCloud) {
			code = http.StatusConflict
		}
		return triage.Remediation{}, code, err
	}
	return rem, 0, nil
}
