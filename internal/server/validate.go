package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/targets"
	"github.com/zer0d4y5/argus/internal/triage"
)

// On-demand severity validation (POST /api/validate, operator+). For a run
// scanned without AI triage, the local model judges one finding — verdict,
// impact, likelihood, and a CVSS 3.1 vector whose score is computed
// deterministically. Same boundary as remediate: store/provider resolved
// server-side, SECRET-to-cloud gated, never persisted, advisory only (it never
// changes the stored severity). The audit line records the request, not content.

// ValidateRequest is POST /api/validate.
type ValidateRequest struct {
	TargetID  string `json:"targetId"`
	RunID     string `json:"runId"`
	FindingID string `json:"findingId"`
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req ValidateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RunID == "" || req.FindingID == "" {
		writeErr(w, http.StatusBadRequest, "runId and findingId are required")
		return
	}

	store := s.store
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
			store = runstore.ForRepo(s.targets.Root(t))
		}
	}

	val, code, err := s.computeValidation(r.Context(), store, req)
	s.audit(audit.EventScanValidate, actorFrom(r), map[string]string{
		"target": req.TargetID, "run": req.RunID, "finding": req.FindingID,
	})
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, val)
}

func (s *Server) computeValidation(ctx context.Context, store runstore.Store, req ValidateRequest) (triage.Validation, int, error) {
	doc, err := store.Load(req.RunID)
	if err != nil {
		return triage.Validation{}, http.StatusNotFound, errors.New("run not found")
	}
	var found *model.Finding
	for i := range doc.Findings {
		if doc.Findings[i].ID == req.FindingID {
			found = &doc.Findings[i]
			break
		}
	}
	if found == nil {
		return triage.Validation{}, http.StatusNotFound, errors.New("finding not found in this run")
	}

	cfg := s.effectiveConfig(s.dir)
	factory := s.llmFactory
	if factory == nil {
		factory = pipeline.NewLLMClient
	}
	client := factory(cfg)
	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			return triage.Validation{}, http.StatusServiceUnavailable,
				errors.New("no reachable LLM provider — configure triage in argus.yml")
		}
	}

	val, err := triage.Validate(ctx, client, *found, cfg.Triage.AllowSecretCloud,
		time.Duration(cfg.Triage.TimeoutSec)*time.Second)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, triage.ErrSecretCloud) {
			code = http.StatusConflict
		}
		return triage.Validation{}, code, err
	}
	return val, 0, nil
}
