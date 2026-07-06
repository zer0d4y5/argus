package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/disposition"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/targets"
)

// Finding-workflow disposition endpoints (operator+). A disposition is durable
// human judgment about a finding, keyed by its stable fingerprint so it
// follows the finding across re-scans. It is NOT LLM triage (advisory,
// per-run) and never moves a severity/gate/compliance — it is a workflow
// overlay. Every change is audited; the note is user text, rendered inert by
// the console. The store lives beside the target's runs (resolved from
// ?target= exactly like run reads).

// DispositionRequest is POST /api/dispositions: set a finding's status.
type DispositionRequest struct {
	TargetID  string `json:"targetId"`
	FindingID string `json:"findingId"`
	Status    string `json:"status"`
	Note      string `json:"note"`
}

// handleDispositions: POST sets a disposition. The finding id is the stable
// fingerprint the browser already has from a run detail; nothing here touches
// a filesystem path or a run file.
func (s *Server) handleDispositions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req DispositionRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.FindingID) == "" {
		writeErr(w, http.StatusBadRequest, "findingId is required")
		return
	}
	if !disposition.ValidStatus(req.Status) {
		writeErr(w, http.StatusBadRequest, "status must be one of in-progress, accepted-risk, false-positive, fixed (clear the disposition to return to open)")
		return
	}
	store, ok := s.dispositionStoreFor(w, r, req.TargetID)
	if !ok {
		return
	}
	rec, err := store.Set(req.FindingID, req.Status, req.Note, actorFrom(r), time.Now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(audit.EventFindingDispose, actorFrom(r), map[string]string{
		"target": req.TargetID, "finding": req.FindingID, "status": req.Status,
	})
	writeJSON(w, http.StatusOK, rec)
}

// handleDispositionByID: DELETE /api/dispositions/{findingId}?target= clears a
// disposition back to open.
func (s *Server) handleDispositionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	findingID := strings.TrimPrefix(r.URL.Path, "/api/dispositions/")
	if findingID == "" || strings.Contains(findingID, "/") {
		writeErr(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	store, ok := s.dispositionStoreFor(w, r, r.URL.Query().Get("target"))
	if !ok {
		return
	}
	if err := store.Clear(findingID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to clear disposition")
		return
	}
	s.audit(audit.EventFindingDispose, actorFrom(r), map[string]string{
		"target": r.URL.Query().Get("target"), "finding": findingID, "status": disposition.StatusOpen,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// dispositionStoreFor resolves the disposition store for a target (or the
// served repo when targetID is empty), landing in the same .appsec dir as
// that target's runs — the same resolution runStoreFor uses, done directly
// (the target for a POST arrives in the body, not the query). Writes the
// response and returns ok=false on an unknown target.
func (s *Server) dispositionStoreFor(w http.ResponseWriter, _ *http.Request, targetID string) (*disposition.Store, bool) {
	if targetID == "" {
		return dispositionStore(s.store), true
	}
	if s.targets == nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return nil, false
	}
	t, err := s.targets.Get(targetID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return nil, false
	}
	if t.Kind() == targets.TypeCloud {
		return disposition.At(filepath.Dir(s.targets.CloudRunStore(t))), true
	}
	return dispositionStore(runstore.ForRepo(s.targets.Root(t))), true
}
