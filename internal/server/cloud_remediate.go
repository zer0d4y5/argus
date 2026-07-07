package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/leaky-hub/argus/internal/audit"
	"github.com/leaky-hub/argus/internal/cloudremediate"
	"github.com/leaky-hub/argus/internal/cloudscan"
	"github.com/leaky-hub/argus/internal/model"
	"github.com/leaky-hub/argus/internal/runstore"
	"github.com/leaky-hub/argus/internal/targets"
)

// Approved cloud remediation endpoints.
//
//   POST /api/cloud/remediations  (operator+): the curated fixes that apply to
//     a cloud finding, with their exact commands, permissions, and
//     reversibility — informational, no execution, no cloud call.
//   POST /api/cloud/remediate     (admin, gated by config): dry-run or apply a
//     chosen fix using a validated write profile. Every call is audited. A fix
//     NEVER marks a finding fixed — only a re-scan clears it.
//
// The command always comes from the catalog, built server-side from the
// finding; the client only names the finding, the fix, the mode, and the write
// profile (chosen from the discovered closed list).

// remediateExecutor is swapped in tests; nil means the production child-process
// executor.
func (s *Server) remediationRunner() *cloudremediate.Runner {
	exec := s.remediateExec
	if exec == nil {
		exec = cloudremediate.NewExecutor(60 * time.Second)
	}
	return &cloudremediate.Runner{
		Exec: exec,
		ValidProfile: func(name string) bool {
			profiles, err := cloudscan.ListAWSProfiles()
			if err != nil {
				return false
			}
			for _, p := range profiles {
				if p == name {
					return true
				}
			}
			return false
		},
	}
}

// findCloudFinding loads one finding from a target's run, requiring it to be a
// CLOUD finding (remediation is cloud-only).
func (s *Server) findCloudFinding(targetID, runID, findingID string) (model.Finding, int, error) {
	store := s.store
	if targetID != "" {
		if s.targets == nil {
			return model.Finding{}, http.StatusNotFound, errors.New("target not found")
		}
		t, err := s.targets.Get(targetID)
		if err != nil {
			return model.Finding{}, http.StatusNotFound, errors.New("target not found")
		}
		if t.Kind() != targets.TypeCloud {
			return model.Finding{}, http.StatusBadRequest, errors.New("remediation applies to cloud findings only")
		}
		store = runstore.Store{Dir: s.targets.CloudRunStore(t)}
	}
	doc, err := store.Load(runID)
	if err != nil {
		return model.Finding{}, http.StatusNotFound, errors.New("run not found")
	}
	for i := range doc.Findings {
		if doc.Findings[i].ID == findingID {
			if doc.Findings[i].Category != model.CategoryCloud {
				return model.Finding{}, http.StatusBadRequest, errors.New("remediation applies to cloud findings only")
			}
			return doc.Findings[i], http.StatusOK, nil
		}
	}
	return model.Finding{}, http.StatusNotFound, errors.New("finding not found in this run")
}

// RemediationsRequest names a finding to list curated fixes for.
type RemediationsRequest struct {
	TargetID  string `json:"targetId"`
	RunID     string `json:"runId"`
	FindingID string `json:"findingId"`
}

func (s *Server) handleCloudRemediations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req RemediationsRequest
	if err := decodeBody(w, r, &req, 8192); err != nil {
		return
	}
	if req.RunID == "" || req.FindingID == "" {
		writeErr(w, http.StatusBadRequest, "runId and findingId are required")
		return
	}
	f, code, err := s.findCloudFinding(req.TargetID, req.RunID, req.FindingID)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	plans := []cloudremediate.Plan{}
	for _, rem := range cloudremediate.Applicable(f) {
		if plan, err := cloudremediate.Build(rem, f); err == nil {
			plans = append(plans, plan)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"remediations": plans,
		"enabled":      s.remediationEnabled(), // whether apply is turned on
	})
}

// remediationEnabled reports the config gate for executing remediations.
func (s *Server) remediationEnabled() bool {
	return s.effectiveConfig(s.dir).Remediation.Enabled
}

// RemediateRunRequest asks to dry-run or apply one curated fix.
type RemediateRunRequest struct {
	TargetID      string `json:"targetId"`
	RunID         string `json:"runId"`
	FindingID     string `json:"findingId"`
	RemediationID string `json:"remediationId"`
	Mode          string `json:"mode"`    // "dryrun" | "apply"
	Profile       string `json:"profile"` // write profile from the discovered list
}

func (s *Server) handleCloudRemediate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.remediationEnabled() {
		// 409 (not 403): this is a config-state gate, not an authorization
		// denial — an admin IS authorized, the capability is simply off.
		writeErr(w, http.StatusConflict, "cloud remediation is disabled — set remediation.enabled in appsec.yml to allow it")
		return
	}
	var req RemediateRunRequest
	if err := decodeBody(w, r, &req, 8192); err != nil {
		return
	}
	if req.RunID == "" || req.FindingID == "" || req.RemediationID == "" || req.Profile == "" {
		writeErr(w, http.StatusBadRequest, "runId, findingId, remediationId, and profile are required")
		return
	}
	mode := cloudremediate.DryRun
	if req.Mode == "apply" {
		mode = cloudremediate.Apply
	} else if req.Mode != "dryrun" {
		writeErr(w, http.StatusBadRequest, "mode must be dryrun or apply")
		return
	}

	f, code, err := s.findCloudFinding(req.TargetID, req.RunID, req.FindingID)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	rem, ok := cloudremediate.ByID(req.RemediationID)
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown remediation")
		return
	}
	// The remediation must actually apply to THIS finding — you can't build one
	// fix's command against another finding's resource.
	if !remediationApplies(rem.ID, f) {
		writeErr(w, http.StatusBadRequest, "this remediation does not apply to that finding")
		return
	}
	plan, err := cloudremediate.Build(rem, f)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	actor := actorFrom(r)
	results, runErr := s.remediationRunner().Run(r.Context(), plan, mode, req.Profile)
	s.audit(audit.EventCloudRemediate, actor, map[string]string{
		"target": req.TargetID, "finding": req.FindingID, "remediation": rem.ID,
		"mode": req.Mode, "ok": boolStr(runErr == nil),
	})
	if runErr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": runErr.Error(), "results": results})
		return
	}
	// A successful apply does NOT mark the finding fixed: only a re-scan clears
	// it. The response says so, so the console prompts a re-scan.
	writeJSON(w, http.StatusOK, map[string]any{
		"results":    results,
		"applied":    mode == cloudremediate.Apply,
		"reScanHint": "Re-scan the target to confirm the finding is resolved — a remediation never marks itself fixed.",
	})
}

// remediationApplies reports whether the remediation id is among those the
// catalog matches for the finding.
func remediationApplies(id string, f model.Finding) bool {
	for _, r := range cloudremediate.Applicable(f) {
		if r.ID == id {
			return true
		}
	}
	return false
}

