package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/compliance"
	"github.com/zer0d4y5/argus/internal/engagement"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/report"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/targets"
)

// Console engagement management (Workstream E, UI half). Listing an engagement
// reveals scope and authorization (operator+); creating or activating one
// declares/switches the authorization for active testing, and exporting the
// report exposes findings plus the audit trail, so those are admin-only and
// audited. The console never arms the DESTRUCTIVE latch (that stays CLI-only,
// matching the scan-launch posture); it may arm the lesser confirmation latch.

// engagementView is the console-safe projection of an engagement.
type engagementView struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	AuthorizationRef string   `json:"authorizationRef"`
	Contact          string   `json:"contact,omitempty"`
	InScope          []string `json:"inScope"`
	OutOfScope       []string `json:"outOfScope,omitempty"`
	Confirm          bool     `json:"confirm"`
	Destructive      bool     `json:"destructive"`
	Active           bool     `json:"active"`
}

func toEngagementView(e *engagement.Engagement, active bool) engagementView {
	return engagementView{
		ID: e.ID, Name: e.Name, AuthorizationRef: e.AuthorizationRef, Contact: e.Contact,
		InScope: e.Scope.InScope, OutOfScope: e.Scope.OutOfScope,
		Confirm: e.Confirm, Destructive: e.Destructive, Active: active,
	}
}

func (s *Server) engStore() *engagement.Store {
	return &engagement.Store{Dir: s.targets.EngagementStoreDir()}
}

// handleEngagements serves GET /api/engagements (list, operator+) and
// POST /api/engagements (create, admin).
func (s *Server) handleEngagements(w http.ResponseWriter, r *http.Request) {
	if s.targets == nil {
		writeErr(w, http.StatusNotFound, "engagements are not available for this server")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listEngagements(w, r)
	case http.MethodPost:
		s.createEngagement(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listEngagements(w http.ResponseWriter, r *http.Request) {
	store := s.engStore()
	list, err := store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list engagements")
		return
	}
	activeID := ""
	if active, _ := store.Active(); active != nil {
		activeID = active.ID
	}
	out := make([]engagementView, 0, len(list))
	for _, e := range list {
		out = append(out, toEngagementView(e, e.ID == activeID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"engagements": out, "activeId": activeID})
}

// createEngagementRequest is POST /api/engagements.
type createEngagementRequest struct {
	Name              string   `json:"name"`
	InScope           []string `json:"inScope"`
	OutOfScope        []string `json:"outOfScope"`
	AuthorizationRef  string   `json:"authorizationRef"`
	Contact           string   `json:"contact"`
	AllowConfirmation bool     `json:"allowConfirmation"`
	Activate          bool     `json:"activate"`
}

func (s *Server) createEngagement(w http.ResponseWriter, r *http.Request) {
	var req createEngagementRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// engagement.New validates the name, scope grammar, and requires an
	// authorization reference. The console never arms the destructive latch.
	e, err := engagement.New(req.Name, engagement.Scope{InScope: trimAll(req.InScope), OutOfScope: trimAll(req.OutOfScope)}, engagement.Options{
		AuthorizationRef: req.AuthorizationRef,
		Contact:          req.Contact,
		Confirm:          req.AllowConfirmation,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	store := s.engStore()
	if err := store.Save(e); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save engagement")
		return
	}
	// Seed the engagement's own tamper-evident audit trail at genesis, as the CLI does.
	if a, err := engagement.OpenAudit(store.AuditPath(e.ID)); err == nil {
		_ = a.Append(engagement.EventEngagementCreate, map[string]string{
			"id": e.ID, "name": e.Name, "authorizationRef": e.AuthorizationRef,
		})
	}
	if req.Activate {
		_ = store.SetActive(e.ID)
	}
	s.audit(audit.EventEngagement, actorFrom(r), map[string]string{"action": "create", "id": e.ID})
	writeJSON(w, http.StatusOK, toEngagementView(e, req.Activate))
}

// handleEngagementItem serves POST /api/engagements/{id}/activate and
// GET /api/engagements/{id}/report.
func (s *Server) handleEngagementItem(w http.ResponseWriter, r *http.Request) {
	if s.targets == nil {
		writeErr(w, http.StatusNotFound, "engagements are not available for this server")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/engagements/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if id == "" {
		writeErr(w, http.StatusNotFound, "engagement not found")
		return
	}
	switch {
	case action == "activate" && r.Method == http.MethodPost:
		s.activateEngagement(w, r, id)
	case action == "report" && r.Method == http.MethodGet:
		s.engagementReport(w, r, id)
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) activateEngagement(w http.ResponseWriter, r *http.Request, id string) {
	store := s.engStore()
	if _, err := store.Load(id); err != nil {
		writeErr(w, http.StatusNotFound, "engagement not found")
		return
	}
	if err := store.SetActive(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not activate engagement")
		return
	}
	s.audit(audit.EventEngagement, actorFrom(r), map[string]string{"action": "activate", "id": id})
	writeJSON(w, http.StatusOK, map[string]string{"activeId": id})
}

func (s *Server) engagementReport(w http.ResponseWriter, r *http.Request, id string) {
	store := s.engStore()
	e, err := store.Load(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "engagement not found")
		return
	}
	findings, err := s.gatherDASTFindings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read run history")
		return
	}
	if len(findings) == 0 {
		writeErr(w, http.StatusConflict, "no dynamic findings to report yet; run a DAST scan under this engagement first")
		return
	}
	_ = compliance.Apply(findings)
	model.Sort(findings)

	auditPath := store.AuditPath(e.ID)
	vr, _ := engagement.Verify(auditPath)
	entries, _ := engagement.Entries(auditPath)
	engRep := &report.EngagementReport{
		Name:             e.Name,
		AuthorizationRef: e.AuthorizationRef,
		Contact:          e.Contact,
		Window:           engagementWindowLabel(e.Window),
		InScope:          e.Scope.InScope,
		OutOfScope:       e.Scope.OutOfScope,
		AuditVerified:    vr.OK,
		AuditEntries:     vr.Entries,
		AuditEvents:      engagementAuditRows(entries),
	}
	if !vr.OK {
		engRep.AuditError = vr.Reason
	}
	meta := report.HTMLMeta{
		Target:      strings.Join(e.Scope.InScope, ", "),
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Engagement:  engRep,
	}

	s.audit(audit.EventEngagement, actorFrom(r), map[string]string{"action": "report", "id": e.ID})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="engagement-%s-report.html"`, e.ID))
	_ = report.WriteHTML(w, findings, meta)
}

// gatherDASTFindings collects the latest run's findings from every registered
// DAST target for the served repo.
func (s *Server) gatherDASTFindings() ([]model.Finding, error) {
	list, err := s.targets.List()
	if err != nil {
		return nil, err
	}
	var all []model.Finding
	for _, t := range list {
		if t.Kind() != targets.TypeDAST {
			continue
		}
		dir, ok := s.targets.NonFSRunStore(t)
		if !ok {
			continue
		}
		store := runstore.Store{Dir: dir}
		meta, has, err := store.Latest()
		if err != nil || !has {
			continue
		}
		doc, err := store.Load(meta.ID)
		if err != nil {
			continue
		}
		all = append(all, doc.Findings...)
	}
	return all, nil
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func engagementWindowLabel(win engagement.Window) string {
	const f = "2006-01-02 15:04 UTC"
	switch {
	case win.Start.IsZero() && win.End.IsZero():
		return ""
	case win.Start.IsZero():
		return "until " + win.End.UTC().Format(f)
	case win.End.IsZero():
		return "from " + win.Start.UTC().Format(f)
	default:
		return win.Start.UTC().Format(f) + " to " + win.End.UTC().Format(f)
	}
}

func engagementAuditRows(entries []engagement.Entry) []report.AuditEventRow {
	const maxRows = 300
	start := 0
	if len(entries) > maxRows {
		start = len(entries) - maxRows
	}
	rows := make([]report.AuditEventRow, 0, len(entries)-start)
	for _, e := range entries[start:] {
		rows = append(rows, report.AuditEventRow{
			Seq: int(e.Seq), Time: e.Time.UTC().Format("15:04:05"), Event: e.Event, Detail: engagementDetail(e.Details),
		})
	}
	return rows
}

func engagementDetail(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	out := strings.Join(parts, " ")
	if len(out) > 200 {
		out = out[:200] + "…"
	}
	return out
}
