package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/disposition"
	"github.com/leaky-hub/appsec/internal/report"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/targets"
	"github.com/leaky-hub/appsec/internal/ticket"
)

// Ticketing endpoints. A ticket is the work-tracking layer over findings; it
// lives in the embedded SQLite store, is created/updated by operators and
// deleted by admins, and every mutation is audited (the event, not the content).
// It never moves a severity or the gate. The one bridge to the gate is explicit:
// POST .../close-fixed writes a "fixed" DISPOSITION (the file-based gate input)
// for each linked finding, on a human action.

// TicketRollup is a ticket's severity rollup, computed at read time from the
// current severities of its linked findings — never stored, so never stale.
type TicketRollup struct {
	Total      int            `json:"total"`         // linked findings
	Resolved   int            `json:"resolved"`      // links whose finding is present in the latest run
	Max        string         `json:"max,omitempty"` // highest severity among resolved links
	BySeverity map[string]int `json:"bySeverity"`
}

// TicketView is a ticket plus its computed rollup and link count for the list.
type TicketView struct {
	ticket.Ticket
	LinkCount int          `json:"linkCount"`
	Rollup    TicketRollup `json:"rollup"`
}

// TicketDetail is the single-ticket payload: the ticket, its links, timeline,
// and rollup.
type TicketDetail struct {
	ticket.Ticket
	Links    []ticket.Link    `json:"links"`
	Comments []ticket.Comment `json:"comments"`
	Rollup   TicketRollup     `json:"rollup"`
}

var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

// handleTickets: GET lists tickets (viewer+), POST creates one (operator+).
func (s *Server) handleTickets(w http.ResponseWriter, r *http.Request) {
	if s.tickets == nil {
		writeErr(w, http.StatusNotFound, "ticketing is not enabled")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listTickets(w, r)
	case http.MethodPost:
		s.createTicket(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listTickets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tickets, err := s.tickets.List(ticket.ListFilter{
		Status: q.Get("status"), TargetID: q.Get("target"),
		Assignee: q.Get("assignee"), Priority: q.Get("priority"),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to list tickets")
		return
	}
	allLinks, err := s.tickets.AllLinks()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to load ticket links")
		return
	}
	sevCache := map[string]map[string]string{}
	out := make([]TicketView, 0, len(tickets))
	for _, t := range tickets {
		links := allLinks[t.ID]
		out = append(out, TicketView{Ticket: t, LinkCount: len(links), Rollup: s.rollup(links, sevCache)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tickets": out})
}

// TicketCreateRequest is POST /api/tickets. FindingIDs (optional) links the
// findings from a Findings-view selection at creation time.
type TicketCreateRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Assignee    string   `json:"assignee"`
	TargetID    string   `json:"targetId"`
	DueDate     string   `json:"dueDate"`
	FindingIDs  []string `json:"findingIds"`
}

func (s *Server) createTicket(w http.ResponseWriter, r *http.Request) {
	var req TicketCreateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	actor := actorFrom(r)
	now := time.Now()
	// Validate every requested link BEFORE creating the ticket: links feed the
	// close-fixed bridge, and a failed link must not leave a half-made ticket.
	sevCache := map[string]map[string]string{}
	var linkIDs []string
	for _, fid := range req.FindingIDs {
		if strings.TrimSpace(fid) == "" {
			continue
		}
		if msg := s.validateFindingLink(req.TargetID, fid, sevCache); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		linkIDs = append(linkIDs, fid)
	}
	t, err := s.tickets.Create(ticket.CreateInput{
		Title: req.Title, Description: req.Description, Priority: req.Priority,
		Assignee: req.Assignee, TargetID: req.TargetID, DueDate: req.DueDate,
	}, actor, now)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, fid := range linkIDs {
		if err := s.tickets.Link(t.ID, fid, req.TargetID); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	s.audit(audit.EventTicketCreate, actor, map[string]string{
		"ticket": t.ID, "target": req.TargetID, "links": itoa(len(req.FindingIDs)),
	})
	writeJSON(w, http.StatusCreated, t)
}

// handleTicketByID routes /api/tickets/{id} and its subpaths (/links,
// /comments, /close-fixed).
func (s *Server) handleTicketByID(w http.ResponseWriter, r *http.Request) {
	if s.tickets == nil {
		writeErr(w, http.StatusNotFound, "ticketing is not enabled")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/tickets/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	switch sub {
	case "":
		switch r.Method {
		case http.MethodGet:
			s.getTicket(w, r, id)
		case http.MethodPatch:
			s.updateTicket(w, r, id)
		case http.MethodDelete:
			s.deleteTicket(w, r, id)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case "links":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.ticketLink(w, r, id)
	case "comments":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.ticketComment(w, r, id)
	case "close-fixed":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.ticketCloseFixed(w, r, id)
	case "github":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.ticketGitHub(w, r, id)
	default:
		writeErr(w, http.StatusNotFound, "unknown ticket subresource")
	}
}

func (s *Server) getTicket(w http.ResponseWriter, _ *http.Request, id string) {
	t, err := s.tickets.Get(id)
	if err != nil {
		s.writeTicketErr(w, err)
		return
	}
	links, _ := s.tickets.Links(id)
	comments, _ := s.tickets.Comments(id)
	writeJSON(w, http.StatusOK, TicketDetail{
		Ticket: t, Links: links, Comments: comments, Rollup: s.rollup(links, nil),
	})
}

// TicketUpdateRequest patches a ticket; omitted fields are unchanged.
type TicketUpdateRequest struct {
	Title       *string `json:"title"`
	Description *string `json:"description"`
	Status      *string `json:"status"`
	Priority    *string `json:"priority"`
	Assignee    *string `json:"assignee"`
	DueDate     *string `json:"dueDate"`
}

func (s *Server) updateTicket(w http.ResponseWriter, r *http.Request, id string) {
	var req TicketUpdateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	before, err := s.tickets.Get(id)
	if err != nil {
		s.writeTicketErr(w, err)
		return
	}
	actor := actorFrom(r)
	now := time.Now()
	t, err := s.tickets.Update(id, ticket.UpdateInput{
		Title: req.Title, Description: req.Description, Status: req.Status,
		Priority: req.Priority, Assignee: req.Assignee, DueDate: req.DueDate,
	}, now)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// A status change lands in the timeline as a system event.
	if req.Status != nil && *req.Status != before.Status {
		s.tickets.AddComment(id, "event", actor, "status → "+t.Status, now)
	}
	s.audit(audit.EventTicketUpdate, actor, map[string]string{"ticket": id, "status": t.Status})
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) deleteTicket(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.tickets.Delete(id); err != nil {
		s.writeTicketErr(w, err)
		return
	}
	s.audit(audit.EventTicketDelete, actorFrom(r), map[string]string{"ticket": id})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// TicketLinkRequest is POST /api/tickets/{id}/links: attach (or, with remove,
// detach) a finding.
type TicketLinkRequest struct {
	FindingID string `json:"findingId"`
	TargetID  string `json:"targetId"`
	Remove    bool   `json:"remove"`
}

func (s *Server) ticketLink(w http.ResponseWriter, r *http.Request, id string) {
	var req TicketLinkRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var err error
	if req.Remove {
		err = s.tickets.Unlink(id, req.FindingID, req.TargetID)
	} else {
		// Attaching requires a real finding; detaching never does (cleanup of a
		// stale link must always work).
		if msg := s.validateFindingLink(req.TargetID, req.FindingID, nil); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		err = s.tickets.Link(id, req.FindingID, req.TargetID)
	}
	if err != nil {
		s.writeTicketErr(w, err)
		return
	}
	s.audit(audit.EventTicketLink, actorFrom(r), map[string]string{
		"ticket": id, "target": req.TargetID, "remove": boolStr(req.Remove),
	})
	links, _ := s.tickets.Links(id)
	writeJSON(w, http.StatusOK, map[string]any{"links": links})
}

// TicketCommentRequest is POST /api/tickets/{id}/comments.
type TicketCommentRequest struct {
	Body string `json:"body"`
}

func (s *Server) ticketComment(w http.ResponseWriter, r *http.Request, id string) {
	var req TicketCommentRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	c, err := s.tickets.AddComment(id, "comment", actorFrom(r), req.Body, time.Now())
	if err != nil {
		if errors.Is(err, ticket.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "ticket not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(audit.EventTicketComment, actorFrom(r), map[string]string{"ticket": id})
	writeJSON(w, http.StatusCreated, c)
}

// ticketCloseFixed is the explicit bridge to the gate: mark the ticket done and
// write a "fixed" disposition for every linked finding, so a completed ticket
// reflects in the gate. The disposition is the deterministic gate input; this
// is a human action writing through the existing file-based store, audited.
func (s *Server) ticketCloseFixed(w http.ResponseWriter, r *http.Request, id string) {
	actor := actorFrom(r)
	now := time.Now()
	if _, err := s.tickets.Update(id, ticket.UpdateInput{Status: ptr("done")}, now); err != nil {
		s.writeTicketErr(w, err)
		return
	}
	links, _ := s.tickets.Links(id)
	fixed, skipped, kept := 0, 0, 0
	sevCache := map[string]map[string]string{}
	for _, l := range links {
		store, ok := s.dispositionStoreForTarget(l.TargetID)
		// A link the API would not accept today (unknown target, or a finding
		// no longer in the latest run) is skipped: a "fixed" disposition for a
		// fingerprint the runs don't show would only mislead a later reader.
		if !ok || !s.findingInLatestRun(l.TargetID, l.FindingID, sevCache) {
			skipped++
			continue
		}
		// Never overwrite a gate-suppressing human judgment: accepted-risk and
		// false-positive carry a justification this close must not destroy.
		if cur, ok := store.Get(l.FindingID); ok && disposition.GateSuppressed(cur.Status) {
			kept++
			continue
		}
		if _, err := store.Set(l.FindingID, disposition.StatusFixed, "resolved via ticket "+id, actor, now); err == nil {
			fixed++
		} else {
			skipped++
		}
	}
	msg := "closed as done — " + itoa(fixed) + " finding(s) marked fixed"
	if skipped > 0 {
		msg += ", " + itoa(skipped) + " skipped (not in the latest run)"
	}
	if kept > 0 {
		msg += ", " + itoa(kept) + " kept an existing accepted-risk/false-positive disposition"
	}
	s.tickets.AddComment(id, "event", actor, msg, now)
	s.audit(audit.EventTicketUpdate, actor, map[string]string{"ticket": id, "status": "done", "fixed": itoa(fixed), "skipped": itoa(skipped), "kept": itoa(kept)})
	// Also record the disposition writes under their own event for the audit view.
	if fixed > 0 {
		s.audit(audit.EventFindingDispose, actor, map[string]string{"ticket": id, "count": itoa(fixed), "status": disposition.StatusFixed, "bulk": "true"})
	}
	writeJSON(w, http.StatusOK, map[string]int{"markedFixed": fixed, "skipped": skipped, "kept": kept})
}

// rollup computes a ticket's severity rollup from its links' current severities.
// sevCache (may be nil) memoizes each target's latest-run severity map so a list
// of tickets loads each distinct target's run at most once.
func (s *Server) rollup(links []ticket.Link, sevCache map[string]map[string]string) TicketRollup {
	r := TicketRollup{Total: len(links), BySeverity: map[string]int{}}
	for _, l := range links {
		sevMap, ok := lookupSevCache(sevCache, l.TargetID)
		if !ok {
			sevMap = s.latestSeverities(l.TargetID)
			storeSevCache(sevCache, l.TargetID, sevMap)
		}
		sev := sevMap[l.FindingID]
		if sev == "" {
			continue // finding not in the latest run (resolved/stale) — counts in Total only
		}
		r.Resolved++
		r.BySeverity[sev]++
		if severityRank[sev] > severityRank[r.Max] {
			r.Max = sev
		}
	}
	return r
}

func lookupSevCache(c map[string]map[string]string, target string) (map[string]string, bool) {
	if c == nil {
		return nil, false
	}
	m, ok := c[target]
	return m, ok
}
func storeSevCache(c map[string]map[string]string, target string, m map[string]string) {
	if c != nil {
		c[target] = m
	}
}

// findingInLatestRun reports whether findingID appears in targetID's latest
// run, memoizing per-target severity maps in sevCache (may be nil) exactly
// like rollup does.
func (s *Server) findingInLatestRun(targetID, findingID string, sevCache map[string]map[string]string) bool {
	sevMap, ok := lookupSevCache(sevCache, targetID)
	if !ok {
		sevMap = s.latestSeverities(targetID)
		storeSevCache(sevCache, targetID, sevMap)
	}
	return sevMap[findingID] != ""
}

// validateFindingLink decides whether a finding may be attached (to a ticket or
// a threat): the target must resolve and the fingerprint must be in its latest
// run, because links feed the close-fixed disposition bridge. Returns a
// user-facing message, or "" when the link is acceptable.
func (s *Server) validateFindingLink(targetID, findingID string, sevCache map[string]map[string]string) string {
	if strings.TrimSpace(findingID) == "" {
		return "findingId is required"
	}
	if _, ok := s.resolveRunStore(targetID); !ok {
		return "unknown target " + strconv.Quote(targetID)
	}
	if !s.findingInLatestRun(targetID, findingID, sevCache) {
		return "finding is not in the target's latest run"
	}
	return ""
}

// latestSeverities maps fingerprint → severity for a target's latest run (nil if
// none), so a ticket's rollup reflects the findings as they stand now.
func (s *Server) latestSeverities(targetID string) map[string]string {
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
	m := make(map[string]string, len(doc.Findings))
	for _, f := range doc.Findings {
		m[f.ID] = f.Severity.String()
	}
	return m
}

// resolveRunStore returns the run store for a target (or the served repo when
// targetID is empty). ok=false for an unknown target.
func (s *Server) resolveRunStore(targetID string) (runstore.Store, bool) {
	if targetID == "" {
		return s.store, true
	}
	if s.targets == nil {
		return runstore.Store{}, false
	}
	t, err := s.targets.Get(targetID)
	if err != nil {
		return runstore.Store{}, false
	}
	if t.Kind() == targets.TypeCloud {
		return runstore.Store{Dir: s.targets.CloudRunStore(t)}, true
	}
	return runstore.ForRepo(s.targets.Root(t)), true
}

// dispositionStoreForTarget is the non-writing sibling of dispositionStoreFor,
// for the close-fixed bridge.
func (s *Server) dispositionStoreForTarget(targetID string) (*disposition.Store, bool) {
	if targetID == "" {
		return dispositionStore(s.store), true
	}
	if s.targets == nil {
		return nil, false
	}
	t, err := s.targets.Get(targetID)
	if err != nil {
		return nil, false
	}
	if t.Kind() == targets.TypeCloud {
		return disposition.At(filepath.Dir(s.targets.CloudRunStore(t))), true
	}
	return dispositionStore(runstore.ForRepo(s.targets.Root(t))), true
}

func (s *Server) writeTicketErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ticket.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "ticket not found")
		return
	}
	writeErr(w, http.StatusBadRequest, err.Error())
}

// handleWorkSummary: GET the ticket and threat status rollup for the Overview
// widget — counts only, no content, viewer-readable like the ticket list.
func (s *Server) handleWorkSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	out := map[string]map[string]int{"tickets": {}, "threats": {}}
	if s.tickets != nil {
		if c, err := s.tickets.StatusCounts(); err == nil {
			out["tickets"] = c
		}
	}
	if s.threats != nil {
		if c, err := s.threats.ThreatStatusCounts(); err == nil {
			out["threats"] = c
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleUserNames: GET just the usernames (no roles, no hashes, no ids) so an
// operator can pick an assignee. Deliberately weaker than admin-only
// /api/users: the roster is already visible to operators through ticket
// assignees and created-by fields; roles and credentials stay admin-only.
func (s *Server) handleUserNames(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	names := []string{}
	if s.users != nil {
		if list, err := s.users.List(); err == nil {
			for _, u := range list {
				names = append(names, u.Username)
			}
		}
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, map[string][]string{"names": names})
}

// addWorkItemsToReport fills the exported report's ticket and threat-model
// sections for a target (empty targetID = the served repo). Best-effort: a store
// error just leaves the section empty rather than failing the export.
func (s *Server) addWorkItemsToReport(meta *report.HTMLMeta, targetID string) {
	if s.tickets != nil {
		if tks, err := s.tickets.List(ticket.ListFilter{TargetID: targetID}); err == nil && len(tks) > 0 {
			links, _ := s.tickets.AllLinks()
			cache := map[string]map[string]string{}
			for _, t := range tks {
				roll := s.rollup(links[t.ID], cache)
				meta.Tickets = append(meta.Tickets, report.TicketReport{
					ID: t.ID, Title: t.Title, Status: t.Status, Priority: t.Priority,
					MaxSeverity: roll.Max, LinkCount: roll.Total,
				})
			}
		}
	}
	if s.threats != nil {
		if models, err := s.threats.ListModels(targetID); err == nil {
			for _, m := range models {
				comps, _ := s.threats.Components(m.ID)
				threats, _ := s.threats.Threats(m.ID)
				tmr := report.ThreatModelReport{Name: m.Name, Components: len(comps)}
				for _, th := range threats {
					tmr.Threats = append(tmr.Threats, report.ThreatReportRow{
						Category: th.Category, Title: th.Title, Status: th.Status, Mitigation: th.Mitigation,
					})
				}
				meta.ThreatModels = append(meta.ThreatModels, tmr)
			}
		}
	}
}

func ptr(s string) *string { return &s }
func itoa(n int) string    { return strconv.Itoa(n) }
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
