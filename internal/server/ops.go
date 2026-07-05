package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/jobs"
	"github.com/leaky-hub/appsec/internal/scanner"
	"github.com/leaky-hub/appsec/internal/server/auth"
	"github.com/leaky-hub/appsec/internal/targets"
)

// Ops handlers: users, targets, scans, audit. The authz middleware has
// already enforced role and CSRF by the time any of these run; handlers
// still validate every input because the middleware only decides WHO may
// call, never WHAT is a sane request.

// audit writes an audit entry, warning on stderr rather than failing the
// user action — the action already happened; the loud failure beats a
// silent one AND a broken console.
func (s *Server) audit(event, actor string, details map[string]string) {
	if s.auditLog == nil {
		return
	}
	if err := s.auditLog.Write(event, actor, details); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: audit write failed: %v\n", err)
	}
}

func actorFrom(r *http.Request) string {
	if sess, ok := sessionFromContext(r.Context()); ok {
		return sess.Username
	}
	return "-"
}

// --- users ---

// UsersResponse is GET /api/users. It carries UserInfo DTOs only — the
// stored hash never has a path into any response body.
type UsersResponse struct {
	Users []UserInfo `json:"users"`
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusForbidden, bootstrapHint)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.users.List()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list users")
			return
		}
		resp := UsersResponse{Users: []UserInfo{}}
		for _, u := range list {
			resp.Users = append(resp.Users, userInfo(u))
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		role, err := auth.ParseRole(req.Role)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		u, err := s.users.Add(req.Username, req.Password, role)
		if err != nil {
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "already exists") {
				status = http.StatusConflict
			}
			writeErr(w, status, err.Error())
			return
		}
		s.audit(audit.EventUserCreate, actorFrom(r), map[string]string{"username": u.Username, "role": string(u.Role)})
		writeJSON(w, http.StatusCreated, userInfo(u))
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusForbidden, bootstrapHint)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusBadRequest, "invalid user id")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req struct {
			Role     *string `json:"role"`
			Password *string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Role == nil && req.Password == nil) {
			writeErr(w, http.StatusBadRequest, "invalid request body (need role and/or password)")
			return
		}
		var u auth.User
		changed := map[string]string{}
		if req.Role != nil {
			role, err := auth.ParseRole(*req.Role)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			var uerr error
			u, uerr = s.users.SetRole(id, role)
			if uerr != nil {
				writeUserErr(w, uerr)
				return
			}
			changed["role"] = string(role)
		}
		if req.Password != nil {
			var uerr error
			u, uerr = s.users.SetPassword(id, *req.Password)
			if uerr != nil {
				writeUserErr(w, uerr)
				return
			}
			changed["password"] = "changed" // never the value
			if s.sessions != nil {
				s.sessions.DeleteUser(u.ID) // rotate credentials = rotate access
			}
		}
		s.audit(audit.EventUserUpdate, actorFrom(r), map[string]string{"username": u.Username, "changed": mapKeys(changed)})
		writeJSON(w, http.StatusOK, userInfo(u))
	case http.MethodDelete:
		u, err := s.users.Remove(id)
		if err != nil {
			writeUserErr(w, err)
			return
		}
		if s.sessions != nil {
			s.sessions.DeleteUser(u.ID)
		}
		s.audit(audit.EventUserDelete, actorFrom(r), map[string]string{"username": u.Username, "role": string(u.Role)})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// writeUserErr maps user-store errors to API statuses: last-admin
// protection is a conflict, not a validation error.
func writeUserErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrLastAdmin):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, auth.ErrNotFound):
		writeErr(w, http.StatusNotFound, "user not found")
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}

func mapKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// --- targets ---

// TargetsResponse is GET /api/targets.
type TargetsResponse struct {
	Targets []targets.Target `json:"targets"`
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resp := TargetsResponse{Targets: []targets.Target{}}
		if s.targets != nil {
			list, err := s.targets.List()
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "failed to list targets")
				return
			}
			resp.Targets = append(resp.Targets, list...)
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		if s.targets == nil {
			writeErr(w, http.StatusForbidden, bootstrapHint)
			return
		}
		var req struct {
			Name     string   `json:"name"`
			Path     string   `json:"path"`
			Scanners []string `json:"scanners"`
			Profile  string   `json:"profile"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		for i := range req.Scanners {
			req.Scanners[i] = strings.ToLower(strings.TrimSpace(req.Scanners[i]))
		}
		// ValidatePath (inside Add) demands an absolute path: the server's
		// CWD means nothing to a browser user, so nothing is resolved.
		t, err := s.targets.Add(req.Name, req.Path, req.Scanners, req.Profile)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(audit.EventTargetCreate, actorFrom(r), map[string]string{"target": t.ID, "name": t.Name, "path": t.Path})
		writeJSON(w, http.StatusCreated, t)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleTargetByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.targets == nil {
		writeErr(w, http.StatusForbidden, bootstrapHint)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusBadRequest, "invalid target id")
		return
	}
	t, err := s.targets.Remove(id)
	if err != nil {
		if errors.Is(err, targets.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "target not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "failed to remove target")
		return
	}
	s.audit(audit.EventTargetDelete, actorFrom(r), map[string]string{"target": t.ID, "name": t.Name})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- scans ---

// ScanRequest is POST /api/scans: an opaque target ID plus closed-enum
// options. NO free-form strings in here ever reach a scanner invocation
// (docs/console-ops.md T1/T2).
type ScanRequest struct {
	TargetID string `json:"targetId"`
	Options  struct {
		Scanners []string `json:"scanners"`
		Profile  string   `json:"profile"`
		Triage   *bool    `json:"triage"`
	} `json:"options"`
}

// JobsResponse is GET /api/scans.
type JobsResponse struct {
	Jobs []jobs.Job `json:"jobs"`
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resp := JobsResponse{Jobs: []jobs.Job{}}
		if s.queue != nil {
			resp.Jobs = append(resp.Jobs, s.queue.List()...)
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		s.handleScanLaunch(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleScanLaunch(w http.ResponseWriter, r *http.Request) {
	if s.queue == nil || s.targets == nil {
		writeErr(w, http.StatusForbidden, bootstrapHint)
		return
	}
	var req ScanRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// The registry lookup is by ID only: an unknown or user-invented ID is a
	// 404 and nothing else happens.
	t, err := s.targets.Get(req.TargetID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return
	}

	// Closed-enum validation against the registry entry.
	allowed := t.Scanners
	if len(allowed) == 0 {
		allowed = targets.KnownScanners()
	}
	allowedSet := map[string]bool{}
	for _, n := range allowed {
		allowedSet[strings.ToLower(n)] = true
	}
	var scannersOpt []string
	for _, n := range req.Options.Scanners {
		n = strings.ToLower(strings.TrimSpace(n))
		if !allowedSet[n] {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("scanner %q is not allowed for this target", n))
			return
		}
		scannersOpt = append(scannersOpt, n)
	}
	if req.Options.Profile != "" {
		if err := scanner.ValidateProfile(req.Options.Profile); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid profile (fast|standard|max)")
			return
		}
	}

	actor := actorFrom(r)
	job, err := s.queue.Enqueue(t.ID, t.Name, actor, jobs.Options{
		Scanners: scannersOpt,
		Profile:  req.Options.Profile,
		Triage:   req.Options.Triage,
	})
	if err != nil {
		if errors.Is(err, jobs.ErrQueueFull) {
			writeErr(w, http.StatusTooManyRequests, "scan queue is full — try again after pending scans finish")
			return
		}
		writeErr(w, http.StatusInternalServerError, "failed to enqueue scan")
		return
	}

	details := map[string]string{"job": job.ID, "target": t.ID, "name": t.Name}
	if len(scannersOpt) > 0 {
		details["scanners"] = strings.Join(scannersOpt, ",")
	}
	if req.Options.Profile != "" {
		details["profile"] = req.Options.Profile
	}
	if req.Options.Triage != nil {
		details["triage"] = strconv.FormatBool(*req.Options.Triage)
	}
	s.audit(audit.EventScanLaunch, actor, details)
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleScanByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	if id == "" || strings.Contains(id, "/") || s.queue == nil {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	job, ok := s.queue.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// --- audit ---

// AuditResponse is GET /api/audit (admin only), newest entry last.
type AuditResponse struct {
	Entries []audit.Entry `json:"entries"`
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resp := AuditResponse{Entries: []audit.Entry{}}
	if s.auditLog != nil {
		n := 200
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 2000 {
				n = parsed
			}
		}
		entries, err := s.auditLog.Tail(n)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to read audit log")
			return
		}
		resp.Entries = append(resp.Entries, entries...)
	}
	writeJSON(w, http.StatusOK, resp)
}
