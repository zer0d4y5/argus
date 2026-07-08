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

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/cloudscan"
	"github.com/zer0d4y5/argus/internal/compliance"
	"github.com/zer0d4y5/argus/internal/jobs"
	"github.com/zer0d4y5/argus/internal/scanner"
	"github.com/zer0d4y5/argus/internal/server/auth"
	"github.com/zer0d4y5/argus/internal/targets"
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
			URL      string   `json:"url"`
			Branch   string   `json:"branch"`
			Scanners []string `json:"scanners"`
			Profile  string   `json:"profile"`
			// Cloud target fields (schema 2.1.0). ProfileName is a NAME from the
			// local config's closed list — NEVER a key. Presence of Provider
			// selects the cloud path.
			Provider    string   `json:"provider"`
			ProfileName string   `json:"profileName"`
			Account     string   `json:"account"` // Azure subscription id / GCP project id
			Regions     []string `json:"regions"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		for i := range req.Scanners {
			req.Scanners[i] = strings.ToLower(strings.TrimSpace(req.Scanners[i]))
		}
		var t targets.Target
		var err error
		switch {
		case req.Provider != "" && (req.Path != "" || req.URL != ""):
			writeErr(w, http.StatusBadRequest, "a cloud target (provider) takes neither path nor url")
			return
		case req.Provider != "":
			// AddCloud validates the provider and the profile NAME against the
			// closed list discovered from the local cloud config (C1/C2). No
			// key material is accepted here — profileName is an identifier only.
			t, err = s.targets.AddCloud(req.Name, req.Provider, req.ProfileName, req.Account, req.Regions, req.Scanners, req.Profile)
		case req.URL != "" && req.Path != "":
			writeErr(w, http.StatusBadRequest, "provide either path (directory target) or url (git target), not both")
			return
		case req.URL != "":
			// ValidateGitURL (inside AddGit) enforces the S1 policy: https
			// only, host present, no embedded credentials.
			t, err = s.targets.AddGit(req.Name, req.URL, req.Branch, req.Scanners, req.Profile)
		default:
			// ValidatePath (inside Add) demands an absolute path: the server's
			// CWD means nothing to a browser user, so nothing is resolved.
			t, err = s.targets.Add(req.Name, req.Path, req.Scanners, req.Profile)
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		details := map[string]string{"target": t.ID, "name": t.Name, "type": t.Kind()}
		switch t.Kind() {
		case targets.TypeGit:
			details["url"] = t.URL
			if t.Branch != "" {
				details["branch"] = t.Branch
			}
		case targets.TypeCloud:
			// The profile NAME is registry metadata, not a secret; recording it
			// in the audit line is the C1/C3 story (a NAME was registered, no
			// credential). No key material exists to leak.
			details["provider"] = t.Provider
			details["profileName"] = t.ProfileName
		default:
			details["path"] = t.Path
		}
		s.audit(audit.EventTargetCreate, actorFrom(r), details)
		writeJSON(w, http.StatusCreated, t)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleTargetByID(w http.ResponseWriter, r *http.Request) {
	if s.targets == nil {
		writeErr(w, http.StatusForbidden, bootstrapHint)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusBadRequest, "invalid target id")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		s.handleTargetUpdate(w, r, id)
	case http.MethodDelete:
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
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleTargetUpdate is the console-managed scan configuration (S3):
// name/scanners/profile plus the closed config block. Registration identity
// (type/path/url/branch) is immutable here by design — re-pointing a target
// is a delete + re-add, both audited.
func (s *Server) handleTargetUpdate(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Name     *string         `json:"name"`
		Scanners *[]string       `json:"scanners"`
		Profile  *string         `json:"profile"`
		Config   *targets.Config `json:"config"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Scanners != nil {
		for i := range *req.Scanners {
			(*req.Scanners)[i] = strings.ToLower(strings.TrimSpace((*req.Scanners)[i]))
		}
	}
	t, changed, err := s.targets.Update(id, targets.Patch{
		Name: req.Name, Scanners: req.Scanners, Profile: req.Profile, Config: req.Config,
	})
	if err != nil {
		if errors.Is(err, targets.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "target not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(changed) > 0 {
		details := map[string]string{"target": t.ID, "name": t.Name, "changed": strings.Join(changed, ",")}
		// Suppression is the finding-killing knob: the audit line carries the
		// pattern/rule text so every suppression is reviewable (S3).
		if req.Config != nil {
			if len(req.Config.IgnorePaths) > 0 {
				details["ignorePaths"] = strings.Join(req.Config.IgnorePaths, ",")
			}
			if len(req.Config.IgnoreRules) > 0 {
				details["ignoreRules"] = strings.Join(req.Config.IgnoreRules, ",")
			}
		}
		s.audit(audit.EventTargetUpdate, actorFrom(r), details)
	}
	writeJSON(w, http.StatusOK, t)
}

// --- scans ---

// ScanRequest is POST /api/scans: an opaque target ID plus closed-enum
// options. NO free-form strings in here ever reach a scanner invocation
// (docs/console-ops.md T1/T2). Scope is the one string that touches a path,
// and only through targets.ResolveScope's confinement (S2).
type ScanRequest struct {
	TargetID string `json:"targetId"`
	Options  struct {
		Scanners   []string `json:"scanners"`
		Profile    string   `json:"profile"`
		Triage     *bool    `json:"triage"`
		Scope      string   `json:"scope"`
		Frameworks []string `json:"frameworks"`
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

	// Cloud targets run prowler over an account: the filesystem launch knobs
	// (scanner subset, semgrep profile, path scope, framework focus) do not
	// apply, so reject them rather than silently ignore — an accepted-but-inert
	// option is a lie about what the scan will do. Only the triage toggle
	// carries over.
	if t.Kind() == targets.TypeCloud {
		if len(req.Options.Scanners) > 0 || req.Options.Profile != "" || req.Options.Scope != "" || len(req.Options.Frameworks) > 0 {
			writeErr(w, http.StatusBadRequest, "cloud targets take no scanner/profile/scope/framework options — only the triage toggle applies")
			return
		}
		actor := actorFrom(r)
		job, err := s.queue.Enqueue(t.ID, t.Name, actor, jobs.Options{Triage: req.Options.Triage})
		if err != nil {
			if errors.Is(err, jobs.ErrQueueFull) {
				writeErr(w, http.StatusTooManyRequests, "scan queue is full — try again after pending scans finish")
				return
			}
			writeErr(w, http.StatusInternalServerError, "failed to enqueue scan")
			return
		}
		s.audit(audit.EventScanLaunch, actor, launchDetails(job, t))
		writeJSON(w, http.StatusAccepted, job)
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

	// S2: confine the scope at enqueue. For dir targets the tree exists now,
	// so this is the full check (existence included); for git targets the
	// workspace may not exist yet, so enqueue rejects the syntactic attacks
	// and the executor re-runs the full confinement against the fresh clone.
	if req.Options.Scope != "" {
		if t.Kind() == targets.TypeGit {
			if err := targets.ValidateScopeSyntax(req.Options.Scope); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		} else {
			if _, err := targets.ResolveScope(s.targets.Root(t), req.Options.Scope); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}

	// S6: frameworks are a closed enum, and focusing must leave at least one
	// relevant scanner in the effective set.
	if len(req.Options.Frameworks) > 0 {
		effective := scannersOpt
		if len(effective) == 0 {
			effective = allowed
		}
		if _, err := compliance.NarrowScanners(effective, req.Options.Frameworks); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	actor := actorFrom(r)
	job, err := s.queue.Enqueue(t.ID, t.Name, actor, jobs.Options{
		Scanners:   scannersOpt,
		Profile:    req.Options.Profile,
		Triage:     req.Options.Triage,
		Scope:      req.Options.Scope,
		Frameworks: req.Options.Frameworks,
	})
	if err != nil {
		if errors.Is(err, jobs.ErrQueueFull) {
			writeErr(w, http.StatusTooManyRequests, "scan queue is full — try again after pending scans finish")
			return
		}
		writeErr(w, http.StatusInternalServerError, "failed to enqueue scan")
		return
	}

	s.audit(audit.EventScanLaunch, actor, launchDetails(job, t))
	writeJSON(w, http.StatusAccepted, job)
}

// FrameworksResponse is GET /api/frameworks: the closed compliance enum the
// launcher's framework picker offers.
type FrameworksResponse struct {
	Frameworks []FrameworkInfo `json:"frameworks"`
}

// FrameworkInfo describes one embedded framework and the scanners relevant
// to it (the S6 narrowing table, surfaced so the UI can hint).
type FrameworkInfo struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Scanners []string `json:"scanners"`
}

func (s *Server) handleFrameworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	fws, err := compliance.Frameworks()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "compliance data unavailable")
		return
	}
	resp := FrameworksResponse{Frameworks: []FrameworkInfo{}}
	for i := range fws {
		relevant, _ := compliance.NarrowScanners(targets.KnownScanners(), []string{fws[i].ID})
		if relevant == nil {
			relevant = []string{}
		}
		resp.Frameworks = append(resp.Frameworks, FrameworkInfo{
			ID: fws[i].ID, Name: fws[i].Name, Version: fws[i].Version, Scanners: relevant,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// CloudProfilesResponse is GET /api/cloud/profiles: the closed list of cloud
// profile NAMES discovered from the console host's local config, offered to
// the cloud-target registration form. Names only — the browser never sees or
// sends key material, and never sends a free-form name into an env var
// (C1/C2): registration re-validates the chosen name against this same list.
type CloudProfilesResponse struct {
	Providers []CloudProviderProfiles `json:"providers"`
}

// CloudProviderProfiles is one provider's discovered profile names.
type CloudProviderProfiles struct {
	Provider string   `json:"provider"`
	Profiles []string `json:"profiles"`
}

func (s *Server) handleCloudProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// AWS is the only provider this beat. Discovery reads ONLY section headers
	// of the local config; credential values are never parsed (profiles.go).
	awsProfiles, err := cloudscan.ListAWSProfiles()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to discover cloud profiles")
		return
	}
	if awsProfiles == nil {
		awsProfiles = []string{}
	}
	writeJSON(w, http.StatusOK, CloudProfilesResponse{
		Providers: []CloudProviderProfiles{{Provider: cloudscan.ProviderAWS, Profiles: awsProfiles}},
	})
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
