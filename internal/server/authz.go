package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/leaky-hub/appsec/internal/server/auth"
)

// This file is the console's entire authorization policy: ONE table, ONE
// middleware, matched top-to-bottom. The UI hides what a role cannot do as
// a courtesy; this table is what actually decides. It must stay in lockstep
// with docs/console-ops.md §5, and the authz matrix test walks every row.

// bootstrapHint names the command that creates the first user; it is the
// body of every 403 in zero-users mode.
const bootstrapHint = "console operations are disabled: no users configured — bootstrap with `appsec user add <name> --role admin`"

// authzRule is one row of the policy.
type authzRule struct {
	method  string    // exact HTTP method
	path    string    // exact path, or prefix when trailing '/'
	minRole auth.Role // minimum role when users exist; "" = no session required
	// zeroOpen: with ZERO users on disk, is this route open (the pre-auth,
	// read-only console behavior) or refused with the bootstrap hint?
	zeroOpen bool
}

// authzTable is matched first-hit; put exact paths before their prefixes.
var authzTable = []authzRule{
	{http.MethodGet, "/api/health", "", true},
	{http.MethodGet, "/api/auth/me", "", true},
	{http.MethodPost, "/api/auth/login", "", false},
	{http.MethodPost, "/api/auth/logout", auth.RoleViewer, false},

	{http.MethodGet, "/api/summary", auth.RoleViewer, true},
	{http.MethodGet, "/api/runs", auth.RoleViewer, true},
	{http.MethodGet, "/api/runs/", auth.RoleViewer, true},

	{http.MethodGet, "/api/targets", auth.RoleViewer, true},
	{http.MethodPost, "/api/targets", auth.RoleAdmin, false},
	{http.MethodDelete, "/api/targets/", auth.RoleAdmin, false},

	{http.MethodGet, "/api/scans", auth.RoleViewer, true},
	{http.MethodGet, "/api/scans/", auth.RoleViewer, true},
	{http.MethodPost, "/api/scans", auth.RoleOperator, false},

	{http.MethodGet, "/api/users", auth.RoleAdmin, false},
	{http.MethodPost, "/api/users", auth.RoleAdmin, false},
	{http.MethodPatch, "/api/users/", auth.RoleAdmin, false},
	{http.MethodDelete, "/api/users/", auth.RoleAdmin, false},

	{http.MethodGet, "/api/audit", auth.RoleAdmin, false},
}

// matchRule finds the policy row for a request. Unlisted API routes fail
// closed: GETs get viewer/zero-open (they can only reach read handlers or a
// 404), anything else requires admin and is refused in zero-users mode.
func matchRule(method, path string) authzRule {
	for _, r := range authzTable {
		if r.method != method {
			continue
		}
		if strings.HasSuffix(r.path, "/") {
			if strings.HasPrefix(path, r.path) && path != strings.TrimSuffix(r.path, "/") {
				return r
			}
		} else if r.path == path {
			return r
		}
	}
	if method == http.MethodGet {
		return authzRule{method, path, auth.RoleViewer, true}
	}
	return authzRule{method, path, auth.RoleAdmin, false}
}

// ctxKey is the context key type for the authenticated session.
type ctxKey int

const sessionKey ctxKey = 0

// sessionFromContext returns the authenticated session, if any. In
// zero-users mode there is none and Username is "".
func sessionFromContext(ctx context.Context) (auth.Session, bool) {
	s, ok := ctx.Value(sessionKey).(auth.Session)
	return s, ok
}

// userCount is the switch between the open read-only console and full auth.
// An unreadable users file counts as "users exist" — fail closed, nobody
// authenticates — never as "no users, no auth".
func (s *Server) userCount() (int, error) {
	if s.users == nil {
		return 0, nil
	}
	return s.users.Count()
}

// authGate enforces the table on every /api request. Non-API paths (the SPA
// shell and assets, including the login page) pass straight through.
func (s *Server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		rule := matchRule(r.Method, r.URL.Path)

		n, err := s.userCount()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "users file unreadable — refusing all authentication")
			return
		}
		if n == 0 {
			if rule.zeroOpen {
				next.ServeHTTP(w, r)
				return
			}
			writeErr(w, http.StatusForbidden, bootstrapHint)
			return
		}

		if rule.minRole == "" { // login / me / health run their own logic
			next.ServeHTTP(w, r)
			return
		}

		sess, ok := s.liveSession(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !sess.Role.AtLeast(rule.minRole) {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		// CSRF: second layer behind SameSite=Strict, on every non-GET.
		if r.Method != http.MethodGet && !s.sessions.CheckCSRF(sess, r.Header.Get("X-CSRF-Token")) {
			writeErr(w, http.StatusForbidden, "missing or invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}

// liveSession resolves the request's cookie to a session AND re-validates it
// against the current user store: a deleted user, a changed password (API or
// CLI), or a role change takes effect on the very next request, not at
// session expiry. The returned session carries the LIVE role.
func (s *Server) liveSession(r *http.Request) (auth.Session, bool) {
	if s.sessions == nil || s.users == nil {
		return auth.Session{}, false
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return auth.Session{}, false
	}
	sess, ok := s.sessions.Get(c.Value)
	if !ok {
		return auth.Session{}, false
	}
	u, ok := s.users.Lookup(sess.UserID)
	if !ok || u.Hash != sess.HashAtLogin {
		s.sessions.DeleteUser(sess.UserID)
		return auth.Session{}, false
	}
	sess.Role = u.Role
	return sess, true
}
