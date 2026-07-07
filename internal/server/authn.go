package server

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/server/auth"
)

// sessionCookieName holds the opaque session token. HttpOnly + SameSite
// Strict always; Secure when the login itself arrived over TLS (directly or
// via a reverse proxy setting X-Forwarded-Proto).
const sessionCookieName = "appsec_session"

// UserInfo is the hash-free user DTO. It is the ONLY user shape any API
// response carries (docs/console-ops.md T6).
type UserInfo struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"createdAt"`
}

func userInfo(u auth.User) UserInfo {
	return UserInfo{ID: u.ID, Username: u.Username, Role: string(u.Role), CreatedAt: u.CreatedAt.Format(rfc3339)}
}

// MeResponse is GET /api/auth/me — the UI's boot probe.
type MeResponse struct {
	AuthRequired  bool      `json:"authRequired"`
	Authenticated bool      `json:"authenticated"`
	User          *UserInfo `json:"user,omitempty"`
	CSRFToken     string    `json:"csrfToken,omitempty"`
	// GitHubRepo is the configured issue-sync repo ("owner/name"), so the UI
	// knows to offer the button. The repo NAME only — never token material.
	GitHubRepo string `json:"githubRepo,omitempty"`
}

// LoginResponse is POST /api/auth/login on success.
type LoginResponse struct {
	User      UserInfo `json:"user"`
	CSRFToken string   `json:"csrfToken"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	n, err := s.userCount()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "users file unreadable")
		return
	}
	if n == 0 {
		writeJSON(w, http.StatusOK, MeResponse{AuthRequired: false})
		return
	}
	sess, ok := s.liveSession(r)
	if !ok {
		writeJSON(w, http.StatusOK, MeResponse{AuthRequired: true})
		return
	}
	u := UserInfo{ID: sess.UserID, Username: sess.Username, Role: string(sess.Role)}
	resp := MeResponse{AuthRequired: true, Authenticated: true, User: &u, CSRFToken: sess.CSRF}
	// Feature flag for the UI: repo name only, never token material.
	if cfg, err := repoConfig(s.dir); err == nil && cfg.GitHubEnabled() {
		resp.GitHubRepo = cfg.Ticketing.GitHub.Repo
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.users == nil || s.sessions == nil || s.limiter == nil {
		writeErr(w, http.StatusForbidden, bootstrapHint)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		writeErr(w, http.StatusBadRequest, "invalid login request")
		return
	}

	// Rate limit BEFORE touching credentials: a locked key never costs an
	// argon2id derivation. Limited attempts are not audited individually —
	// an attacker must not be able to grow the audit file at line rate.
	ipKey, userKey := "ip:"+clientIP(r), "user:"+req.Username
	if !s.limiter.Allow(ipKey, userKey) {
		writeErr(w, http.StatusTooManyRequests, "too many login attempts — try again later")
		return
	}

	user, ok := s.users.Authenticate(req.Username, req.Password)
	if !ok {
		// Identical status and body for unknown user vs wrong password, and
		// Authenticate burned an argon2id verification either way.
		s.limiter.Failure(ipKey, userKey)
		s.audit(audit.EventLoginFailure, "-", map[string]string{"username": req.Username, "ip": clientIP(r)})
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.limiter.Success(ipKey, userKey)

	token, sess := s.sessions.Create(user)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsTLS(r),
	})
	s.audit(audit.EventLoginSuccess, user.Username, map[string]string{"ip": clientIP(r)})
	writeJSON(w, http.StatusOK, LoginResponse{User: userInfo(user), CSRFToken: sess.CSRF})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && s.sessions != nil {
		s.sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestIsTLS(r),
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// clientIP is the rate-limit key. It uses the socket peer only — trusting
// X-Forwarded-For would let anyone rotate limiter keys with a header. Behind
// the documented single reverse proxy this collapses to one IP, and the
// per-username key still throttles stuffing against an account.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// requestIsTLS reports whether the request arrived over TLS, directly or via
// the documented reverse-proxy deployment.
func requestIsTLS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}
