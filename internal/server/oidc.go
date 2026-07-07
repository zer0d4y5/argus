package server

import (
	"context"
	"net/http"
	"os"

	"github.com/leaky-hub/argus/internal/audit"
	"github.com/leaky-hub/argus/internal/server/auth"
)

// Single sign-on (OIDC) endpoints. Both are pre-auth (the user isn't signed in
// yet) and GET-only: the flow's CSRF protection is the one-time state, not the
// header the mutation routes use. A successful callback mints the same session
// a password login does; SSO only changes how the session is born.

// oidc returns the lazily-built provider for the effective config (the console
// store, else appsec.yml), or nil when SSO is not configured. A discovery
// failure is cached and never blocks password login. An admin config change
// calls invalidateOIDC to force a rebuild. Tests may inject s.oidcProvider.
func (s *Server) oidc() (oidcAuthenticator, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.oidcProvider != nil { // test injection or already built
		return s.oidcProvider, s.oidcErr
	}
	if s.oidcBuilt {
		return nil, s.oidcErr // already tried: disabled or failed
	}
	s.oidcBuilt = true
	o, source := s.effectiveOIDC()
	if source == "none" || !o.Enabled() {
		return nil, nil
	}
	secret := os.Getenv(o.SecretEnv())
	p, err := auth.NewOIDCProvider(context.Background(), auth.OIDCParams{
		Issuer:         o.Issuer,
		ClientID:       o.ClientID,
		ClientSecret:   secret,
		RedirectURL:    o.RedirectURL,
		AllowedDomains: o.AllowedDomains,
		DefaultRole:    auth.Role(o.EffectiveDefaultRole()),
		GroupClaim:     o.GroupClaim,
		RoleMap:        o.RoleMap,
	})
	if err != nil {
		s.oidcErr = err
		return nil, err
	}
	s.oidcProvider = p
	return p, nil
}

// invalidateOIDC drops the cached provider so the next login rebuilds it from
// the current config. Called after an admin config change.
func (s *Server) invalidateOIDC() {
	s.oidcMu.Lock()
	s.oidcProvider = nil
	s.oidcErr = nil
	s.oidcBuilt = false
	s.oidcMu.Unlock()
}

// ssoEnabled reports whether the login page should offer the SSO button. It is
// a cheap config check — it does NOT trigger discovery, so a page load never
// waits on the IdP.
func (s *Server) ssoEnabled() bool {
	if s.users == nil {
		return false
	}
	o, _ := s.effectiveOIDC()
	return o.Enabled()
}

// handleOIDCStart redirects the browser to the identity provider.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p, err := s.oidc()
	if err != nil || p == nil {
		// Misconfigured or disabled: send the user back to the login page with
		// a generic flag rather than leaking config detail.
		http.Redirect(w, r, "/?sso_error=1", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, p.AuthURL(), http.StatusSeeOther)
}

// handleOIDCCallback completes the flow: verify the identity, provision or
// resolve the user, mint a session, and land on the console. Every failure
// redirects to the login page with a generic flag; the specific reason is
// audited, never reflected to the browser.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	fail := func(reason string) {
		s.audit(audit.EventLoginFailure, "-", map[string]string{"method": "oidc", "reason": reason, "ip": clientIP(r)})
		http.Redirect(w, r, "/?sso_error=1", http.StatusSeeOther)
	}
	p, err := s.oidc()
	if err != nil || p == nil {
		fail("provider unavailable")
		return
	}
	// The IdP signals user-denied / errored consent via an error param.
	if e := r.URL.Query().Get("error"); e != "" {
		fail("idp error")
		return
	}
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	if state == "" || code == "" {
		fail("missing state or code")
		return
	}
	claims, err := p.Exchange(r.Context(), state, code)
	if err != nil {
		fail("exchange/verify failed")
		return
	}
	role, err := p.Authorize(claims)
	if err != nil {
		fail("not authorized")
		return
	}
	user, created, err := s.users.FindOrCreateOIDC(claims.Subject, claims.Email, role)
	if err != nil {
		fail("provisioning failed")
		return
	}

	token, sess := s.sessions.Create(user)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		// Strict, matching password sessions: the cookie is set here and first
		// read on the same-origin redirect to "/", so Strict suffices.
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsTLS(r),
	})
	meta := map[string]string{"method": "oidc", "ip": clientIP(r)}
	if created {
		meta["provisioned"] = "true"
	}
	s.audit(audit.EventLoginSuccess, user.Username, meta)
	_ = sess
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
