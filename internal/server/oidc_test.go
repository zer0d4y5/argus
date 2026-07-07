package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leaky-hub/argus/internal/server/auth"
)

// fakeOIDC is an injected authenticator: it stands in for the real provider so
// the server test exercises the handler glue (provisioning, session, cookie,
// audit, redirects) without a live IdP. The crypto path is covered in the auth
// package's fake-IdP tests.
type fakeOIDC struct {
	claims  auth.OIDCClaims
	exchErr error
	authErr error
	role    auth.Role
}

func (f *fakeOIDC) AuthURL() string { return "https://idp.example/authorize?state=x" }
func (f *fakeOIDC) Exchange(_ context.Context, state, code string) (auth.OIDCClaims, error) {
	if f.exchErr != nil {
		return auth.OIDCClaims{}, f.exchErr
	}
	return f.claims, nil
}
func (f *fakeOIDC) Authorize(auth.OIDCClaims) (auth.Role, error) {
	if f.authErr != nil {
		return "", f.authErr
	}
	return f.role, nil
}

// doNoRedirect issues a request that does NOT follow redirects, returning the
// recorder so the test can inspect Location and Set-Cookie.
func (f *consoleFixture) doRaw(method, path string) *http.Response {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec.Result()
}

// TestSSOEnabledFlag: /api/auth/me reports ssoEnabled only when the served
// repo's config has an OIDC block.
func TestSSOEnabledFlag(t *testing.T) {
	f := newConsole(t, nil)
	// No config → not enabled, even to an unauthenticated caller.
	rec := f.do("GET", "/api/auth/me", "", session{})
	if strings.Contains(rec.Body.String(), `"ssoEnabled":true`) {
		t.Error("ssoEnabled true without config")
	}
	// Configure OIDC in the served repo's appsec.yml.
	writeFile(t, f.dir, "appsec.yml", "auth:\n  oidc:\n    issuer: https://accounts.google.com\n    client_id: abc\n    redirect_url: http://127.0.0.1:8080/api/auth/oidc/callback\n")
	rec = f.do("GET", "/api/auth/me", "", session{})
	if !strings.Contains(rec.Body.String(), `"ssoEnabled":true`) {
		t.Errorf("ssoEnabled not reported when configured: %s", rec.Body.String())
	}
}

// TestSSOStartDisabledRedirects: with no provider, /start bounces back to the
// login page with a generic flag rather than erroring.
func TestSSOStartDisabledRedirects(t *testing.T) {
	f := newConsole(t, nil)
	resp := f.doRaw("GET", "/api/auth/oidc/start")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?sso_error=1" {
		t.Errorf("disabled start = %d %q, want 303 /?sso_error=1", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// TestSSOCallbackProvisionsAndSignsIn drives the happy path through the handler
// with an injected authenticator: a verified identity provisions a user, mints
// a session cookie, and lands on the console; that cookie then authenticates.
func TestSSOCallbackProvisionsAndSignsIn(t *testing.T) {
	f := newConsole(t, nil)
	f.srv.oidcProvider = &fakeOIDC{
		claims: auth.OIDCClaims{Subject: "sub-9", Email: "dana@example.com", EmailVerified: true},
		role:   auth.RoleViewer,
	}

	resp := f.doRaw("GET", "/api/auth/oidc/callback?state=x&code=abc")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback = %d %q, want 303 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("callback set no session cookie")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie flags wrong: httpOnly=%v samesite=%v", cookie.HttpOnly, cookie.SameSite)
	}

	// The user was provisioned as an SSO user at the default role.
	list, _ := f.srv.users.List()
	var provisioned bool
	for _, u := range list {
		if u.Subject == "sub-9" {
			provisioned = true
			if u.AuthProvider() != auth.ProviderOIDC || u.Hash != "" || u.Role != auth.RoleViewer {
				t.Errorf("bad provisioned user: %+v", u)
			}
		}
	}
	if !provisioned {
		t.Fatal("no user provisioned from the SSO login")
	}

	// The minted cookie authenticates a follow-up request.
	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"authenticated":true`) {
		t.Errorf("SSO session did not authenticate: %s", rec.Body.String())
	}

	// The success was audited as an oidc login.
	auditRaw, _ := os.ReadFile(filepath.Join(f.dir, ".appsec", "audit.jsonl"))
	if !strings.Contains(string(auditRaw), "oidc") || !strings.Contains(string(auditRaw), "provisioned") {
		t.Errorf("audit missing oidc provisioning event: %s", auditRaw)
	}
}

// TestSSOCallbackRejections: exchange/verify failure, authorization denial, and
// missing params all bounce to the login page with a generic flag and audit a
// failure — no session minted.
func TestSSOCallbackRejections(t *testing.T) {
	cases := []struct {
		name  string
		prov  *fakeOIDC
		query string
	}{
		{"missing code", &fakeOIDC{}, "?state=x"},
		{"exchange fails", &fakeOIDC{exchErr: fmt.Errorf("verify failed")}, "?state=x&code=c"},
		{"not authorized", &fakeOIDC{claims: auth.OIDCClaims{Subject: "s", Email: "x@evil.com"}, authErr: fmt.Errorf("domain not allowed")}, "?state=x&code=c"},
		{"idp error param", &fakeOIDC{}, "?error=access_denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConsole(t, nil)
			f.srv.oidcProvider = tc.prov
			resp := f.doRaw("GET", "/api/auth/oidc/callback"+tc.query)
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?sso_error=1" {
				t.Errorf("%s = %d %q, want 303 /?sso_error=1", tc.name, resp.StatusCode, resp.Header.Get("Location"))
			}
			for _, c := range resp.Cookies() {
				if c.Name == sessionCookieName && c.Value != "" {
					t.Errorf("%s minted a session on failure", tc.name)
				}
			}
		})
	}
}
