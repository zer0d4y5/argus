// Package dastauth establishes an authenticated session against a running web
// target so an active DAST scan can reach pages behind a login. It detects the
// login form, tries credentials (caller-supplied first, then optionally a
// bounded list of well-known vendor defaults), submits the login while
// carrying any per-session CSRF token, and verifies the resulting session is
// actually authenticated before handing it back.
//
// SECURITY:
//   - User-supplied credentials are referenced by env-var NAME upstream (see
//     targets.Config) and reach this package only as ephemeral values; nothing
//     here writes them anywhere. The built-in default-credential list is public
//     vendor-default knowledge, not secret material.
//   - The obtained session (its cookies) is a live credential. It is held in
//     memory for one scan and is NEVER written to a finding, a saved run, a
//     progress line, or a log. Only the username that worked is ever surfaced,
//     and only to progress ("authenticated as <user>").
//   - Trying default credentials is an active credential test. It is opt-in per
//     target and bounded to a short list, for authorized testing of a target
//     the operator registered. It is deliberately not a brute-forcer: no
//     wordlists, no lockout-evasion, no large candidate sets.
package dastauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
)

// maxLoginBody bounds how much of a login/verify page we read into memory.
const maxLoginBody = 4 << 20 // 4 MiB

// Credential is one username/password candidate.
type Credential struct {
	Username string
	Password string
}

// Config controls how authentication is attempted.
type Config struct {
	// LoginURL is the page carrying the login form. Empty means use the scan's
	// base URL (many apps show the login form on the landing page).
	LoginURL string
	// Credentials are caller-supplied candidates (resolved from env-var
	// references upstream), tried in order before any defaults.
	Credentials []Credential
	// TryDefaults also tries the built-in vendor-default list after the
	// caller-supplied credentials. Opt-in.
	TryDefaults bool
	// SuccessMarker, when set, is text whose presence on a post-login page
	// confirms authentication. Empty uses the built-in heuristic (the login
	// form is gone, or a logout affordance appeared).
	SuccessMarker string
}

// defaultCreds is a short, public list of well-known vendor defaults. It is not
// a brute-force wordlist: it exists so an operator scanning their own target
// does not have to hand-configure the obvious first guess.
var defaultCreds = []Credential{
	{"admin", "password"},
	{"admin", "admin"},
	{"admin", ""},
	{"administrator", "password"},
	{"root", "root"},
	{"root", "toor"},
	{"user", "user"},
	{"test", "test"},
	{"guest", "guest"},
	{"admin", "admin123"},
	{"admin", "changeme"},
	{"tomcat", "tomcat"},
}

// Session is an authenticated session ready to drive a scanner. It exposes the
// cookies as a header value; it never exposes or persists them any other way.
type Session struct {
	jar  http.CookieJar
	base *url.URL
	User string // the username that authenticated (safe to log; never the password)
	// Model is what authentication observed about the target's auth machinery:
	// the mechanism, whether a CSRF token was carried, and the session cookies
	// set at login with their security flags. It never carries a cookie VALUE,
	// only the name and flags.
	Model AuthModel
}

// AuthModel is the recon view of a target's authentication flow. It is built
// during login from what the target served, and drives the session-cookie
// hardening findings.
type AuthModel struct {
	Mechanism  string       // e.g. "form-login"
	LoginURL   string       // where the login form was submitted
	CSRFField  string       // the login form's CSRF token field name ("" if none)
	SetCookies []CookieInfo // cookies the login response set, with flags (no values)
}

// CookieInfo is a cookie's identity and security flags, never its value.
type CookieInfo struct {
	Name     string
	HTTPOnly bool
	Secure   bool
	SameSite string // "Strict" | "Lax" | "None" | "" (unset)
}

// Client returns an http.Client that carries this session's cookies, borrowing
// base's transport and timeout. A crawler uses it to fetch pages as the
// logged-in user without re-sending the login each request.
func (s *Session) Client(base *http.Client) *http.Client {
	if s == nil {
		return base
	}
	return withJar(base, s.jar)
}

// CookieHeader renders the session's cookies for the base URL as a single
// Cookie header value ("a=1; b=2"), or "" if the session carries none. This is
// the value an active scanner sends to stay authenticated.
func (s *Session) CookieHeader() string {
	if s == nil || s.jar == nil || s.base == nil {
		return ""
	}
	var parts []string
	for _, c := range s.jar.Cookies(s.base) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// Authenticate detects the login form at cfg.LoginURL (or baseURL), tries each
// credential, and returns the first session that verifies as authenticated. A
// nil client uses http.DefaultClient's behavior with a fresh per-attempt jar.
// progress may be nil.
func Authenticate(ctx context.Context, client *http.Client, baseURL string, cfg Config, progress func(string)) (*Session, error) {
	if progress == nil {
		progress = func(string) {}
	}
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("dastauth: invalid base URL")
	}
	loginURL := strings.TrimSpace(cfg.LoginURL)
	if loginURL == "" {
		loginURL = baseURL
	}

	cands := append([]Credential{}, cfg.Credentials...)
	if cfg.TryDefaults {
		cands = append(cands, defaultCreds...)
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("dastauth: no credentials to try (supply credentials or enable defaults)")
	}

	for _, c := range cands {
		// A fresh jar per attempt: a failed login must not leak cookies into the
		// next try, and a rotating CSRF token is re-read from the form each time.
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("dastauth: cookie jar: %w", err)
		}
		cl := withJar(client, jar)
		// Record Set-Cookie attributes across the whole login flow (form GET,
		// submit, any redirect) so the auth model reflects the session cookies'
		// real flags, which the jar strips.
		rec := &cookieRecorder{rt: transportOf(cl), seen: map[string]*http.Cookie{}}
		cl.Transport = rec

		form, err := fetchLoginForm(ctx, cl, loginURL)
		if err != nil {
			// The login page being unreachable or form-less is a hard, credential
			// -independent failure: report it once rather than looping.
			return nil, err
		}

		if err := form.submit(ctx, cl, c); err != nil {
			continue // this candidate failed to submit; try the next
		}
		if authed, _ := isAuthenticated(ctx, cl, baseURL, cfg.SuccessMarker); authed {
			progress(fmt.Sprintf("==> authenticated as %q\n", c.Username))
			return &Session{
				jar: jar, base: base, User: c.Username,
				Model: AuthModel{
					Mechanism:  "form-login",
					LoginURL:   loginURL,
					CSRFField:  csrfFieldName(form.fields),
					SetCookies: cookieInfos(rec.cookies()),
				},
			}, nil
		}
	}
	return nil, fmt.Errorf("dastauth: authentication failed: none of the %d credential(s) worked", len(cands))
}

// withJar returns a client that follows redirects and uses jar, borrowing the
// caller's transport and timeout.
func withJar(base *http.Client, jar http.CookieJar) *http.Client {
	c := &http.Client{Jar: jar}
	if base != nil {
		c.Timeout = base.Timeout
		c.Transport = base.Transport
	}
	return c
}

// transportOf returns a client's transport, or the default when unset.
func transportOf(c *http.Client) http.RoundTripper {
	if c != nil && c.Transport != nil {
		return c.Transport
	}
	return http.DefaultTransport
}

// loginForm is the parsed login form: where to POST, the field names, and any
// hidden fields (including a CSRF token) that must be echoed back.
type loginForm struct {
	action    string
	method    string
	userField string
	passField string
	fields    map[string]string // all named inputs (hidden + submit + defaults)
}

// fetchLoginForm GETs the login page and parses its login form. The GET also
// seeds the jar with the session cookie the CSRF token is bound to.
func fetchLoginForm(ctx context.Context, cl *http.Client, loginURL string) (*loginForm, error) {
	body, finalURL, err := get(ctx, cl, loginURL)
	if err != nil {
		return nil, fmt.Errorf("dastauth: fetch login page: %w", err)
	}
	form, err := parseLoginForm(finalURL, body)
	if err != nil {
		return nil, fmt.Errorf("dastauth: %s: %w", loginURL, err)
	}
	return form, nil
}

// submit posts the credential through the form, filling the username/password
// fields and echoing every hidden field (so a CSRF token round-trips).
func (f *loginForm) submit(ctx context.Context, cl *http.Client, c Credential) error {
	vals := url.Values{}
	for k, v := range f.fields {
		vals.Set(k, v)
	}
	if f.userField != "" {
		vals.Set(f.userField, c.Username)
	}
	vals.Set(f.passField, c.Password)

	if strings.EqualFold(f.method, "GET") {
		u := f.action
		if strings.Contains(u, "?") {
			u += "&" + vals.Encode()
		} else {
			u += "?" + vals.Encode()
		}
		_, _, err := get(ctx, cl, u)
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.action, strings.NewReader(vals.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxLoginBody))
	return nil
}

// cookieRecorder wraps a RoundTripper and records the Set-Cookie entries from
// every response (across redirects), keeping the full attributes the cookie jar
// drops. It is used only during authentication to model the session cookies'
// security flags; it never stores a value beyond the in-memory attempt.
type cookieRecorder struct {
	rt   http.RoundTripper
	mu   sync.Mutex
	seen map[string]*http.Cookie // by name, last wins
}

func (c *cookieRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.rt.RoundTrip(req)
	if resp != nil {
		c.mu.Lock()
		for _, ck := range resp.Cookies() {
			c.seen[ck.Name] = ck
		}
		c.mu.Unlock()
	}
	return resp, err
}

func (c *cookieRecorder) cookies() []*http.Cookie {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*http.Cookie, 0, len(c.seen))
	for _, ck := range c.seen {
		out = append(out, ck)
	}
	return out
}

// csrfFieldName returns the name of the login form's CSRF token field, or "".
func csrfFieldName(fields map[string]string) string {
	for name := range fields {
		l := strings.ToLower(name)
		if strings.Contains(l, "csrf") || strings.Contains(l, "authenticity") ||
			strings.Contains(l, "_token") || l == "token" || l == "nonce" {
			return name
		}
	}
	return ""
}

// cookieInfos maps captured Set-Cookie entries to their identity and flags,
// dropping the value.
func cookieInfos(cs []*http.Cookie) []CookieInfo {
	out := make([]CookieInfo, 0, len(cs))
	for _, c := range cs {
		out = append(out, CookieInfo{
			Name:     c.Name,
			HTTPOnly: c.HttpOnly,
			Secure:   c.Secure,
			SameSite: sameSiteLabel(c.SameSite),
		})
	}
	return out
}

func sameSiteLabel(s http.SameSite) string {
	switch s {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// isAuthenticated GETs baseURL with the attempt's jar and decides whether the
// session is logged in. With a marker, its presence is authoritative.
// Otherwise the heuristic is: no password field remains AND the page is not
// itself the login form, or a logout affordance is present.
func isAuthenticated(ctx context.Context, cl *http.Client, baseURL, marker string) (bool, error) {
	body, _, err := get(ctx, cl, baseURL)
	if err != nil {
		return false, err
	}
	text := string(body)
	if marker != "" {
		return strings.Contains(text, marker), nil
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "logout") || strings.Contains(lower, "sign out") {
		return true, nil
	}
	return !hasPasswordInput(body), nil
}

// get performs a bounded GET and returns the body and the final URL after
// redirects (for resolving a form's relative action).
func get(ctx context.Context, cl *http.Client, rawURL string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxLoginBody))
	if err != nil {
		return nil, "", err
	}
	final := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return body, final, nil
}
