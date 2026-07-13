package dastauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeLoginApp is an in-memory app with a CSRF-protected login form, mirroring
// DVWA's shape: GET issues a session cookie and a per-session token; POST
// accepts only the matching token and the right credentials, then flips the
// session to authenticated (no password field, a logout link).
type fakeLoginApp struct {
	mu      sync.Mutex
	tokens  map[string]string // session -> current token
	authed  map[string]bool   // session -> logged in
	user    string
	pass    string
	next    int
	loginAt string // path serving the login form ("/" by default)
}

func newFakeApp(user, pass string) *fakeLoginApp {
	return &fakeLoginApp{tokens: map[string]string{}, authed: map[string]bool{}, user: user, pass: pass, loginAt: "/"}
}

func (a *fakeLoginApp) session(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("SESS"); err == nil && c.Value != "" {
		return c.Value
	}
	a.mu.Lock()
	a.next++
	sid := fmt.Sprintf("s%d", a.next)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "SESS", Value: sid, Path: "/"})
	return sid
}

func (a *fakeLoginApp) handler() http.Handler {
	mux := http.NewServeMux()
	serveLogin := func(w http.ResponseWriter, r *http.Request) {
		sid := a.session(w, r)
		a.mu.Lock()
		authed := a.authed[sid]
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil &&
				r.Form.Get("token") == a.tokens[sid] &&
				r.Form.Get("username") == a.user &&
				r.Form.Get("password") == a.pass {
				a.authed[sid] = true
				authed = true
			}
		}
		// Issue a fresh token for the next GET render.
		tok := fmt.Sprintf("t%d", a.next*7+len(a.tokens))
		a.tokens[sid] = tok
		a.mu.Unlock()

		if authed {
			w.Write([]byte(`<html><body>Welcome. <a href="/logout">Logout</a></body></html>`))
			return
		}
		fmt.Fprintf(w, `<html><body><form action="%s" method="post">
<input type="text" name="username">
<input type="password" name="password">
<input type="hidden" name="token" value="%s">
<input type="submit" name="Login" value="Login">
</form></body></html>`, a.loginAt, tok)
	}
	mux.HandleFunc("/", serveLogin)
	return mux
}

func TestAuthenticateWithCSRFAndCredentials(t *testing.T) {
	app := newFakeApp("admin", "s3cret")
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	// Wrong password first, correct second: exercises per-attempt fresh jar and
	// token, and confirms only the right credential authenticates.
	sess, err := Authenticate(context.Background(), srv.Client(), srv.URL+"/", Config{
		Credentials: []Credential{{"admin", "wrong"}, {"admin", "s3cret"}},
	}, nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.User != "admin" {
		t.Errorf("User = %q, want admin", sess.User)
	}
	if !strings.Contains(sess.CookieHeader(), "SESS=") {
		t.Errorf("cookie header missing session: %q", sess.CookieHeader())
	}
}

func TestAuthenticateCapturesAuthModel(t *testing.T) {
	app := newFakeApp("admin", "s3cret")
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	sess, err := Authenticate(context.Background(), srv.Client(), srv.URL+"/", Config{
		Credentials: []Credential{{"admin", "s3cret"}},
	}, nil)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.Model.Mechanism != "form-login" {
		t.Errorf("mechanism = %q, want form-login", sess.Model.Mechanism)
	}
	if sess.Model.CSRFField != "token" {
		t.Errorf("CSRFField = %q, want token", sess.Model.CSRFField)
	}
	// The app sets SESS with no security flags; the model must record it and its
	// (absent) flags without carrying a value.
	var sessCookie *CookieInfo
	for i := range sess.Model.SetCookies {
		if sess.Model.SetCookies[i].Name == "SESS" {
			sessCookie = &sess.Model.SetCookies[i]
		}
	}
	if sessCookie == nil {
		t.Fatalf("SESS cookie not captured in the model: %+v", sess.Model.SetCookies)
	}
	if sessCookie.HTTPOnly || sessCookie.Secure || sessCookie.SameSite != "" {
		t.Errorf("expected no flags on the fake cookie, got %+v", *sessCookie)
	}
}

func TestAuthenticateFailsClosedOnBadCredentials(t *testing.T) {
	app := newFakeApp("admin", "s3cret")
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	_, err := Authenticate(context.Background(), srv.Client(), srv.URL+"/", Config{
		Credentials: []Credential{{"admin", "nope"}, {"root", "root"}},
	}, nil)
	if err == nil {
		t.Fatal("expected authentication failure, got success")
	}
}

func TestAuthenticateTriesDefaults(t *testing.T) {
	// admin/password is in the built-in default list.
	app := newFakeApp("admin", "password")
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	sess, err := Authenticate(context.Background(), srv.Client(), srv.URL+"/", Config{TryDefaults: true}, nil)
	if err != nil {
		t.Fatalf("Authenticate with defaults: %v", err)
	}
	if sess.User != "admin" {
		t.Errorf("User = %q, want admin", sess.User)
	}
}

func TestAuthenticateNoCredentialsIsError(t *testing.T) {
	_, err := Authenticate(context.Background(), http.DefaultClient, "http://example.invalid/", Config{}, nil)
	if err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("want no-credentials error, got %v", err)
	}
}

func TestParseLoginFormExtractsFieldsAndAction(t *testing.T) {
	body := []byte(`<html><body>
<form action="/do/login.php" method="POST">
  <input type="text" name="user_name">
  <input type="password" name="pass">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="submit" name="Login" value="Login">
</form></body></html>`)
	f, err := parseLoginForm("http://host.example/auth/login.php", body)
	if err != nil {
		t.Fatal(err)
	}
	if f.method != "POST" {
		t.Errorf("method = %q, want POST", f.method)
	}
	if f.action != "http://host.example/do/login.php" {
		t.Errorf("action = %q, want resolved absolute", f.action)
	}
	if f.userField != "user_name" || f.passField != "pass" {
		t.Errorf("fields user=%q pass=%q", f.userField, f.passField)
	}
	if f.fields["csrf_token"] != "abc123" {
		t.Errorf("csrf token not captured: %v", f.fields)
	}
	if f.fields["Login"] != "Login" {
		t.Errorf("submit button not captured: %v", f.fields)
	}
}

func TestParseLoginFormRejectsNonLoginForm(t *testing.T) {
	body := []byte(`<form action="/search"><input type="text" name="q"></form>`)
	if _, err := parseLoginForm("http://host/", body); err == nil {
		t.Fatal("a form with no password field must not be treated as a login form")
	}
}
