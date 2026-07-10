package dastcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A small app: an index linking to a GET-form page (like DVWA's sqli), a
// parameterized link (like fi/?page=), a logout link (must NOT be crawled),
// and an off-site link (must be ignored).
func fakeApp() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/sqli/">SQLi</a>
			<a href="/fi/?page=include.php">File include</a>
			<a href="/logout.php">Logout</a>
			<a href="https://evil.example/">offsite</a>
		</body></html>`)
	})
	mux.HandleFunc("/sqli/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/sqli/" method="GET">
			<input type="text" name="id">
			<input type="submit" name="Submit" value="Submit">
		</form></body></html>`)
	})
	mux.HandleFunc("/fi/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>included</body></html>`)
	})
	mux.HandleFunc("/logout.php", func(w http.ResponseWriter, _ *http.Request) {
		// If the crawler ever hits this, the test asserts it did not.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>logged out</body></html>`)
	})
	return mux
}

// flatten joins endpoints (method, url, body) for substring assertions.
func flatten(eps []Endpoint) string {
	var b strings.Builder
	for _, e := range eps {
		b.WriteString(e.Method + " " + e.URL + " " + e.Body + "\n")
	}
	return b.String()
}

func TestCrawlDiscoversParamsAndForms(t *testing.T) {
	srv := httptest.NewServer(fakeApp())
	defer srv.Close()

	eps, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := flatten(eps)

	// The GET form is synthesized into a fuzzable URL with its fields.
	if !strings.Contains(joined, "/sqli/?") || !strings.Contains(joined, "id=1") || !strings.Contains(joined, "Submit=Submit") {
		t.Errorf("sqli form not synthesized into a fuzzable URL:\n%s", joined)
	}
	// The parameterized link is captured.
	if !strings.Contains(joined, "/fi/?page=include.php") {
		t.Errorf("parameterized link not discovered:\n%s", joined)
	}
}

func TestCrawlNeverFollowsLogoutOrOffsite(t *testing.T) {
	var logoutHit bool
	mux := http.NewServeMux()
	base := fakeApp()
	mux.HandleFunc("/logout.php", func(w http.ResponseWriter, _ *http.Request) { logoutHit = true })
	mux.Handle("/", base)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	eps, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if logoutHit {
		t.Error("crawler fetched the logout page (would destroy the session)")
	}
	for _, e := range eps {
		if strings.Contains(e.URL, "evil.example") {
			t.Errorf("off-site URL leaked into results: %s", e.URL)
		}
		if strings.Contains(e.URL, "logout") {
			t.Errorf("logout URL in results: %s", e.URL)
		}
	}
}

// A POST form must be captured as a POST endpoint with a form-encoded body, so
// the form-aware engines (dalfox/sqlmap) can drive it.
func TestCrawlCapturesPostForms(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/guestbook/">gb</a>`)
	})
	mux.HandleFunc("/guestbook/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<form action="/guestbook/" method="POST">
			<input name="name"><textarea name="message"></textarea>
			<input type="submit" name="sign" value="Sign"></form>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	eps, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var post *Endpoint
	for i := range eps {
		if eps[i].Method == "POST" {
			post = &eps[i]
		}
	}
	if post == nil {
		t.Fatalf("no POST endpoint captured: %v", eps)
	}
	if !strings.Contains(post.Body, "name=1") || !strings.Contains(post.Body, "message=1") {
		t.Errorf("POST body missing seeded fields: %q", post.Body)
	}
	if !strings.Contains(post.URL, "/guestbook/") || strings.Contains(post.URL, "?") {
		t.Errorf("POST endpoint URL should be the bare action: %q", post.URL)
	}
}

func TestCrawlBoundsPages(t *testing.T) {
	// A page that links to a fresh page forever; the page cap must stop it.
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="%s/p%d">next</a>`, "", count)
	}))
	defer srv.Close()

	if _, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{MaxPages: 5}, nil); err != nil {
		t.Fatal(err)
	}
	if count > 6 { // 5 pages plus a little slack for in-flight
		t.Errorf("page cap not honored: fetched %d pages", count)
	}
}

// A password-change form must not be synthesized into a fuzzable URL: fuzzing
// it would change the session's own credentials and lock the scan out.
func TestCrawlSkipsCredentialChangeForms(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/csrf/">csrf</a></body></html>`)
	})
	mux.HandleFunc("/csrf/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<form action="/csrf/" method="GET">
			<input name="password_new"><input name="password_conf">
			<input type="submit" name="Change" value="Change"></form>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	eps, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(flatten(eps), "password_new") {
		t.Errorf("credential-change form was driven (self-lockout risk): %v", eps)
	}
}

func TestIsAssetAndAuthPath(t *testing.T) {
	for _, p := range []string{"/x.css", "/a/b.js", "/img.PNG"} {
		if !isAsset(p) {
			t.Errorf("%s should be an asset", p)
		}
	}
	for _, p := range []string{"/logout.php", "/user/login", "/setup.php"} {
		if !isAuthPath(p) {
			t.Errorf("%s should be an auth path", p)
		}
	}
	if isAuthPath("/vulnerabilities/sqli/") {
		t.Error("a normal page misclassified as an auth path")
	}
}
