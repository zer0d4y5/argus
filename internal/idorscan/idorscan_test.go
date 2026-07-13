package idorscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// docApp serves objects by id. When enforce is true it checks that the caller
// (identified by the "who" cookie) owns the object; when false it serves any
// id to anyone (the BOLA vulnerability). Objects 1 belong to alice, 2 to bob.
func docApp(enforce bool) http.HandlerFunc {
	owner := map[string]string{"1": "alice", "2": "bob"}
	body := map[string]string{"1": "SSN 111-11-1111 alice private record", "2": "SSN 222-22-2222 bob private record"}
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		who := ""
		if c, err := r.Cookie("who"); err == nil {
			who = c.Value
		}
		if _, ok := body[id]; !ok {
			http.NotFound(w, r)
			return
		}
		if enforce && owner[id] != who {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "forbidden")
			return
		}
		io.WriteString(w, body[id])
	}
}

// clientAs returns a client that sends who=<name> as a cookie on every request.
func clientAs(name string) *http.Client {
	return &http.Client{Transport: cookieRT{name}}
}

type cookieRT struct{ name string }

func (c cookieRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r.AddCookie(&http.Cookie{Name: "who", Value: c.name})
	return http.DefaultTransport.RoundTrip(r)
}

func TestScanDetectsIDOR(t *testing.T) {
	srv := httptest.NewServer(docApp(false)) // no ownership check: vulnerable
	defer srv.Close()

	// Endpoint references alice's object (id=1); bob is the second identity.
	fs := Scan(context.Background(), clientAs("alice"), clientAs("bob"), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/doc?id=1", Method: "GET"}},
	}, nil)

	if len(fs) != 1 {
		t.Fatalf("want 1 IDOR finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].CWEs[0] != "CWE-639" || fs[0].Meta["param"] != "id" {
		t.Errorf("wrong finding: %v / %v", fs[0].CWEs, fs[0].Meta)
	}
	// The cross-read body must never be stored in the proof.
	if fs[0].Proof == nil || strings.Contains(fmt.Sprintf("%+v", fs[0].Proof), "SSN") {
		t.Errorf("proof must redact the cross-read body: %+v", fs[0].Proof)
	}
}

func TestScanNoIDORWhenAccessControlEnforced(t *testing.T) {
	srv := httptest.NewServer(docApp(true)) // ownership enforced: not vulnerable
	defer srv.Close()

	fs := Scan(context.Background(), clientAs("alice"), clientAs("bob"), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/doc?id=1", Method: "GET"}},
	}, nil)
	if len(fs) != 0 {
		t.Errorf("an endpoint that enforces ownership must not be flagged: %+v", fs)
	}
}

func TestScanNoIDOROnPublicIdInvariantPage(t *testing.T) {
	// Serves the SAME content regardless of id: a public page, not IDOR.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "public homepage content, identical for every id value here")
	}))
	defer srv.Close()

	fs := Scan(context.Background(), clientAs("alice"), clientAs("bob"), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/page?id=1", Method: "GET"}},
	}, nil)
	if len(fs) != 0 {
		t.Errorf("an id-invariant public page must not be flagged: %+v", fs)
	}
}
