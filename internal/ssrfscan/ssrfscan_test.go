package ssrfscan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// vulnApp fetches whatever URL its "url" parameter names (classic SSRF) and,
// when reflect is true, echoes the fetched body into its response.
func vulnApp(reflect bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		target := r.Form.Get("url")
		if target == "" {
			io.WriteString(w, "ok")
			return
		}
		resp, err := http.Get(target) // the vulnerable server-side fetch
		if err != nil {
			io.WriteString(w, "fetch failed")
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if reflect {
			w.Write(body)
			return
		}
		io.WriteString(w, "done")
	}
}

func TestScanDetectsBlindSSRF(t *testing.T) {
	l, err := NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	srv := httptest.NewServer(vulnApp(false)) // fetches but does not reflect
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/?url=x", Method: "GET"}}, CallbackWait: 200e6,
	}, nil)

	if len(fs) != 1 {
		t.Fatalf("want 1 blind SSRF finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].CWEs[0] != "CWE-918" || !strings.Contains(fs[0].RuleID, "ssrf-oob") {
		t.Errorf("wrong finding: %v / %s", fs[0].CWEs, fs[0].RuleID)
	}
	if fs[0].Proof == nil || !strings.Contains(fs[0].Proof.Observed, "connected back") {
		t.Errorf("proof should describe the callback: %+v", fs[0].Proof)
	}
}

func TestScanDetectsReflectedSSRF(t *testing.T) {
	l, err := NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	srv := httptest.NewServer(vulnApp(true)) // reflects the fetched body
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/?url=x", Method: "GET"}}, CallbackWait: 200e6,
	}, nil)

	var reflected bool
	for _, f := range fs {
		if strings.Contains(f.RuleID, "ssrf-reflected") {
			reflected = true
			if f.Proof == nil || f.Proof.Response == "" {
				t.Error("reflected SSRF proof should carry the response")
			}
		}
	}
	if !reflected {
		t.Fatalf("expected a reflected SSRF finding, got %+v", fs)
	}
}

const fakeMetadataIndex = "ami-id\nami-launch-index\ninstance-id\ninstance-type\niam/\nlocal-ipv4\nreservation-id\nsecurity-groups/\n"

func TestScanDetectsCloudMetadataSSRF(t *testing.T) {
	l, err := NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// A fake metadata service, and a vulnerable app that fetches the url param
	// and reflects it. Point the engine's metadata URL at the fake for the test.
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, fakeMetadataIndex)
	}))
	defer meta.Close()
	old := cloudMetadataURL
	cloudMetadataURL = meta.URL + "/latest/meta-data/"
	defer func() { cloudMetadataURL = old }()

	srv := httptest.NewServer(vulnApp(true))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints:     []dastcrawl.Endpoint{{URL: srv.URL + "/?url=x", Method: "GET"}},
		CloudMetadata: true,
		CallbackWait:  200e6,
	}, nil)
	var found bool
	for _, f := range fs {
		if strings.Contains(f.RuleID, "cloud-metadata") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a cloud-metadata SSRF finding, got %+v", fs)
	}
}

// A page that ignores the url parameter and merely contains metadata-shaped
// words must not be flagged: the signal is not induced by the injection.
func TestScanNoCloudMetadataFalsePositive(t *testing.T) {
	l, err := NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "cloud dashboard: instance-id i-1, instance-type t3, ami-id ami-9, local-ipv4 10.0.0.1, reservation-id r-2")
	}))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints:     []dastcrawl.Endpoint{{URL: srv.URL + "/?url=x", Method: "GET"}},
		CloudMetadata: true,
		CallbackWait:  200e6,
	}, nil)
	for _, f := range fs {
		if strings.Contains(f.RuleID, "cloud-metadata") {
			t.Errorf("a param-ignoring page with metadata words must not be flagged: %+v", f)
		}
	}
}

func TestScanNoFalsePositiveWhenNoFetch(t *testing.T) {
	l, err := NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// A safe app that never fetches the parameter.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		io.WriteString(w, "you said: "+r.Form.Get("url")) // reflects input, never fetches
	}))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/?url=x", Method: "GET"}}, CallbackWait: 200e6,
	}, nil)
	if len(fs) != 0 {
		t.Errorf("a reflecting-but-not-fetching app must not be flagged: %+v", fs)
	}
}
