package cmdiscan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// exprRe matches the injected `expr A \* B` so a fake vulnerable app can
// "execute" it and echo the product, exactly like a real shell would.
var exprRe = regexp.MustCompile(`expr (\d+) \\?\* (\d+)`)

// vulnApp simulates a command-injectable endpoint: the "cmd" parameter is
// concatenated into a shell, so an injected `expr A \* B` runs and its product
// appears in the response. Other parameters are safe (echoed as literal input).
func vulnApp(vulnerable bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		val := r.Form.Get("cmd")
		out := "input: " + val // safe reflection of the raw input
		if vulnerable {
			if m := exprRe.FindStringSubmatch(val); m != nil {
				a, _ := strconv.Atoi(m[1])
				b, _ := strconv.Atoi(m[2])
				out += "\nresult: " + fmt.Sprintf("%d", a*b) // command "executed"
			}
		}
		w.Write([]byte(out))
	})
}

func TestScanDetectsCommandInjectionGET(t *testing.T) {
	srv := httptest.NewServer(vulnApp(true))
	defer srv.Close()

	fs, err := Scan(context.Background(), srv.Client(), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/?cmd=127.0.0.1&safe=x", Method: "GET"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 cmdi finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Meta["param"] != "cmd" || f.CWEs[0] != "CWE-78" {
		t.Errorf("wrong finding: %v / %v", f.Meta, f.CWEs)
	}
	if f.Meta["technique"] != "arithmetic" {
		t.Errorf("technique = %q, want arithmetic", f.Meta["technique"])
	}
	if f.Proof == nil {
		t.Fatal("cmdi finding must carry a reproduction proof")
	}
	if !strings.Contains(f.Proof.Curl, "cmd=") || !strings.Contains(f.Proof.Curl, "curl") {
		t.Errorf("proof curl should reproduce the injected request: %q", f.Proof.Curl)
	}
	if !strings.Contains(f.Proof.Rationale, "cmd parameter") {
		t.Errorf("proof rationale should name the parameter: %q", f.Proof.Rationale)
	}
	if f.Proof.Observed == "" {
		t.Error("proof should record what was observed")
	}
}

func TestScanDetectsCommandInjectionPOST(t *testing.T) {
	srv := httptest.NewServer(vulnApp(true))
	defer srv.Close()

	fs, err := Scan(context.Background(), srv.Client(), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/exec", Method: "POST", Body: "cmd=127.0.0.1&Submit=Submit"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Meta["method"] != "POST" {
		t.Fatalf("POST cmdi not detected: %+v", fs)
	}
}

// A safe app that only reflects input must NOT be flagged: the product of the
// injected expression never appears because nothing is executed. This is the
// false-positive guard the arithmetic technique buys.
func TestScanNoFalsePositiveOnReflection(t *testing.T) {
	srv := httptest.NewServer(vulnApp(false)) // reflects input, never executes
	defer srv.Close()

	fs, err := Scan(context.Background(), srv.Client(), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/?cmd=1", Method: "GET"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("false positive on an input-reflecting app: %+v", fs)
	}
}

func TestScanSendsAuthHeaders(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	_, _ = Scan(context.Background(), srv.Client(), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/?cmd=1", Method: "GET"}},
		Headers:   []string{"Cookie: SESS=abc"},
	}, nil)
	if !strings.Contains(gotCookie, "SESS=abc") {
		t.Errorf("auth cookie not sent: %q", gotCookie)
	}
}
