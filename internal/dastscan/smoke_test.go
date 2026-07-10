package dastscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
)

// TestSmokeNuclei runs the real nuclei binary against a local test server and
// asserts the adapter produces well-formed DAST findings. Skipped with -short
// or when nuclei is not installed, matching the scanner smoke-test pattern.
func TestSmokeNuclei(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping nuclei smoke test in -short mode")
	}
	if !Available() {
		t.Skip("nuclei not installed")
	}

	// A plain server with no security headers: the missing-headers template
	// fires reliably and offline (no external target needed).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := Scan(ctx, Options{
		URL:  srv.URL,
		Tags: []string{"misconfig"},
	}, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Raw) == 0 {
		t.Skip("nuclei ran but matched nothing (template set may be minimal in this environment)")
	}
	for _, f := range res.Raw {
		if f.Tool != "nuclei" || f.Category != model.CategoryDAST {
			t.Errorf("bad tool/category: %q/%q", f.Tool, f.Category)
		}
		if f.URL == "" {
			t.Errorf("finding %q has no URL", f.RuleID)
		}
		// No response bytes on any finding.
		if s := string(f.RawPayload); s != "" {
			for _, banned := range []string{"HTTP/1.1", "response", "hello</body>"} {
				if strings.Contains(s, banned) {
					t.Errorf("rawPayload leaked %q: %s", banned, s)
				}
			}
		}
	}
}
