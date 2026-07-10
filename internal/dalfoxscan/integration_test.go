package dalfoxscan

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// TestIntegrationDalfoxDVWA confirms dalfox finds DVWA's reflected XSS through
// the adapter. Skipped in -short, when dalfox is absent, or when no
// authenticated DVWA is reachable. Set DVWA_COOKIE to a session cookie.
func TestIntegrationDalfoxDVWA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dalfox integration test in -short mode")
	}
	if !Available() {
		t.Skip("dalfox not installed")
	}
	cookie := os.Getenv("DVWA_COOKIE")
	base := os.Getenv("DVWA_URL")
	if base == "" {
		base = "http://localhost/"
	}
	url := strings.TrimRight(base, "/") + "/vulnerabilities/xss_r/?name=1"
	if cookie == "" || !reachable(url, cookie) {
		t.Skip("no authenticated DVWA reachable (set DVWA_COOKIE)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	fs, err := Scan(ctx, Options{
		Cookie:    cookie,
		Endpoints: []dastcrawl.Endpoint{{URL: url, Method: "GET"}},
	}, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("dalfox found no XSS on DVWA xss_r (expected at least one)")
	}
	if fs[0].CWEs[0] != "CWE-79" {
		t.Errorf("cwe = %v, want CWE-79", fs[0].CWEs)
	}
}

func reachable(url, cookie string) bool {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Cookie", cookie)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
