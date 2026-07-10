package sqlmapscan

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// TestIntegrationSqlmapDVWA confirms sqlmap finds DVWA's SQL injection through
// the adapter. Skipped in -short, when sqlmap is absent, or when no DVWA is
// reachable/authenticated. Set DVWA_COOKIE to an authenticated session cookie.
func TestIntegrationSqlmapDVWA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sqlmap integration test in -short mode")
	}
	if !Available() {
		t.Skip("sqlmap not installed")
	}
	cookie := os.Getenv("DVWA_COOKIE")
	base := os.Getenv("DVWA_URL")
	if base == "" {
		base = "http://localhost/"
	}
	url := strings.TrimRight(base, "/") + "/vulnerabilities/sqli/?id=1&Submit=Submit"
	if cookie == "" || !reachable(url, cookie) {
		t.Skip("no authenticated DVWA reachable (set DVWA_COOKIE)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fs, err := Scan(ctx, Options{
		Cookie:    cookie,
		Endpoints: []dastcrawl.Endpoint{{URL: url, Method: "GET"}},
	}, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("sqlmap found no injection on DVWA sqli (expected at least one)")
	}
	if fs[0].CWEs[0] != "CWE-89" {
		t.Errorf("cwe = %v, want CWE-89", fs[0].CWEs)
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
