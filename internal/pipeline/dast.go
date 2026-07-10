package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/dalfoxscan"
	"github.com/zer0d4y5/argus/internal/dastauth"
	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/dastscan"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/sqlmapscan"
)

// DASTOptions configure one dynamic scan.
type DASTOptions struct {
	URL        string
	Templates  []string
	Tags       []string
	Severities []string
	RateLimit  int
	TimeoutSec int
	Fuzzing    bool     // enable nuclei -dast active fuzzing
	Headers    []string // extra request headers (sent to nuclei, never logged)
	Auth       *DASTAuth
	Crawl      bool // discover endpoints (authenticated) and fuzz all of them
	CrawlDepth int  // crawl depth (0 = default)
	CrawlPages int  // crawl page cap (0 = default)
	Evidence   bool // capture redacted request/response on each finding (opt-in)
	Dalfox     bool // also run dalfox (active XSS, GET+POST forms)
	Sqlmap     bool // also run sqlmap (SQL injection incl. blind, GET+POST)
	Config     config.Config
}

// DASTAuth configures pre-scan authentication. When set, RunDAST establishes a
// session before scanning and sends it on every request, so the scan reaches
// pages behind a login. Credential VALUES arrive here already resolved from
// env-var references upstream; they are used in memory and never persisted.
type DASTAuth struct {
	LoginURL    string
	Username    string
	Password    string
	TryDefaults bool // also try the built-in vendor-default list
}

// DASTResult is a completed dynamic scan.
type DASTResult struct {
	Findings    []model.Finding
	ToolVersion string
}

// RunDAST executes a dynamic scan through nuclei and the SAME enrichment half
// as a code or cloud scan (Enrich): unified model -> correlate -> triage seam
// -> risk+band -> compliance. The triage root is "" (a DAST finding has no
// source file; the triager feature-detects that, exactly like cloud).
func RunDAST(ctx context.Context, opts DASTOptions, progress Progress) (DASTResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !dastscan.Available() {
		return DASTResult{}, fmt.Errorf("nuclei not found on PATH: install nuclei to run DAST scans")
	}

	// Authenticate first when configured, and fold the resulting session into
	// the request headers so the scan runs logged in. Auth failure is fatal to
	// the run: silently scanning the login page is worse than a clear error.
	headers := opts.Headers
	var session *dastauth.Session
	if opts.Auth != nil {
		sess, err := authenticate(ctx, opts, progress)
		if err != nil {
			return DASTResult{}, err
		}
		session = sess
		if cookie := sess.CookieHeader(); cookie != "" {
			headers = append(append([]string{}, headers...), "Cookie: "+cookie)
		}
	}

	// When crawling is on, discover the app's fuzzable endpoints (authenticated,
	// reusing the login session) and drive every engine over all of them, so
	// pointing at a base URL finds injection across the whole app.
	var endpoints []dastcrawl.Endpoint
	if opts.Crawl {
		eps, err := crawlEndpoints(ctx, opts, session, headers, progress)
		if err != nil {
			return DASTResult{}, err
		}
		endpoints = eps
		if len(endpoints) == 0 {
			progress("==> crawl found no parameterized endpoints; scanning the base URL only\n")
		}
	}

	// nuclei fuzzes the GET endpoints (it cannot fuzz POST bodies via -l).
	scan, err := dastscan.Scan(ctx, dastscan.Options{
		URL:        opts.URL,
		URLs:       dastcrawl.GETURLs(endpoints),
		Templates:  opts.Templates,
		Tags:       opts.Tags,
		Severities: opts.Severities,
		RateLimit:  opts.RateLimit,
		TimeoutSec: opts.TimeoutSec,
		Fuzzing:    opts.Fuzzing,
		Headers:    headers,
		Evidence:   opts.Evidence,
	}, progress)
	if err != nil {
		return DASTResult{}, err
	}
	raw := scan.Raw

	// dalfox and sqlmap drive both GET and POST endpoints, catching XSS on
	// forms and blind SQL injection that URL fuzzing misses. Their failures are
	// non-fatal: the scan still returns nuclei's findings.
	cookie := cookieFromHeaders(headers)
	targets := scanEndpoints(opts, endpoints)
	if (opts.Dalfox || opts.Sqlmap) && len(endpoints) > len(targets) {
		progress(fmt.Sprintf("NOTE: dalfox/sqlmap limited to the first %d of %d discovered endpoints (--crawl-pages to narrow the crawl)\n", len(targets), len(endpoints)))
	}
	if opts.Dalfox && len(targets) > 0 {
		if fs := runDalfox(ctx, targets, cookie, progress); len(fs) > 0 {
			raw = append(raw, fs...)
		}
	}
	if opts.Sqlmap && len(targets) > 0 {
		if fs := runSqlmap(ctx, targets, cookie, progress); len(fs) > 0 {
			raw = append(raw, fs...)
		}
	}

	findings := Enrich(ctx, opts.Config, "", raw, progress)
	return DASTResult{Findings: findings, ToolVersion: scan.ToolVersion}, nil
}

// maxToolEndpoints bounds how many endpoints the slower form-aware engines
// (sqlmap especially) drive, so a large crawl cannot make a scan run for hours.
const maxToolEndpoints = 40

// scanEndpoints is the endpoint set the form-aware engines drive: the crawl
// results (capped), or the single target URL when no crawl ran.
func scanEndpoints(opts DASTOptions, discovered []dastcrawl.Endpoint) []dastcrawl.Endpoint {
	if len(discovered) == 0 {
		return []dastcrawl.Endpoint{{URL: opts.URL, Method: "GET"}}
	}
	if len(discovered) > maxToolEndpoints {
		return discovered[:maxToolEndpoints]
	}
	return discovered
}

// cookieFromHeaders extracts the session cookie value from the assembled
// headers, for the tools that take a cookie flag rather than a raw header.
func cookieFromHeaders(headers []string) string {
	for _, h := range headers {
		if v, ok := strings.CutPrefix(h, "Cookie: "); ok {
			return v
		}
	}
	return ""
}

func runDalfox(ctx context.Context, eps []dastcrawl.Endpoint, cookie string, progress Progress) []model.RawFinding {
	if !dalfoxscan.Available() {
		progress("NOTE: dalfox not on PATH; skipping XSS engine\n")
		return nil
	}
	progress(fmt.Sprintf("==> running dalfox (XSS) against %d endpoint(s)\n", len(eps)))
	fs, err := dalfoxscan.Scan(ctx, dalfoxscan.Options{Cookie: cookie, Endpoints: eps}, progress)
	if err != nil {
		progress(fmt.Sprintf("WARN: dalfox failed: %v\n", err))
	}
	return fs
}

func runSqlmap(ctx context.Context, eps []dastcrawl.Endpoint, cookie string, progress Progress) []model.RawFinding {
	if !sqlmapscan.Available() {
		progress("NOTE: sqlmap not on PATH; skipping SQLi engine\n")
		return nil
	}
	progress(fmt.Sprintf("==> running sqlmap (SQLi) against %d endpoint(s)\n", len(eps)))
	fs, err := sqlmapscan.Scan(ctx, sqlmapscan.Options{Cookie: cookie, Endpoints: eps}, progress)
	if err != nil {
		progress(fmt.Sprintf("WARN: sqlmap failed: %v\n", err))
	}
	return fs
}

// authenticate runs the pre-scan login and returns the session (cookies held
// in memory, never logged).
func authenticate(ctx context.Context, opts DASTOptions, progress Progress) (*dastauth.Session, error) {
	a := opts.Auth
	cfg := dastauth.Config{LoginURL: a.LoginURL, TryDefaults: a.TryDefaults}
	if a.Username != "" || a.Password != "" {
		cfg.Credentials = []dastauth.Credential{{Username: a.Username, Password: a.Password}}
	}
	client := &http.Client{Timeout: 20 * time.Second}
	progress(fmt.Sprintf("==> authenticating to %s before scan\n", opts.URL))
	sess, err := dastauth.Authenticate(ctx, client, opts.URL, cfg, progress)
	if err != nil {
		return nil, fmt.Errorf("dast auth: %w", err)
	}
	return sess, nil
}

// crawlEndpoints walks the target (reusing the auth session when present) and
// returns the fuzzable endpoints to scan.
func crawlEndpoints(ctx context.Context, opts DASTOptions, session *dastauth.Session, headers []string, progress Progress) ([]dastcrawl.Endpoint, error) {
	progress(fmt.Sprintf("==> crawling %s to discover endpoints\n", opts.URL))
	client := &http.Client{Timeout: 20 * time.Second}
	if session != nil {
		client = session.Client(client)
	}
	eps, err := dastcrawl.Crawl(ctx, client, opts.URL, dastcrawl.Options{
		MaxDepth: opts.CrawlDepth,
		MaxPages: opts.CrawlPages,
		Headers:  headers,
	}, progress)
	if err != nil {
		return nil, fmt.Errorf("dast crawl: %w", err)
	}
	return eps, nil
}
