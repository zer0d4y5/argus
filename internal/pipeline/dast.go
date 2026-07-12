package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/cmdiscan"
	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/dalfoxscan"
	"github.com/zer0d4y5/argus/internal/dastauth"
	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/dastscan"
	"github.com/zer0d4y5/argus/internal/engagement"
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
	Cmdi       bool // also run the native command-injection detector (GET+POST)
	Config     config.Config

	// Governor is the engagement enforcement plane. It is REQUIRED: a nil
	// Governor means no active engagement, and RunDAST refuses to send any
	// request ("no engagement, no offense"). Every in-process request runs
	// through its governed HTTP client (scope + intensity + budget + audit per
	// request), and every subprocess engine is scope- and budget-gated at
	// dispatch through it.
	Governor *engagement.Governor
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

// RunDAST executes a dynamic scan through the engine set and the SAME enrichment
// half as a code or cloud scan (Enrich). Every packet is authorized: the target
// and every discovered endpoint pass the engagement scope gate, the intensity
// governor throttles and budgets the traffic, and the tamper-evident audit trail
// records it. Without an engagement (a nil Governor) it refuses outright.
func RunDAST(ctx context.Context, opts DASTOptions, progress Progress) (DASTResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	gov := opts.Governor
	if gov == nil {
		return DASTResult{}, engagement.ErrNoEngagement
	}
	eng := gov.Engagement()

	if !dastscan.Available() {
		return DASTResult{}, fmt.Errorf("nuclei not found on PATH: install nuclei to run DAST scans")
	}

	// Gate the target itself before a single packet leaves. The scope gate is
	// the whole basis for this being an authorized tool, so it is checked first,
	// loudly, and it is fatal.
	if !eng.WindowOpen(time.Now()) {
		gov.Event(engagement.EventRefused, map[string]string{"reason": engagement.ReasonWindowClosed, "url": opts.URL, "phase": "target"})
		return DASTResult{}, fmt.Errorf("refused: engagement %q testing window is closed", eng.Name)
	}
	if !eng.InScope(opts.URL) {
		gov.Event(engagement.EventRefused, map[string]string{"reason": engagement.ReasonOutOfScope, "url": opts.URL, "phase": "target"})
		return DASTResult{}, fmt.Errorf("refused: target %s is outside the engagement %q scope (see `argus engagement show %s`)", opts.URL, eng.Name, eng.ID)
	}
	gov.Event(engagement.EventScanStart, map[string]string{
		"target":           opts.URL,
		"engagement":       eng.ID,
		"authorizationRef": eng.AuthorizationRef,
	})
	progress(fmt.Sprintf("==> engagement %q (%s), authorization %s: target in scope\n", eng.Name, eng.ID, eng.AuthorizationRef))

	// The governed client enforces scope + intensity + budget + audit on EVERY
	// in-process request (auth, crawl, cmdi). Off-scope requests and redirects
	// never reach the network; each permitted request is metered and recorded.
	governed := gov.Client(&http.Client{Timeout: 20 * time.Second})

	// Authenticate first when configured, folding the session into the request
	// headers so the scan runs logged in. Auth failure is fatal: silently
	// scanning the login page is worse than a clear error.
	headers := opts.Headers
	var session *dastauth.Session
	if opts.Auth != nil {
		sess, err := authenticate(ctx, governed, opts, progress)
		if err != nil {
			return DASTResult{}, err
		}
		session = sess
		gov.Event(engagement.EventAuthSuccess, map[string]string{"user": sess.User})
		if cookie := sess.CookieHeader(); cookie != "" {
			headers = append(append([]string{}, headers...), "Cookie: "+cookie)
		}
	}

	// When crawling is on, discover the app's fuzzable endpoints (authenticated,
	// reusing the login session through the governed client) and scope-filter
	// them: a discovered link or synthesized form action can be same-host yet
	// outside an in-scope URL-prefix, and it must be dropped.
	var endpoints []dastcrawl.Endpoint
	if opts.Crawl {
		eps, err := crawlEndpoints(ctx, governed, opts, session, headers, progress)
		if err != nil {
			return DASTResult{}, err
		}
		endpoints = filterEndpointsInScope(eng, eps)
		if dropped := len(eps) - len(endpoints); dropped > 0 {
			progress(fmt.Sprintf("==> dropped %d discovered endpoint(s) outside the engagement scope\n", dropped))
		}
		if len(endpoints) == 0 {
			progress("==> crawl found no in-scope parameterized endpoints; scanning the base URL only\n")
		}
	}

	// nuclei is a subprocess (its HTTP is out of our process), so it is gated at
	// DISPATCH: every URL is scope- and budget-checked here, out-of-scope URLs
	// are dropped and audited, and the engagement rate ceiling is passed to
	// nuclei's own -rate-limit. A base-URL scan (no crawl) uses -target; a
	// crawl feeds nuclei the discovered list.
	listMode := len(endpoints) > 0
	var nucleiURLs []string
	if listMode {
		nucleiURLs = gov.FilterEndpoints("nuclei", dastcrawl.GETURLs(endpoints))
	} else {
		nucleiURLs = gov.FilterEndpoints("nuclei", []string{opts.URL})
	}

	var raw []model.RawFinding
	var toolVersion string
	if len(nucleiURLs) > 0 {
		scanOpts := dastscan.Options{
			URL:        opts.URL,
			Templates:  opts.Templates,
			Tags:       opts.Tags,
			Severities: opts.Severities,
			RateLimit:  cappedRate(gov, opts.RateLimit),
			TimeoutSec: opts.TimeoutSec,
			Fuzzing:    opts.Fuzzing,
			Headers:    headers,
			Evidence:   opts.Evidence,
		}
		if listMode {
			scanOpts.URLs = nucleiURLs
		}
		scan, err := dastscan.Scan(ctx, scanOpts, progress)
		if err != nil {
			return DASTResult{}, err
		}
		raw = scan.Raw
		toolVersion = scan.ToolVersion
	} else {
		progress("==> no in-scope endpoints remain within the engagement budget; skipping nuclei\n")
	}

	// dalfox and sqlmap (subprocesses) drive both GET and POST endpoints; cmdi
	// is in-process. All three run only against in-scope endpoints; the
	// subprocess tools are budget-gated at dispatch, cmdi is metered per request
	// by the governed client it is handed. Their failures are non-fatal.
	cookie := cookieFromHeaders(headers)
	targets := scanEndpoints(opts, endpoints)
	if (opts.Dalfox || opts.Sqlmap) && len(endpoints) > len(targets) {
		progress(fmt.Sprintf("NOTE: dalfox/sqlmap limited to the first %d of %d discovered endpoints (--crawl-pages to narrow the crawl)\n", len(targets), len(endpoints)))
	}
	if opts.Dalfox {
		if eps := gateEndpoints(gov, "dalfox", targets); len(eps) > 0 {
			if fs := runDalfox(ctx, gov, eps, cookie, progress); len(fs) > 0 {
				raw = append(raw, fs...)
			}
		}
	}
	if opts.Sqlmap {
		if eps := gateEndpoints(gov, "sqlmap", targets); len(eps) > 0 {
			if fs := runSqlmap(ctx, eps, cookie, progress); len(fs) > 0 {
				raw = append(raw, fs...)
			}
		}
	}
	if opts.Cmdi && len(targets) > 0 {
		// cmdi's requests go through the governed client, so scope and budget are
		// enforced per request; the endpoint list is already scope-filtered.
		if fs := runCmdi(ctx, governed, targets, headers, progress); len(fs) > 0 {
			raw = append(raw, fs...)
		}
	}

	gov.Event(engagement.EventScanFinish, map[string]string{
		"target":          opts.URL,
		"rawFindings":     fmt.Sprintf("%d", len(raw)),
		"budgetRemaining": fmt.Sprintf("%d", gov.BudgetRemaining()),
	})

	findings := Enrich(ctx, opts.Config, "", raw, progress)
	return DASTResult{Findings: findings, ToolVersion: toolVersion}, nil
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

// filterEndpointsInScope drops endpoints whose URL is outside the engagement
// scope. It spends no budget: it is a pure scope filter applied to synthesized
// endpoints before any tool sends them (the tool dispatch spends the budget).
func filterEndpointsInScope(eng *engagement.Engagement, eps []dastcrawl.Endpoint) []dastcrawl.Endpoint {
	var out []dastcrawl.Endpoint
	for _, e := range eps {
		if eng.InScope(e.URL) {
			out = append(out, e)
		}
	}
	return out
}

// gateEndpoints is the subprocess dispatch gate for the form-aware engines: it
// scope- and budget-checks each endpoint's URL through the governor (auditing
// drops and dispatches) and returns the endpoints cleared to run.
func gateEndpoints(gov *engagement.Governor, tool string, eps []dastcrawl.Endpoint) []dastcrawl.Endpoint {
	urls := make([]string, len(eps))
	for i, e := range eps {
		urls[i] = e.URL
	}
	allowed := map[string]bool{}
	for _, u := range gov.FilterEndpoints(tool, urls) {
		allowed[u] = true
	}
	var out []dastcrawl.Endpoint
	for _, e := range eps {
		if allowed[e.URL] {
			out = append(out, e)
		}
	}
	return out
}

// cappedRate returns the nuclei -rate-limit to use: the engagement intensity
// ceiling, lowered further if the operator asked for something gentler.
func cappedRate(gov *engagement.Governor, operator int) int {
	ceil := gov.ToolRateLimit()
	if operator > 0 && operator < ceil {
		return operator
	}
	return ceil
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

func runDalfox(ctx context.Context, gov *engagement.Governor, eps []dastcrawl.Endpoint, cookie string, progress Progress) []model.RawFinding {
	if !dalfoxscan.Available() {
		progress("NOTE: dalfox not on PATH; skipping XSS engine\n")
		return nil
	}
	progress(fmt.Sprintf("==> running dalfox (XSS) against %d endpoint(s)\n", len(eps)))
	fs, err := dalfoxscan.Scan(ctx, dalfoxscan.Options{
		Cookie:    cookie,
		Endpoints: eps,
		Workers:   gov.ToolConcurrency(), // hold dalfox to the engagement concurrency ceiling
	}, progress)
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

func runCmdi(ctx context.Context, client *http.Client, eps []dastcrawl.Endpoint, headers []string, progress Progress) []model.RawFinding {
	progress(fmt.Sprintf("==> testing %d endpoint(s) for command injection\n", len(eps)))
	fs, err := cmdiscan.Scan(ctx, client, cmdiscan.Options{Endpoints: eps, Headers: headers, Timing: true}, progress)
	if err != nil {
		progress(fmt.Sprintf("WARN: command-injection scan failed: %v\n", err))
	}
	return fs
}

// authenticate runs the pre-scan login through the governed client (so every
// login request is scope-gated and audited) and returns the session (cookies
// held in memory, never logged).
func authenticate(ctx context.Context, client *http.Client, opts DASTOptions, progress Progress) (*dastauth.Session, error) {
	a := opts.Auth
	cfg := dastauth.Config{LoginURL: a.LoginURL, TryDefaults: a.TryDefaults}
	if a.Username != "" || a.Password != "" {
		cfg.Credentials = []dastauth.Credential{{Username: a.Username, Password: a.Password}}
	}
	progress(fmt.Sprintf("==> authenticating to %s before scan\n", opts.URL))
	sess, err := dastauth.Authenticate(ctx, client, opts.URL, cfg, progress)
	if err != nil {
		return nil, fmt.Errorf("dast auth: %w", err)
	}
	return sess, nil
}

// crawlEndpoints walks the target through the governed client (reusing the auth
// session when present) and returns the fuzzable endpoints to scan.
func crawlEndpoints(ctx context.Context, governed *http.Client, opts DASTOptions, session *dastauth.Session, headers []string, progress Progress) ([]dastcrawl.Endpoint, error) {
	progress(fmt.Sprintf("==> crawling %s to discover endpoints\n", opts.URL))
	client := governed
	if session != nil {
		client = session.Client(governed) // preserves the governed transport, adds the session jar
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
