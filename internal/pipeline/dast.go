package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/apirecon"
	"github.com/zer0d4y5/argus/internal/apiscan"
	"github.com/zer0d4y5/argus/internal/cmdiscan"
	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/confirm"
	"github.com/zer0d4y5/argus/internal/dalfoxscan"
	"github.com/zer0d4y5/argus/internal/dastauth"
	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/dastscan"
	"github.com/zer0d4y5/argus/internal/engagement"
	"github.com/zer0d4y5/argus/internal/exploit"
	"github.com/zer0d4y5/argus/internal/fingerprint"
	"github.com/zer0d4y5/argus/internal/idorscan"
	"github.com/zer0d4y5/argus/internal/jsrecon"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/poc"
	"github.com/zer0d4y5/argus/internal/sqlmapscan"
	"github.com/zer0d4y5/argus/internal/ssrfscan"
	"github.com/zer0d4y5/argus/internal/sstiscan"
	"github.com/zer0d4y5/argus/internal/uploadscan"
)

// DASTOptions configure one dynamic scan.
type DASTOptions struct {
	URL         string
	Templates   []string
	Tags        []string
	Severities  []string
	RateLimit   int
	TimeoutSec  int
	Fuzzing     bool     // enable nuclei -dast active fuzzing
	Headers     []string // extra request headers (sent to nuclei, never logged)
	Auth        *DASTAuth
	Crawl       bool // discover endpoints (authenticated) and fuzz all of them
	CrawlDepth  int  // crawl depth (0 = default)
	CrawlPages  int  // crawl page cap (0 = default)
	Evidence    bool // capture redacted request/response on each finding (opt-in)
	Dalfox      bool // also run dalfox (active XSS, GET+POST forms)
	Sqlmap      bool // also run sqlmap (SQL injection incl. blind, GET+POST)
	Cmdi        bool // also run the native command-injection detector (GET+POST)
	SSRF        bool // also run the native SSRF detector (local out-of-band listener + cloud-metadata reachability)
	SSTI        bool // also run the native server-side template injection detector (GET+POST)
	FileUpload  bool // also test discovered upload forms for unrestricted file upload (fetch-back a benign marker)
	IDOR        bool // also test for IDOR/BOLA by replaying identity A's object ids as a second identity
	GraphQL     bool // also test discovered GraphQL endpoints for batching and alias amplification
	Auth2       *DASTAuth // second identity for IDOR: its session replays identity A's object references
	Recon       bool // reverse-engineer the target's client-side JS for endpoints and exposed secrets
	Fingerprint bool // identify the target's technology stack and correlate to known-exploited software
	APIRecon    bool // reconstruct the API surface from served schemas (OpenAPI/Swagger/GraphQL) and fuzz it
	Config      config.Config

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
	var authFlowFindings []model.RawFinding
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
		// Auth-flow modeling: what login observed about the session cookies drives
		// deterministic hardening findings (missing HttpOnly/Secure/SameSite).
		authFlowFindings = authModelFindings(sess.Model, opts.URL, progress)
	}

	// IDOR/BOLA needs a second authenticated identity to replay the first
	// identity's object references. Authenticate it on its own governed client
	// (a separate session jar), so its requests are also scope-gated, budgeted,
	// and audited. A second-identity auth failure disables IDOR but never fails
	// the whole scan.
	var sessionB *dastauth.Session
	var governedB *http.Client
	if opts.IDOR && opts.Auth2 != nil {
		governedB = gov.Client(&http.Client{Timeout: 20 * time.Second})
		if sb, err := authenticateWith(ctx, governedB, opts.Auth2, opts.URL, progress); err != nil {
			progress(fmt.Sprintf("WARN: idor: second identity did not authenticate (%v); skipping IDOR\n", err))
		} else {
			sessionB = sb
			gov.Event(engagement.EventAuthSuccess, map[string]string{"user": sb.User, "identity": "second"})
		}
	}

	// When crawling is on, discover the app's fuzzable endpoints (authenticated,
	// reusing the login session through the governed client) and scope-filter
	// them: a discovered link or synthesized form action can be same-host yet
	// outside an in-scope URL-prefix, and it must be dropped.
	var endpoints []dastcrawl.Endpoint
	var uploadForms []dastcrawl.UploadForm
	if opts.Crawl {
		eps, uploads, err := crawlEndpoints(ctx, governed, opts, session, headers, progress)
		if err != nil {
			return DASTResult{}, err
		}
		uploadForms = filterUploadsInScope(eng, uploads)
		endpoints = filterEndpointsInScope(eng, eps)
		if dropped := len(eps) - len(endpoints); dropped > 0 {
			progress(fmt.Sprintf("==> dropped %d discovered endpoint(s) outside the engagement scope\n", dropped))
		}
		if len(endpoints) == 0 {
			progress("==> crawl found no in-scope parameterized endpoints; scanning the base URL only\n")
		}
	}

	// Client-side reverse-engineering: recover endpoints the crawler's
	// link-following never sees (fetch/XHR routes, minified references, sourcemap
	// originals) and report secrets exposed in served JavaScript. Recovered
	// endpoints are scope-filtered and merged into the fuzz set; findings are
	// appended before enrichment. Recon fetches through the governed client, so
	// it is scope-gated, budgeted, and audited like every other active step.
	var reconFindings []model.RawFinding
	if opts.Recon {
		reconEps, rf := runJSRecon(ctx, authedClient(governed, session), opts, eng, progress)
		reconFindings = rf
		if merged := mergeEndpoints(endpoints, reconEps); len(merged) > len(endpoints) {
			progress(fmt.Sprintf("==> jsrecon added %d endpoint(s) to the fuzz set\n", len(merged)-len(endpoints)))
			endpoints = merged
		}
	}

	// API schema reconstruction: recover the API surface from served OpenAPI/
	// Swagger/GraphQL schemas, merge the fuzzable operations into the scan, and
	// report the exposure. Fetches through the governed client.
	var apiFindings []model.RawFinding
	if opts.APIRecon {
		apiEps, af := runAPIRecon(ctx, authedClient(governed, session), opts, eng, progress)
		apiFindings = af
		if merged := mergeEndpoints(endpoints, apiEps); len(merged) > len(endpoints) {
			progress(fmt.Sprintf("==> apirecon added %d operation(s) to the fuzz set\n", len(merged)-len(endpoints)))
			endpoints = merged
		}
	}

	// Stack fingerprinting: identify the target's technologies and versions from
	// what it discloses, emit version-disclosure findings, and correlate CMS
	// families against the known-exploited catalog. One governed GET.
	var fingerprintFindings []model.RawFinding
	if opts.Fingerprint {
		fingerprintFindings = runFingerprint(ctx, authedClient(governed, session), opts, progress)
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
	if opts.SSRF && len(targets) > 0 {
		// ssrf probes go to the target through the governed client (scope +
		// budget + audit per request); the callback is to Argus's own local
		// listener, never a third-party out-of-band service.
		if fs := runSSRF(ctx, governed, targets, headers, progress); len(fs) > 0 {
			raw = append(raw, fs...)
		}
	}
	if opts.SSTI && len(targets) > 0 {
		if fs := runSSTI(ctx, governed, targets, headers, progress); len(fs) > 0 {
			raw = append(raw, fs...)
		}
	}
	if opts.FileUpload && len(uploadForms) > 0 {
		if fs := runFileUpload(ctx, governed, opts.URL, uploadForms, headers, progress); len(fs) > 0 {
			raw = append(raw, fs...)
		}
	}
	if opts.IDOR && sessionB != nil && len(targets) > 0 {
		if fs := runIDOR(ctx, authedClient(governed, session), authedClient(governedB, sessionB), targets, progress); len(fs) > 0 {
			raw = append(raw, fs...)
		}
	}
	if opts.GraphQL {
		// Consider the discovered endpoints plus the target itself when it looks
		// like a GraphQL endpoint (the operator may point straight at /graphql
		// without crawling).
		cands := endpoints
		if strings.Contains(strings.ToLower(opts.URL), "graphql") {
			cands = append([]dastcrawl.Endpoint{{URL: opts.URL, Method: http.MethodPost, Body: `{"query":"{__typename}"}`}}, endpoints...)
		}
		if len(cands) > 0 {
			if fs := runGraphQL(ctx, governed, cands, headers, progress); len(fs) > 0 {
				raw = append(raw, fs...)
			}
		}
	}

	raw = append(raw, authFlowFindings...)
	raw = append(raw, reconFindings...)
	raw = append(raw, apiFindings...)
	raw = append(raw, fingerprintFindings...)

	// Build the reproduction proof-of-concept for the confirmed dynamic findings
	// that do not already carry one (the subprocess engines sqlmap and dalfox;
	// cmdi builds its own from the exact request it sent). This renders what the
	// engines observed into a request, a curl, and a plain-English reason. It
	// sends no traffic.
	bodies := pocBodies(endpoints)
	poc.AttachToRaw(raw, bodies, cookie != "")

	// Bounded impact confirmation: only when the operator armed the confirmation
	// interlock. It sends the minimum identifying probe (a DB banner + current
	// user for SQLi, one benign `id` for command injection) against confirmed
	// findings, gated and audited through the governor, and attaches the result.
	// A no-op when the interlock is not armed.
	confirm.Run(ctx, gov, raw, confirm.Inputs{
		Client:  governed,
		Cookie:  cookie,
		Headers: headers,
		Bodies:  bodies,
	}, progress)

	gov.Event(engagement.EventScanFinish, map[string]string{
		"target":          opts.URL,
		"rawFindings":     fmt.Sprintf("%d", len(raw)),
		"budgetRemaining": fmt.Sprintf("%d", gov.BudgetRemaining()),
	})

	findings := Enrich(ctx, opts.Config, "", raw, progress)
	return DASTResult{Findings: findings, ToolVersion: toolVersion}, nil
}

// pocBodies indexes discovered endpoints' request bodies by method+URL so the
// reproduction builder can render a faithful POST curl for a finding whose
// engine did not carry the body on the finding itself.
func pocBodies(eps []dastcrawl.Endpoint) map[string]string {
	conv := make([]poc.Endpoint, 0, len(eps))
	for _, ep := range eps {
		conv = append(conv, poc.Endpoint{Method: ep.Method, URL: ep.URL, Body: ep.Body})
	}
	return poc.BodiesFromEndpoints(conv)
}

// ConfirmTarget identifies a single confirmed finding to run bounded impact
// confirmation against. Class is "sqli" or "cmdi".
type ConfirmTarget struct {
	URL    string
	Method string
	Body   string
	Param  string
	Class  string
}

// ConfirmOptions configure a single-finding bounded confirmation (the console
// path). Auth, when set, re-establishes a session before probing, since the
// original scan's session was never persisted.
type ConfirmOptions struct {
	Governor *engagement.Governor
	Auth     *DASTAuth
	LoginURL string // where to authenticate (the target base); defaults to the finding URL
	Headers  []string
	Config   config.Config
	Target   ConfirmTarget
}

// ConfirmImpact runs bounded impact confirmation for one confirmed finding,
// re-authenticating first when configured, and returns the ImpactProof (nil if
// the probe did not confirm). It refuses unless the confirmation interlock is
// armed and the finding URL is in scope and within the testing window. Every
// probe is scope-gated, budgeted, and audited through the governor.
func ConfirmImpact(ctx context.Context, opts ConfirmOptions, progress Progress) (*model.ImpactProof, error) {
	if progress == nil {
		progress = func(string) {}
	}
	gov := opts.Governor
	if gov == nil {
		return nil, engagement.ErrNoEngagement
	}
	if !gov.ConfirmationArmed() {
		return nil, fmt.Errorf("refused: the engagement's confirmation interlock is not armed (needs --allow-confirmation and an explicit confirmation)")
	}
	eng := gov.Engagement()
	if !eng.WindowOpen(time.Now()) {
		return nil, fmt.Errorf("refused: engagement %q testing window is closed", eng.Name)
	}
	url := opts.Target.URL
	if !eng.InScope(url) {
		gov.Event(engagement.EventRefused, map[string]string{"reason": engagement.ReasonOutOfScope, "url": url, "phase": "confirm"})
		return nil, fmt.Errorf("refused: %s is outside the engagement %q scope", url, eng.Name)
	}
	cwe := map[string]string{"sqli": "CWE-89", "cmdi": "CWE-78"}[opts.Target.Class]
	if cwe == "" {
		return nil, fmt.Errorf("unsupported confirmation class %q", opts.Target.Class)
	}

	governed := gov.Client(&http.Client{Timeout: 20 * time.Second})
	headers := opts.Headers
	var cookie string
	if opts.Auth != nil {
		loginURL := opts.LoginURL
		if loginURL == "" {
			loginURL = url
		}
		sess, err := authenticate(ctx, governed, DASTOptions{Auth: opts.Auth, URL: loginURL}, progress)
		if err != nil {
			return nil, err
		}
		gov.Event(engagement.EventAuthSuccess, map[string]string{"user": sess.User})
		if c := sess.CookieHeader(); c != "" {
			cookie = c
			headers = append(append([]string{}, headers...), "Cookie: "+c)
		}
	}

	raw := []model.RawFinding{{
		Category: model.CategoryDAST,
		URL:      url,
		CWEs:     []string{cwe},
		Meta:     map[string]string{"param": opts.Target.Param, "method": opts.Target.Method, "body": opts.Target.Body},
	}}
	confirm.Run(ctx, gov, raw, confirm.Inputs{Client: governed, Cookie: cookie, Headers: headers}, progress)
	if raw[0].Proof != nil {
		return raw[0].Proof.Impact, nil
	}
	return nil, nil
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

// runJSRecon reverse-engineers the target's client-side JavaScript and returns
// the scope-filtered endpoints it recovered plus any findings (exposed secrets,
// sensitive surfaces). Recon failure is non-fatal: the scan still proceeds.
func runJSRecon(ctx context.Context, client *http.Client, opts DASTOptions, eng *engagement.Engagement, progress Progress) ([]dastcrawl.Endpoint, []model.RawFinding) {
	progress("==> reverse-engineering client-side JavaScript for endpoints and secrets\n")
	res, err := jsrecon.Analyze(ctx, client, opts.URL, jsrecon.Options{Headers: opts.Headers}, progress)
	if err != nil {
		progress(fmt.Sprintf("WARN: jsrecon failed: %v\n", err))
		return nil, nil
	}
	return filterEndpointsInScope(eng, res.Endpoints), res.Findings
}

// runAPIRecon reconstructs the API surface from the target's served schema
// documents (OpenAPI/Swagger/GraphQL), returning scope-filtered fuzzable
// operations to merge into the scan and the exposure findings. Non-fatal on
// failure.
func runAPIRecon(ctx context.Context, client *http.Client, opts DASTOptions, eng *engagement.Engagement, progress Progress) ([]dastcrawl.Endpoint, []model.RawFinding) {
	progress("==> reconstructing the API surface from served schemas\n")
	res, err := apirecon.Analyze(ctx, client, opts.URL, apirecon.Options{}, progress)
	if err != nil {
		progress(fmt.Sprintf("WARN: apirecon failed: %v\n", err))
		return nil, nil
	}
	return filterEndpointsInScope(eng, res.Operations), res.Findings
}

// authModelFindings turns what authentication observed about the session
// cookies into deterministic hardening findings: a session cookie without
// HttpOnly, without Secure (over HTTPS), or without SameSite. It reports on the
// cookie's name and flags only, never its value.
func authModelFindings(m dastauth.AuthModel, targetURL string, progress Progress) []model.RawFinding {
	https := strings.HasPrefix(strings.ToLower(strings.TrimSpace(targetURL)), "https://")
	var out []model.RawFinding
	for _, c := range m.SetCookies {
		if !isSessionCookie(c.Name) {
			continue
		}
		if !c.HTTPOnly {
			out = append(out, cookieFinding(targetURL, c.Name, "httponly", "CWE-1004", "medium",
				"The session cookie %q is set without the HttpOnly flag, so page JavaScript can read it. Paired with any cross-site-scripting flaw, that hands an attacker the session."))
		}
		if https && !c.Secure {
			out = append(out, cookieFinding(targetURL, c.Name, "secure", "CWE-614", "medium",
				"The session cookie %q is served over HTTPS without the Secure flag, so a downgrade or mixed-content request can carry it in cleartext."))
		}
		if c.SameSite == "" {
			out = append(out, cookieFinding(targetURL, c.Name, "samesite", "CWE-1275", "low",
				"The session cookie %q has no SameSite attribute, so the browser sends it on cross-site requests, widening the target's CSRF exposure."))
		}
	}
	if len(out) > 0 {
		progress(fmt.Sprintf("==> auth-flow modeling: %d session-cookie hardening finding(s)\n", len(out)))
	}
	return out
}

// isSessionCookie is a name heuristic for the cookies worth hardening findings.
func isSessionCookie(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "sess") || strings.Contains(l, "sid") || strings.Contains(l, "auth")
}

func cookieFinding(targetURL, cookie, flag, cwe, sev, descFmt string) model.RawFinding {
	return model.RawFinding{
		Tool:        "argus-authmodel",
		Category:    model.CategoryDAST,
		RuleID:      "session-cookie-" + flag + ":" + cookie,
		Title:       "Session Cookie Missing " + cookieFlagLabel(flag),
		Description: fmt.Sprintf(descFmt, cookie),
		RawSeverity: sev,
		URL:         targetURL,
		CWEs:        []string{cwe},
		Meta:        map[string]string{"cookie": cookie, "flag": cookieFlagLabel(flag)},
	}
}

func cookieFlagLabel(flag string) string {
	switch flag {
	case "httponly":
		return "HttpOnly"
	case "secure":
		return "Secure"
	case "samesite":
		return "SameSite"
	}
	return flag
}

// authedClient returns the governed client wrapped with the auth session when
// one exists (preserving the governed transport), so the recon steps fetch as
// the logged-in user while staying scope-gated, budgeted, and audited.
func authedClient(governed *http.Client, session *dastauth.Session) *http.Client {
	if session != nil {
		return session.Client(governed)
	}
	return governed
}

// runFingerprint identifies the target's technology stack and returns its
// findings (version disclosure + KEV-family correlation). Non-fatal on failure.
func runFingerprint(ctx context.Context, client *http.Client, opts DASTOptions, progress Progress) []model.RawFinding {
	progress("==> fingerprinting the target technology stack\n")
	cat, err := exploit.Load("") // KEV-only: product correlation needs no EPSS
	if err != nil {
		progress(fmt.Sprintf("WARN: fingerprint: KEV catalog unavailable (%v); reporting version disclosure only\n", err))
		cat = nil
	}
	res, err := fingerprint.Analyze(ctx, client, opts.URL, cat, fingerprint.Options{Headers: opts.Headers}, progress)
	if err != nil {
		progress(fmt.Sprintf("WARN: fingerprint failed: %v\n", err))
		return nil
	}
	return res.Findings
}

// mergeEndpoints appends the endpoints in b that are not already in a,
// deduplicating on method+URL+body.
func mergeEndpoints(a, b []dastcrawl.Endpoint) []dastcrawl.Endpoint {
	seen := make(map[string]bool, len(a))
	for _, e := range a {
		seen[e.Method+" "+e.URL+" "+e.Body] = true
	}
	out := a
	for _, e := range b {
		k := e.Method + " " + e.URL + " " + e.Body
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	return out
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

func runSSRF(ctx context.Context, client *http.Client, eps []dastcrawl.Endpoint, headers []string, progress Progress) []model.RawFinding {
	progress(fmt.Sprintf("==> testing %d endpoint(s) for server-side request forgery\n", len(eps)))
	listener, err := ssrfscan.NewListener()
	if err != nil {
		progress(fmt.Sprintf("WARN: ssrf: could not start the out-of-band listener: %v\n", err))
		return nil
	}
	defer listener.Close()
	return ssrfscan.Scan(ctx, client, listener, ssrfscan.Options{Endpoints: eps, Headers: headers, CloudMetadata: true}, progress)
}

func runSSTI(ctx context.Context, client *http.Client, eps []dastcrawl.Endpoint, headers []string, progress Progress) []model.RawFinding {
	progress(fmt.Sprintf("==> testing %d endpoint(s) for server-side template injection\n", len(eps)))
	return sstiscan.Scan(ctx, client, sstiscan.Options{Endpoints: eps, Headers: headers}, progress)
}

func runFileUpload(ctx context.Context, client *http.Client, baseURL string, forms []dastcrawl.UploadForm, headers []string, progress Progress) []model.RawFinding {
	progress(fmt.Sprintf("==> testing %d upload form(s) for unrestricted file upload\n", len(forms)))
	return uploadscan.Scan(ctx, client, uploadscan.Options{BaseURL: baseURL, Forms: forms, Headers: headers}, progress)
}

func runIDOR(ctx context.Context, clientA, clientB *http.Client, eps []dastcrawl.Endpoint, progress Progress) []model.RawFinding {
	progress(fmt.Sprintf("==> testing %d endpoint(s) for IDOR/BOLA across two identities\n", len(eps)))
	return idorscan.Scan(ctx, clientA, clientB, idorscan.Options{Endpoints: eps}, progress)
}

func runGraphQL(ctx context.Context, client *http.Client, eps []dastcrawl.Endpoint, headers []string, progress Progress) []model.RawFinding {
	progress("==> testing discovered GraphQL endpoint(s) for batching and alias amplification\n")
	return apiscan.Scan(ctx, client, apiscan.Options{Endpoints: eps, Headers: headers}, progress)
}

// filterUploadsInScope drops upload forms whose action is outside the engagement
// scope, mirroring filterEndpointsInScope.
func filterUploadsInScope(eng *engagement.Engagement, forms []dastcrawl.UploadForm) []dastcrawl.UploadForm {
	out := forms[:0:0]
	for _, f := range forms {
		if eng.InScope(f.Action) {
			out = append(out, f)
		}
	}
	return out
}

// authenticate runs the pre-scan login through the governed client (so every
// login request is scope-gated and audited) and returns the session (cookies
// held in memory, never logged).
func authenticate(ctx context.Context, client *http.Client, opts DASTOptions, progress Progress) (*dastauth.Session, error) {
	return authenticateWith(ctx, client, opts.Auth, opts.URL, progress)
}

// authenticateWith establishes a session for the given identity against
// loginURL, so the primary and (for IDOR) the second identity share one code
// path.
func authenticateWith(ctx context.Context, client *http.Client, a *DASTAuth, loginURL string, progress Progress) (*dastauth.Session, error) {
	cfg := dastauth.Config{LoginURL: a.LoginURL, TryDefaults: a.TryDefaults}
	if a.Username != "" || a.Password != "" {
		cfg.Credentials = []dastauth.Credential{{Username: a.Username, Password: a.Password}}
	}
	progress(fmt.Sprintf("==> authenticating to %s before scan\n", loginURL))
	sess, err := dastauth.Authenticate(ctx, client, loginURL, cfg, progress)
	if err != nil {
		return nil, fmt.Errorf("dast auth: %w", err)
	}
	return sess, nil
}

// crawlEndpoints walks the target through the governed client (reusing the auth
// session when present) and returns the fuzzable endpoints to scan.
func crawlEndpoints(ctx context.Context, governed *http.Client, opts DASTOptions, session *dastauth.Session, headers []string, progress Progress) ([]dastcrawl.Endpoint, []dastcrawl.UploadForm, error) {
	progress(fmt.Sprintf("==> crawling %s to discover endpoints\n", opts.URL))
	client := governed
	if session != nil {
		client = session.Client(governed) // preserves the governed transport, adds the session jar
	}
	eps, uploads, err := dastcrawl.Crawl(ctx, client, opts.URL, dastcrawl.Options{
		MaxDepth: opts.CrawlDepth,
		MaxPages: opts.CrawlPages,
		Headers:  headers,
	}, progress)
	if err != nil {
		return nil, nil, fmt.Errorf("dast crawl: %w", err)
	}
	return eps, uploads, nil
}
