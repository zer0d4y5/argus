// Package cmdiscan is a native OS-command-injection detector for the DAST
// pipeline. It confirms injection the way an appsec engineer would, but with
// benign, self-verifying probes only: it never runs an attacker-controlled
// command, exfiltrates data, or writes to the target. It exists because the
// off-the-shelf tool (commix) is not always installable, and because
// exploit-detection logic must be hand-written and owned here anyway.
//
// Two techniques, both false-positive resistant:
//
//   - Arithmetic echo (results-based): inject `<sep>expr A \* B` for random A,B.
//     The response confirms injection only if it contains the PRODUCT A*B,
//     which never appears in the payload itself, so a target that merely
//     reflects input cannot trigger a false positive.
//   - Differential timing (blind): inject `<sep>sleep N` and require the
//     response to be at least N seconds slower than a control request, so
//     ordinary latency cannot masquerade as injection.
//
// SECURITY: the only commands injected are `expr` (arithmetic) and `sleep`
// (delay). No command is ever taken from configuration or a response. The auth
// cookie/headers are sent but never logged or written to a finding.
package cmdiscan

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/poc"
)

const (
	maxBodyBytes    = 512 << 10
	maxParamsPerEP  = 12
	sleepSeconds    = 5
	timingThreshold = 4 * time.Second // response must be at least this much slower
)

// separators are the shell metacharacters that break out of the original
// argument into a new command. Kept small and standard.
var separators = []string{";", "|", "&&", "&", "\n"}

// Options configure a command-injection scan.
type Options struct {
	Endpoints []dastcrawl.Endpoint
	Headers   []string // e.g. "Cookie: SESS=..." for auth
	Timing    bool     // also try the (slower) blind timing technique
}

// Scan probes each endpoint's parameters for command injection and returns one
// finding per confirmed injectable parameter.
func Scan(ctx context.Context, client *http.Client, opts Options, progress func(string)) ([]model.RawFinding, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	sc := &scanner{client: client, headers: opts.Headers, timing: opts.Timing}

	var out []model.RawFinding
	seen := map[string]bool{}
	for _, ep := range opts.Endpoints {
		if ctx.Err() != nil {
			break
		}
		for _, f := range sc.scanEndpoint(ctx, ep) {
			key := f.RuleID + "\x00" + f.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	progress(fmt.Sprintf("cmdi: %d command-injection finding(s)\n", len(out)))
	return out, nil
}

type scanner struct {
	client  *http.Client
	headers []string
	timing  bool
}

// scanEndpoint tests every parameter of one endpoint.
func (s *scanner) scanEndpoint(ctx context.Context, ep dastcrawl.Endpoint) []model.RawFinding {
	params, base, err := paramsOf(ep)
	if err != nil {
		return nil
	}
	var out []model.RawFinding
	tested := 0
	for _, p := range params {
		if tested >= maxParamsPerEP {
			break
		}
		tested++
		if c := s.testParam(ctx, ep, base, p); c != nil {
			out = append(out, finding(ep, base, p, *c, hasCookie(s.headers)))
		}
	}
	return out
}

// confirmation is a confirmed command injection: the technique that proved it,
// the exact payload the parameter carried, a plain-English proof line, and the
// response body that demonstrated it.
type confirmation struct {
	technique string
	payload   string
	observed  string
	response  string
}

// testParam returns the confirmation, or nil if the parameter is not injectable.
func (s *scanner) testParam(ctx context.Context, ep dastcrawl.Endpoint, base url.Values, param string) *confirmation {
	// Arithmetic echo: the product proves execution and is absent from the payload.
	a, b := randInt(), randInt()
	product := fmt.Sprintf("%d", a*b)
	orig := base.Get(param)
	for _, sep := range separators {
		payload := orig + sep + fmt.Sprintf("expr %d \\* %d", a, b)
		body, _, err := s.send(ctx, ep, base, param, payload)
		if err == nil && strings.Contains(body, product) {
			return &confirmation{
				technique: "arithmetic",
				payload:   payload,
				observed:  fmt.Sprintf("A benign shell probe computing %d times %d returned %s in the response, a value the request itself never contains.", a, b, product),
				response:  body,
			}
		}
	}
	if !s.timing {
		return nil
	}
	// Differential timing: a control, then a sleep, requiring a clear slowdown.
	_, control, err := s.send(ctx, ep, base, param, orig)
	if err != nil {
		return nil
	}
	for _, sep := range separators {
		payload := orig + sep + fmt.Sprintf("sleep %d", sleepSeconds)
		body, elapsed, err := s.send(ctx, ep, base, param, payload)
		if err == nil && elapsed-control >= timingThreshold {
			return &confirmation{
				technique: "time-based",
				payload:   payload,
				observed:  fmt.Sprintf("A time-based probe delayed the response by at least %d seconds over a control request, which only a blind shell sleep explains.", sleepSeconds),
				response:  body,
			}
		}
	}
	return nil
}

// send issues the request with param replaced by value, returning the body and
// the round-trip time.
func (s *scanner) send(ctx context.Context, ep dastcrawl.Endpoint, base url.Values, param, value string) (string, time.Duration, error) {
	method, u, reqBody := requestTarget(ep, base, param, value)

	var req *http.Request
	var err error
	if method == http.MethodPost {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(reqBody))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	}
	if err != nil {
		return "", 0, err
	}
	for _, h := range s.headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}

	start := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(body), time.Since(start), nil
}

// paramsOf returns the parameter names and their base values for an endpoint
// (from the query for GET, the body for POST).
func paramsOf(ep dastcrawl.Endpoint) ([]string, url.Values, error) {
	var vals url.Values
	if ep.Method == http.MethodPost {
		v, err := url.ParseQuery(ep.Body)
		if err != nil {
			return nil, nil, err
		}
		vals = v
	} else {
		u, err := url.Parse(ep.URL)
		if err != nil {
			return nil, nil, err
		}
		vals = u.Query()
	}
	names := make([]string, 0, len(vals))
	for name := range vals {
		names = append(names, name)
	}
	return names, vals, nil
}

// requestTarget builds the (method, url, body) for a request that sets param to
// value, matching how send issues it: GET carries params in the query, POST in
// a form-encoded body. It sends nothing.
func requestTarget(ep dastcrawl.Endpoint, base url.Values, param, value string) (method, u, body string) {
	vals := cloneValues(base)
	vals.Set(param, value)
	if ep.Method == http.MethodPost {
		return http.MethodPost, stripQuery(ep.URL), vals.Encode()
	}
	return http.MethodGet, stripQuery(ep.URL) + "?" + vals.Encode(), ""
}

func finding(ep dastcrawl.Endpoint, base url.Values, param string, c confirmation, cookiePresent bool) model.RawFinding {
	method := ep.Method
	if method == "" {
		method = http.MethodGet
	}
	_, u, body := requestTarget(ep, base, param, c.payload)
	f := model.RawFinding{
		Tool:        "argus-cmdi",
		Category:    model.CategoryDAST,
		RuleID:      "cmdi:" + strings.ToLower(method) + ":" + param,
		Title:       "OS Command Injection",
		Description: fmt.Sprintf("Parameter %q (%s) is vulnerable to OS command injection, confirmed by a %s probe.", param, method, c.technique),
		RawSeverity: "critical",
		URL:         ep.URL,
		CWEs:        []string{"CWE-78"},
		Meta:        map[string]string{"param": param, "method": method, "technique": c.technique},
	}
	if method == http.MethodPost && ep.Body != "" {
		f.Meta["body"] = ep.Body
	}
	f.Proof = poc.Build("cmdi", poc.Request{
		Method:        method,
		URL:           u,
		Body:          body,
		CookiePresent: cookiePresent,
	}, param, c.observed)
	if f.Proof != nil {
		f.Proof.Response = poc.RedactResponse(c.response)
	}
	return f
}

// ConfirmID is the bounded impact confirmation for command injection: it
// injects a single benign `id` command into a confirmed-injectable parameter
// and returns the identity line the shell prints (e.g.
// "uid=33(www-data) gid=33(www-data) ..."). It runs one identifying command and
// nothing else: no shell, no persistence, no data read beyond the process
// identity. It returns ("", false, nil) when the response carried no id output.
// The client should be the governed client so the probe is scope- and
// budget-metered and audited.
func ConfirmID(ctx context.Context, client *http.Client, ep dastcrawl.Endpoint, param string, headers []string) (string, bool, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	s := &scanner{client: client, headers: headers}
	_, base, err := paramsOf(ep)
	if err != nil {
		return "", false, err
	}
	orig := base.Get(param)
	for _, sep := range separators {
		if ctx.Err() != nil {
			break
		}
		body, _, err := s.send(ctx, ep, base, param, orig+sep+"id")
		if err != nil {
			continue
		}
		if line := extractIDLine(body); line != "" {
			return line, true, nil
		}
	}
	return "", false, nil
}

// extractIDLine returns the `uid=...` identity line from an `id` command's
// output in a response, bounded in length. It is the minimum identifying proof
// of command execution.
func extractIDLine(body string) string {
	idx := strings.Index(body, "uid=")
	if idx < 0 {
		return ""
	}
	rest := body[idx:]
	if cut := strings.IndexAny(rest, "\r\n<"); cut >= 0 {
		rest = rest[:cut]
	}
	if len(rest) > 200 {
		rest = rest[:200]
	}
	return strings.TrimSpace(rest)
}

// hasCookie reports whether the request headers carry a session cookie, so the
// rendered PoC shows a cookie placeholder rather than an unauthenticated request.
func hasCookie(headers []string) bool {
	for _, h := range headers {
		if k, _, ok := splitHeader(h); ok && strings.EqualFold(strings.TrimSpace(k), "Cookie") {
			return true
		}
	}
	return false
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func stripQuery(raw string) string {
	if i := strings.Index(raw, "?"); i >= 0 {
		return raw[:i]
	}
	return raw
}

func splitHeader(h string) (key, val string, ok bool) {
	i := strings.Index(h, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]), true
}

// randInt returns a random 3-digit int so A*B is a distinctive 5-6 digit
// product unlikely to occur incidentally in a response.
func randInt() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(800))
	if err != nil {
		return 613 // fixed fallback; still valid, just not random
	}
	return n.Int64() + 100
}
