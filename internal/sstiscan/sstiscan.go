// Package sstiscan is a native server-side template injection detector for the
// DAST pipeline. It uses the same arithmetic-marker discipline as the
// command-injection detector: it injects a template expression that multiplies
// two random numbers and confirms injection only when the response contains the
// PRODUCT, which never appears in the payload. A target that merely reflects the
// payload back therefore cannot produce a false positive.
//
// The payloads cover the common template engines (Jinja2/Twig/Nunjucks,
// Freemarker/Velocity, Thymeleaf/Spring EL, ERB, Smarty). Each is a pure
// arithmetic expression; none reads files, runs commands, or reaches the
// network, so confirmation stays benign.
package sstiscan

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
	maxBodyBytes   = 512 << 10
	maxParamsPerEP = 12
)

// engine is one template-engine payload family: a wrapper that evaluates
// A*B and the human name of the engines it fingerprints.
type engine struct {
	name string
	wrap func(expr string) string
}

// engines are the injection templates, ordered common-first. The product marker
// is arithmetic, so a reflected payload cannot forge it.
var engines = []engine{
	{"Jinja2/Twig/Nunjucks", func(e string) string { return "{{" + e + "}}" }},
	{"Freemarker/Velocity", func(e string) string { return "${" + e + "}" }},
	{"Thymeleaf/Spring-EL", func(e string) string { return "#{" + e + "}" }},
	{"ERB", func(e string) string { return "<%= " + e + " %>" }},
	{"Smarty", func(e string) string { return "{" + e + "}" }},
}

// Options configure an SSTI scan.
type Options struct {
	Endpoints []dastcrawl.Endpoint
	Headers   []string
}

// Scan probes each endpoint's parameters for template injection and returns one
// finding per confirmed injectable parameter.
func Scan(ctx context.Context, client *http.Client, opts Options, progress func(string)) []model.RawFinding {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	s := &scanner{client: client, headers: opts.Headers}

	var out []model.RawFinding
	seen := map[string]bool{}
	for _, ep := range opts.Endpoints {
		if ctx.Err() != nil {
			break
		}
		names, base, err := paramsOf(ep)
		if err != nil {
			continue
		}
		tested := 0
		for _, p := range names {
			if tested >= maxParamsPerEP {
				break
			}
			tested++
			if c := s.testParam(ctx, ep, base, p); c != nil {
				f := finding(ep, base, p, *c, hasCookie(s.headers))
				key := f.RuleID + "\x00" + f.URL
				if !seen[key] {
					seen[key] = true
					out = append(out, f)
				}
			}
		}
	}
	progress(fmt.Sprintf("ssti: %d template-injection finding(s)\n", len(out)))
	return out
}

type scanner struct {
	client  *http.Client
	headers []string
}

// confirmation is a confirmed template injection.
type confirmation struct {
	engine   string
	payload  string
	observed string
	response string
}

// testParam returns the confirmation, or nil if the parameter is not injectable.
func (s *scanner) testParam(ctx context.Context, ep dastcrawl.Endpoint, base url.Values, param string) *confirmation {
	a, b := randInt(), randInt()
	product := fmt.Sprintf("%d", a*b)
	expr := fmt.Sprintf("%d*%d", a, b)
	orig := base.Get(param)
	for _, e := range engines {
		payload := orig + e.wrap(expr)
		body, err := s.send(ctx, ep, base, param, payload)
		// Confirm only when the product appears AND the raw expression does not,
		// so a template that echoes the payload verbatim is not a false positive.
		if err == nil && strings.Contains(body, product) && !strings.Contains(body, expr) {
			return &confirmation{
				engine:   e.name,
				payload:  payload,
				observed: fmt.Sprintf("The %s template payload evaluating %d*%d returned %s in the response, a value the payload never contains. The server rendered the input as a template.", e.name, a, b, product),
				response: body,
			}
		}
	}
	return nil
}

// send issues the request with param set to value and returns the response body.
func (s *scanner) send(ctx context.Context, ep dastcrawl.Endpoint, base url.Values, param, value string) (string, error) {
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
		return "", err
	}
	for _, h := range s.headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(body), nil
}

func finding(ep dastcrawl.Endpoint, base url.Values, param string, c confirmation, cookiePresent bool) model.RawFinding {
	method := ep.Method
	if method == "" {
		method = http.MethodGet
	}
	_, u, body := requestTarget(ep, base, param, c.payload)
	f := model.RawFinding{
		Tool:        "argus-ssti",
		Category:    model.CategoryDAST,
		RuleID:      "ssti:" + strings.ToLower(method) + ":" + param,
		Title:       "Server-Side Template Injection",
		Description: fmt.Sprintf("Parameter %q (%s) is evaluated as a server-side template (%s), which commonly leads to remote code execution. Confirmed because the response returned the arithmetic result of an injected template expression; verify the sink is a template engine (rather than a dedicated math/formula feature) before rating it as RCE-capable.", param, method, c.engine),
		RawSeverity: "critical",
		URL:         ep.URL,
		CWEs:        []string{"CWE-1336"},
		Meta:        map[string]string{"param": param, "method": method, "engine": c.engine},
	}
	if method == http.MethodPost && body != "" {
		f.Meta["body"] = body
	}
	f.Proof = poc.Build("ssti", poc.Request{Method: method, URL: u, Body: body, CookiePresent: cookiePresent}, param, c.observed)
	if f.Proof != nil {
		f.Proof.Response = poc.RedactResponse(c.response)
	}
	return f
}

// randInt returns a random int in [100000, 199999] via crypto/rand, so the
// product is a large, distinctive number unlikely to appear by chance.
func randInt() int {
	n, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		return 133337
	}
	return int(n.Int64()) + 100000
}
