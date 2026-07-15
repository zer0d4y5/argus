// Package apirecon reconstructs a target's API surface from the schema
// documents it serves, so the active engines can fuzz the real API rather than
// only what link-following finds. It discovers OpenAPI/Swagger documents and
// GraphQL introspection at well-known locations, parses them into fuzzable
// operations, and reports the exposure.
//
// Everything here is analysis of what the target serves. All fetching goes
// through the caller's governed client, so it is scope-gated, budgeted, and
// audited like every other active step. The parsers treat the documents as
// hostile input: bounded reads, no execution, benign placeholders substituted
// for path parameters. Recovered operations are filtered through the same
// auth-path and credential-change guards the crawler applies, so a
// schema-driven fuzz never drives a logout or password-change route.
package apirecon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
)

const (
	maxDocBytes = 2 << 20 // per-document read ceiling
	defaultOps  = 200     // cap on recovered operations
)

// openapiCandidates are well-known locations for an OpenAPI/Swagger JSON
// document. YAML variants are deliberately excluded (no YAML parser, and the
// JSON forms are what most frameworks serve).
var openapiCandidates = []string{
	"/openapi.json", "/swagger.json",
	"/v2/api-docs", "/v3/api-docs", "/api-docs",
	"/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json",
}

// graphqlCandidates are well-known GraphQL endpoints.
var graphqlCandidates = []string{"/graphql", "/api/graphql", "/query"}

// fuzzMethods are the HTTP methods a recovered operation may be fuzzed with.
// DELETE and the safe/idempotent metadata methods are excluded: DELETE is
// unambiguously destructive, and confirmation over exploitation is the posture.
var fuzzMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true}

// Options configure API schema reconstruction.
type Options struct {
	MaxOps int // cap on recovered operations (0 = default)
}

// Result is the outcome of reconstruction.
type Result struct {
	Operations []dastcrawl.Endpoint // fuzzable operations to merge into the scan
	Findings   []model.RawFinding   // schema-exposure / introspection findings
	Sources    []string             // human labels of what was found (for progress)
}

// Analyze probes the target for API schema documents, returns the fuzzable
// operations recovered from them, and reports what it found. It sends only GETs
// (for schema docs) and one POST introspection query per GraphQL candidate,
// all through the governed client.
func Analyze(ctx context.Context, client *http.Client, baseURL string, opts Options, progress func(string)) (Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil {
		client = &http.Client{}
	}
	if opts.MaxOps <= 0 {
		opts.MaxOps = defaultOps
	}
	root, err := rootURL(baseURL)
	if err != nil {
		return Result{}, err
	}

	var res Result
	// OpenAPI / Swagger: the first valid document is enough.
	for _, p := range openapiCandidates {
		if ctx.Err() != nil {
			break
		}
		body, ok := fetchJSON(ctx, client, root+p)
		if !ok {
			continue
		}
		doc, ok := parseOpenAPI(body)
		if !ok {
			continue
		}
		res.Findings = append(res.Findings, schemaExposedFinding(root+p))
		res.Sources = append(res.Sources, "OpenAPI/Swagger at "+p)
		res.Operations = append(res.Operations, openAPIOperations(doc, root)...)
		break
	}

	// GraphQL introspection: an enabled schema is a real information-disclosure
	// finding, and the endpoint itself becomes a fuzz target.
	for _, p := range graphqlCandidates {
		if ctx.Err() != nil {
			break
		}
		if introspectionEnabled(ctx, client, root+p) {
			res.Findings = append(res.Findings, graphqlIntrospectionFinding(root+p))
			res.Sources = append(res.Sources, "GraphQL introspection at "+p)
			res.Operations = append(res.Operations, dastcrawl.Endpoint{
				URL: root + p, Method: "POST", Body: `{"query":"{__typename}"}`,
			})
			break
		}
	}

	res.Operations = filterOperations(res.Operations, opts.MaxOps)
	if len(res.Sources) > 0 {
		progress("==> apirecon: " + strings.Join(res.Sources, "; ") + "\n")
	}
	return res, nil
}

// rootURL reduces a target URL to scheme://host, where schema documents live.
func rootURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("apirecon: base URL needs a scheme and host")
	}
	return u.Scheme + "://" + u.Host, nil
}

// fetchJSON GETs a candidate and returns its body when the response looks like a
// JSON document. It never follows the body's content anywhere; it only reads.
func fetchJSON(ctx context.Context, client *http.Client, u string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDocBytes))
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "json") && !looksJSON(body) {
		return nil, false
	}
	return body, true
}

func looksJSON(b []byte) bool {
	s := strings.TrimSpace(string(b))
	return strings.HasPrefix(s, "{")
}

// filterOperations drops operations that must never be fuzzed (auth machinery,
// credential changes) and caps the count. It dedups on method+URL+body.
func filterOperations(ops []dastcrawl.Endpoint, cap int) []dastcrawl.Endpoint {
	seen := map[string]bool{}
	out := make([]dastcrawl.Endpoint, 0, len(ops))
	for _, ep := range ops {
		if len(out) >= cap {
			break
		}
		u, err := url.Parse(ep.URL)
		if err != nil || u.Host == "" {
			continue
		}
		// Schema-recovered operations are not linked and the crawler never sees
		// them, so this filter is load-bearing. A GET is safe to fuzz; anything
		// that could change state on a sensitive surface (auth, account, MFA,
		// tokens, password reset) is dropped, since fuzzing it could disrupt the
		// account under test or lock the session out.
		if dastcrawl.IsAuthPath(u.Path) || isSensitiveOperation(ep.Method, u.Path) {
			continue
		}
		if dastcrawl.ChangesCredentials(paramNames(u, ep.Body)) {
			continue
		}
		key := ep.Method + "\x00" + ep.URL + "\x00" + ep.Body
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ep)
	}
	return out
}

// sensitiveOpTokens name surfaces whose state-changing operations must never be
// fuzzed from a schema (they could rotate a credential, disable MFA, or lock the
// session out). A GET on these is still allowed (read-only); a body-bearing
// method is not.
var sensitiveOpTokens = []string{
	"password", "passwd", "credential", "reset", "recover", "mfa", "2fa",
	"otp", "email", "account", "session", "token", "apikey", "api-key",
	"api_key", "verify", "activate", "deactivate", "disable", "enable",
	"role", "permission", "privilege", "billing", "payment", "delete", "remove",
}

// isSensitiveOperation reports whether a schema operation is too sensitive to
// fuzz. Read-only GETs are never sensitive; a state-changing method whose path
// mentions a sensitive surface is.
func isSensitiveOperation(method, path string) bool {
	if strings.EqualFold(method, "GET") {
		return false
	}
	l := strings.ToLower(path)
	for _, t := range sensitiveOpTokens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// paramNames collects the parameter names an operation carries, from the query
// string and a form-encoded body, for the credential-change guard.
func paramNames(u *url.URL, body string) []string {
	var names []string
	for name := range u.Query() {
		names = append(names, name)
	}
	if body != "" {
		if vals, err := url.ParseQuery(body); err == nil {
			for name := range vals {
				names = append(names, name)
			}
		}
	}
	return names
}

func schemaExposedFinding(u string) model.RawFinding {
	return model.RawFinding{
		Tool:        "argus-apirecon",
		Category:    model.CategoryDAST,
		RuleID:      "api-schema-exposed",
		Title:       "API Schema Documentation Exposed",
		Description: "An OpenAPI/Swagger document is served at this URL, disclosing the full API surface (paths, parameters, and methods) to anyone who requests it. Confirm this exposure is intended for the audience that can reach it.",
		RawSeverity: "info",
		URL:         u,
		CWEs:        []string{"CWE-200"},
	}
}

func graphqlIntrospectionFinding(u string) model.RawFinding {
	return model.RawFinding{
		Tool:        "argus-apirecon",
		Category:    model.CategoryDAST,
		RuleID:      "graphql-introspection",
		Title:       "GraphQL Introspection Enabled",
		Description: "The GraphQL endpoint answered an introspection query, disclosing its full schema (every type, query, and mutation). Disabling introspection in production is a common hardening step, since it hands an attacker the API's map.",
		RawSeverity: "low",
		URL:         u,
		CWEs:        []string{"CWE-200"},
	}
}
