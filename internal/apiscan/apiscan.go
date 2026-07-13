// Package apiscan tests GraphQL endpoints for the resource-control weaknesses
// that make an API abusable: query batching (many operations in one request,
// which bypasses per-request rate limits and amplifies attacks like credential
// stuffing) and alias-based amplification (repeating a field under many aliases
// with no complexity limit). Both probes are benign: they send a handful of
// trivial `__typename` operations, never a resource-exhausting payload, so they
// confirm the missing control without causing a denial of service.
package apiscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/poc"
)

const (
	maxBodyBytes = 256 << 10
	aliasCount   = 100 // small enough to be benign, enough to reveal no complexity limit
)

// Options configure an API scan.
type Options struct {
	Endpoints []dastcrawl.Endpoint
	Headers   []string
}

// Scan finds GraphQL endpoints among the discovered endpoints and probes them
// for batching and alias amplification. It sends through the governed client.
func Scan(ctx context.Context, client *http.Client, opts Options, progress func(string)) []model.RawFinding {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	var out []model.RawFinding
	seen := map[string]bool{}
	for _, ep := range graphqlEndpoints(opts.Endpoints) {
		if ctx.Err() != nil {
			break
		}
		for _, f := range probe(ctx, client, ep, opts.Headers) {
			key := f.RuleID + "\x00" + f.URL
			if !seen[key] {
				seen[key] = true
				out = append(out, f)
			}
		}
	}
	progress(fmt.Sprintf("api: %d GraphQL abuse finding(s)\n", len(out)))
	return out
}

// graphqlEndpoints returns the endpoints that look like GraphQL: a URL path
// mentioning graphql, or a POST body carrying a "query" field.
func graphqlEndpoints(eps []dastcrawl.Endpoint) []dastcrawl.Endpoint {
	var out []dastcrawl.Endpoint
	seen := map[string]bool{}
	for _, ep := range eps {
		isGQL := strings.Contains(strings.ToLower(ep.URL), "graphql") ||
			(ep.Method == http.MethodPost && strings.Contains(ep.Body, "query"))
		if isGQL && !seen[ep.URL] {
			seen[ep.URL] = true
			out = append(out, ep)
		}
	}
	return out
}

func probe(ctx context.Context, client *http.Client, ep dastcrawl.Endpoint, headers []string) []model.RawFinding {
	var out []model.RawFinding

	// Batching: two operations in one request. A JSON array of results back
	// means the endpoint executes batched operations.
	batch := `[{"query":"{__typename}"},{"query":"{__typename}"}]`
	if body, ok := postJSON(ctx, client, ep.URL, batch, headers); ok && isBatchedResult(body) {
		out = append(out, finding(ep, headers,
			"graphql-batching",
			"GraphQL Query Batching Enabled",
			"The GraphQL endpoint executes an array of operations in a single request. Batching bypasses per-request rate limits and amplifies attacks such as credential stuffing.",
			batch, body,
			"Sending an array of two operations returned an array of two results, so the endpoint executes batched operations without a per-request cap."))
	}

	// Alias amplification: one field repeated under many aliases. Executing all
	// of them means there is no query-complexity limit.
	amp := aliasQuery(aliasCount)
	if body, ok := postJSON(ctx, client, ep.URL, amp, headers); ok && countTypenames(body) >= aliasCount {
		out = append(out, finding(ep, headers,
			"graphql-alias-amplification",
			"GraphQL Alias-Based Amplification (no complexity limit)",
			fmt.Sprintf("The GraphQL endpoint executed %d aliases of a single field in one query. With no query-complexity limit, an attacker can amplify a single request into heavy server work.", aliasCount),
			amp, body,
			fmt.Sprintf("A query repeating one field under %d aliases returned all %d results, so no query-complexity limit is enforced.", aliasCount, aliasCount)))
	}
	return out
}

// aliasQuery builds a benign query repeating __typename under n aliases.
func aliasQuery(n int) string {
	var b strings.Builder
	b.WriteString(`{"query":"{`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "a%d:__typename ", i)
	}
	b.WriteString(`}"}`)
	return b.String()
}

func isBatchedResult(body string) bool {
	t := strings.TrimSpace(body)
	// A batched response is a JSON array; require two data envelopes.
	return strings.HasPrefix(t, "[") && strings.Count(t, "\"data\"") >= 2
}

func countTypenames(body string) int {
	return strings.Count(body, "__typename") + strings.Count(body, "\"Query\"") + strings.Count(body, "\"query\"")
}

func finding(ep dastcrawl.Endpoint, headers []string, rule, title, desc, req, resp, observed string) model.RawFinding {
	f := model.RawFinding{
		Tool:        "argus-api",
		Category:    model.CategoryDAST,
		RuleID:      rule,
		Title:       title,
		Description: desc,
		RawSeverity: "medium",
		URL:         ep.URL,
		CWEs:        []string{"CWE-770"},
		Meta:        map[string]string{"method": "POST"},
	}
	r := poc.Request{Method: "POST", URL: ep.URL, Body: req, CookiePresent: hasCookie(headers)}
	f.Proof = &model.Proof{
		Request:  poc.RawHTTP(r),
		Curl:     poc.Curl(r),
		Observed: observed,
		Response: poc.RedactResponse(resp),
	}
	return f
}

// postJSON sends a JSON body and returns the response body and whether it was a
// 200.
func postJSON(ctx context.Context, client *http.Client, url, body string, headers []string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for _, h := range headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(b), resp.StatusCode == http.StatusOK
}

func splitHeader(h string) (key, val string, ok bool) {
	i := strings.Index(h, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]), true
}

func hasCookie(headers []string) bool {
	for _, h := range headers {
		if k, _, ok := splitHeader(h); ok && strings.EqualFold(strings.TrimSpace(k), "Cookie") {
			return true
		}
	}
	return false
}
