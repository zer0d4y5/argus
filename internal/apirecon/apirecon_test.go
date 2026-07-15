package apirecon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

const openapiDoc = `{
  "openapi": "3.0.0",
  "servers": [{"url": "/api/v1"}],
  "paths": {
    "/users/{id}": {
      "get": {"parameters": [{"name": "verbose", "in": "query"}]},
      "delete": {}
    },
    "/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
    "/login": {"post": {"parameters": [{"name": "user", "in": "formData"}]}},
    "/account/change-password": {"post": {"parameters": [{"name": "new_password", "in": "formData"}]}}
  }
}`

func TestParseOpenAPIRejectsNonSchema(t *testing.T) {
	for _, b := range []string{`{"hello":"world"}`, `{"openapi":"3.0.0"}`, `not json`} {
		if _, ok := parseOpenAPI([]byte(b)); ok {
			t.Errorf("parseOpenAPI accepted a non-schema document: %s", b)
		}
	}
}

func TestOpenAPIOperations(t *testing.T) {
	doc, ok := parseOpenAPI([]byte(openapiDoc))
	if !ok {
		t.Fatal("valid OpenAPI doc rejected")
	}
	ops := openAPIOperations(doc, "http://t")
	byKey := map[string]bool{}
	for _, ep := range ops {
		byKey[ep.Method+" "+ep.URL] = true
	}
	// GET /users/{id} -> path param filled with 1, query seeded.
	if !byKey["GET http://t/api/v1/users/1?verbose=1"] {
		t.Errorf("missing templated GET operation; got %v", byKey)
	}
	// GET /search with base path.
	if !byKey["GET http://t/api/v1/search?q=1"] {
		t.Errorf("missing search operation; got %v", byKey)
	}
	// DELETE must be excluded (destructive).
	for k := range byKey {
		if strings.HasPrefix(k, "DELETE ") {
			t.Errorf("DELETE operation must not be fuzzed: %s", k)
		}
	}
}

func TestFilterOperationsDropsSensitiveStateChanges(t *testing.T) {
	ops := []dastcrawl.Endpoint{
		{URL: "http://t/api/products/1", Method: "GET"},      // safe: keep
		{URL: "http://t/api/account/email", Method: "PUT"},   // sensitive: drop
		{URL: "http://t/reset-password", Method: "POST"},     // sensitive: drop
		{URL: "http://t/api/mfa/disable", Method: "POST"},    // sensitive: drop
		{URL: "http://t/api/users/1/roles", Method: "PATCH"}, // sensitive: drop
		{URL: "http://t/api/account", Method: "GET"},         // read-only account: keep
	}
	out := filterOperations(ops, 200)
	for _, ep := range out {
		if ep.Method != "GET" && (strings.Contains(ep.URL, "account") || strings.Contains(ep.URL, "reset") ||
			strings.Contains(ep.URL, "mfa") || strings.Contains(ep.URL, "roles")) {
			t.Errorf("sensitive state-changing op must be dropped: %s %s", ep.Method, ep.URL)
		}
	}
	// The safe GET operations survive.
	if len(out) != 2 {
		t.Errorf("expected the two safe GETs to survive, got %d: %+v", len(out), out)
	}
}

func TestFilterOperationsDropsAuthAndCredChanges(t *testing.T) {
	doc, _ := parseOpenAPI([]byte(openapiDoc))
	ops := filterOperations(openAPIOperations(doc, "http://t"), 200)
	for _, ep := range ops {
		if strings.Contains(ep.URL, "/login") {
			t.Errorf("auth-path operation must be dropped: %s", ep.URL)
		}
		if strings.Contains(ep.URL, "change-password") || strings.Contains(ep.Body, "new_password") {
			t.Errorf("credential-change operation must be dropped: %s %s", ep.URL, ep.Body)
		}
	}
	if len(ops) == 0 {
		t.Fatal("expected some safe operations to survive")
	}
}

func TestAnalyzeDiscoversOpenAPIAndGraphQL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(openapiDoc))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Analyze(context.Background(), srv.Client(), srv.URL+"/app/page", Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, f := range res.Findings {
		rules[f.RuleID] = true
	}
	if !rules["api-schema-exposed"] {
		t.Error("expected an api-schema-exposed finding")
	}
	if !rules["graphql-introspection"] {
		t.Error("expected a graphql-introspection finding")
	}
	if len(res.Operations) == 0 {
		t.Error("expected recovered operations to fuzz")
	}
	// The GraphQL endpoint should be among the operations.
	var haveGQL bool
	for _, ep := range res.Operations {
		if strings.HasSuffix(ep.URL, "/graphql") && ep.Method == "POST" {
			haveGQL = true
		}
	}
	if !haveGQL {
		t.Error("graphql endpoint should be a fuzz operation")
	}
}

func TestIntrospectionDisabledNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A server with introspection disabled returns an error, no data.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"introspection is disabled"}]}`))
	}))
	defer srv.Close()
	if introspectionEnabled(context.Background(), srv.Client(), srv.URL+"/graphql") {
		t.Error("a disabled-introspection response must not be flagged as enabled")
	}
}
