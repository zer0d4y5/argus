package apiscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// graphqlApp executes batched operations and unlimited aliases (the weaknesses).
func graphqlApp(batching, aliases bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "application/json")
		s := strings.TrimSpace(string(body))
		if strings.HasPrefix(s, "[") { // a batch
			if !batching {
				io.WriteString(w, `{"errors":[{"message":"batching disabled"}]}`)
				return
			}
			var arr []map[string]any
			_ = json.Unmarshal([]byte(s), &arr)
			var out []string
			for range arr {
				out = append(out, `{"data":{"__typename":"Query"}}`)
			}
			io.WriteString(w, "["+strings.Join(out, ",")+"]")
			return
		}
		// A single query with many aliases.
		if aliases {
			n := strings.Count(s, "__typename")
			var parts []string
			for i := 0; i < n; i++ {
				parts = append(parts, `"a`+itoa(i)+`":"Query"`)
			}
			io.WriteString(w, `{"data":{`+strings.Join(parts, ",")+`}}`)
			return
		}
		io.WriteString(w, `{"errors":[{"message":"query too complex"}]}`)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestScanDetectsBatchingAndAmplification(t *testing.T) {
	srv := httptest.NewServer(graphqlApp(true, true))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/graphql", Method: "POST", Body: `{"query":"{__typename}"}`}},
	}, nil)

	rules := map[string]bool{}
	for _, f := range fs {
		rules[f.RuleID] = true
		if f.CWEs[0] != "CWE-770" {
			t.Errorf("expected CWE-770, got %v", f.CWEs)
		}
		if f.Proof == nil || f.Proof.Response == "" {
			t.Errorf("proof should carry request/response: %+v", f.Proof)
		}
	}
	if !rules["graphql-batching"] || !rules["graphql-alias-amplification"] {
		t.Errorf("expected both batching and amplification findings, got %v", rules)
	}
}

func TestScanNoFindingWhenLimited(t *testing.T) {
	srv := httptest.NewServer(graphqlApp(false, false)) // both controls enforced
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/graphql", Method: "POST", Body: `{"query":"{__typename}"}`}},
	}, nil)
	if len(fs) != 0 {
		t.Errorf("a limited GraphQL endpoint must not be flagged: %+v", fs)
	}
}

func TestScanIgnoresNonGraphQL(t *testing.T) {
	fs := Scan(context.Background(), http.DefaultClient, Options{
		Endpoints: []dastcrawl.Endpoint{{URL: "http://t/page?id=1", Method: "GET"}},
	}, nil)
	if len(fs) != 0 {
		t.Errorf("non-GraphQL endpoints must be ignored: %+v", fs)
	}
}
