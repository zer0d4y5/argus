package prcomment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

// fakeGitHub is a minimal stand-in for the four API calls Post makes. It
// checks token hygiene on every request and captures posted reviews.
type fakeGitHub struct {
	t        *testing.T
	comments []string // existing inline-comment bodies
	reviews  []string // existing review bodies
	files    []map[string]string
	posted   []map[string]json.RawMessage
	srv      *httptest.Server
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{t: t}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token-value" {
			t.Errorf("outbound auth header wrong: %q", got)
		}
		bodies := func(items []string) []map[string]string {
			out := make([]map[string]string, 0, len(items))
			for _, b := range items {
				out = append(out, map[string]string{"body": b})
			}
			return out
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/webapp/pulls/7":
			json.NewEncoder(w).Encode(map[string]any{"head": map[string]string{"sha": "headsha123"}})
		case r.Method == "GET" && r.URL.Path == "/repos/acme/webapp/pulls/7/files":
			json.NewEncoder(w).Encode(f.files)
		case r.Method == "GET" && r.URL.Path == "/repos/acme/webapp/pulls/7/comments":
			json.NewEncoder(w).Encode(bodies(f.comments))
		case r.Method == "GET" && r.URL.Path == "/repos/acme/webapp/pulls/7/reviews":
			json.NewEncoder(w).Encode(bodies(f.reviews))
		case r.Method == "POST" && r.URL.Path == "/repos/acme/webapp/pulls/7/reviews":
			var req map[string]json.RawMessage
			json.NewDecoder(r.Body).Decode(&req)
			f.posted = append(f.posted, req)
			w.Write([]byte(`{"id":1}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) opts() Options {
	return Options{Repo: "acme/webapp", PR: 7, Token: "test-token-value", APIBase: f.srv.URL}
}

func fid(n int) string { return fmt.Sprintf("%032x", n) }

// threeFindings: A inline-able (in the diff), B out-of-diff line, C cloud.
func threeFindings() []model.Finding {
	a := sastFinding(fid(1))
	b := sastFinding(fid(2))
	b.Location.StartLine = 500
	c := sastFinding(fid(3))
	c.Category = model.CategoryCloud
	c.Location = model.Location{Resource: "arn:aws:s3:::bucket"}
	return []model.Finding{a, b, c}
}

func dbPatchFiles() []map[string]string {
	return []map[string]string{{
		"filename": "app/db.go",
		"status":   "modified",
		"patch":    "@@ -10,3 +10,4 @@\n ctx10\n ctx11\n+added12\n ctx13",
	}}
}

// TestPostBatchesReview drives the whole flow: one review, the in-diff
// finding inline on its line, everything else in the review body, all
// anchored to the PR head commit.
func TestPostBatchesReview(t *testing.T) {
	f := newFakeGitHub(t)
	f.files = dbPatchFiles()

	res, err := Post(context.Background(), f.opts(), threeFindings())
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if res.Inline != 1 || res.InBody != 2 || res.Duplicate != 0 {
		t.Errorf("result = %+v, want 1 inline, 2 in body", res)
	}
	if len(f.posted) != 1 {
		t.Fatalf("posted %d reviews, want 1", len(f.posted))
	}
	req := f.posted[0]
	if got := string(req["commit_id"]); got != `"headsha123"` {
		t.Errorf("commit_id = %s", got)
	}
	if got := string(req["event"]); got != `"COMMENT"` {
		t.Errorf("event = %s", got)
	}
	var comments []reviewComment
	json.Unmarshal(req["comments"], &comments)
	if len(comments) != 1 {
		t.Fatalf("inline comments = %d, want 1: %s", len(comments), req["comments"])
	}
	c := comments[0]
	if c.Path != "app/db.go" || c.Line != 12 || c.Side != "RIGHT" {
		t.Errorf("inline placement = %+v", c)
	}
	if !strings.Contains(c.Body, "argus-fp:"+fid(1)) {
		t.Errorf("inline body missing its marker:\n%s", c.Body)
	}
	var body string
	json.Unmarshal(req["body"], &body)
	for _, want := range []string{"3 new finding(s)", "argus-fp:" + fid(2), "argus-fp:" + fid(3), "arn:aws:s3:::bucket"} {
		if !strings.Contains(body, want) {
			t.Errorf("review body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "argus-fp:"+fid(1)) {
		t.Errorf("inline finding duplicated into the review body:\n%s", body)
	}
}

// TestPostIdempotent: markers already on the PR (inline comment or review
// body) suppress re-posting those findings; only the genuinely new one goes.
func TestPostIdempotent(t *testing.T) {
	f := newFakeGitHub(t)
	f.files = dbPatchFiles()
	f.comments = []string{"old comment\n<!-- argus-fp:" + fid(1) + " -->"}
	f.reviews = []string{"old review\n<!-- argus-fp:" + fid(2) + " -->"}

	res, err := Post(context.Background(), f.opts(), threeFindings())
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if res.Inline != 0 || res.InBody != 1 || res.Duplicate != 2 {
		t.Errorf("result = %+v, want 0 inline, 1 in body, 2 duplicate", res)
	}
	if len(f.posted) != 1 {
		t.Fatalf("posted %d reviews, want 1", len(f.posted))
	}
	var body string
	json.Unmarshal(f.posted[0]["body"], &body)
	if !strings.Contains(body, "argus-fp:"+fid(3)) || strings.Contains(body, "argus-fp:"+fid(1)) {
		t.Errorf("re-post filtered wrong:\n%s", body)
	}
}

// TestPostAllDuplicates: nothing new means NO review at all, not an empty one.
func TestPostAllDuplicates(t *testing.T) {
	f := newFakeGitHub(t)
	f.files = dbPatchFiles()
	f.comments = []string{
		"<!-- argus-fp:" + fid(1) + " -->",
		"<!-- argus-fp:" + fid(2) + " --> and <!-- argus-fp:" + fid(3) + " -->",
	}
	res, err := Post(context.Background(), f.opts(), threeFindings())
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if res.Duplicate != 3 || res.Inline != 0 || res.InBody != 0 {
		t.Errorf("result = %+v, want 3 duplicates only", res)
	}
	if len(f.posted) != 0 {
		t.Errorf("posted %d reviews, want none", len(f.posted))
	}
}

// TestPostInlineCap: past maxInline, findings overflow to the review body
// instead of producing an unusable wall of comments.
func TestPostInlineCap(t *testing.T) {
	f := newFakeGitHub(t)
	var patch strings.Builder
	patch.WriteString("@@ -1,0 +1,60 @@")
	for i := 0; i < 60; i++ {
		patch.WriteString("\n+line")
	}
	f.files = []map[string]string{{"filename": "app/db.go", "status": "modified", "patch": patch.String()}}

	var findings []model.Finding
	for i := 1; i <= maxInline+5; i++ {
		fd := sastFinding(fid(100 + i))
		fd.Location.StartLine = i
		findings = append(findings, fd)
	}
	res, err := Post(context.Background(), f.opts(), findings)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if res.Inline != maxInline || res.InBody != 5 {
		t.Errorf("result = %+v, want %d inline, 5 in body", res, maxInline)
	}
}

// TestPostAPIFailure: a failing API call surfaces the status code and never
// echoes the response body or the token.
func TestPostAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Resource not accessible, token test-token-value"}`))
	}))
	defer srv.Close()
	opts := Options{Repo: "acme/webapp", PR: 7, Token: "test-token-value", APIBase: srv.URL}
	_, err := Post(context.Background(), opts, threeFindings())
	if err == nil {
		t.Fatal("Post against a 403 API succeeded")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error should carry the status: %v", err)
	}
	if strings.Contains(err.Error(), "test-token-value") || strings.Contains(err.Error(), "Resource not accessible") {
		t.Fatalf("error echoes the token or response body: %v", err)
	}
}

func TestPostOptionValidation(t *testing.T) {
	ctx := context.Background()
	findings := threeFindings()
	for name, opts := range map[string]Options{
		"bad repo":    {Repo: "not-a-repo", PR: 7, Token: "t"},
		"zero pr":     {Repo: "acme/webapp", PR: 0, Token: "t"},
		"empty token": {Repo: "acme/webapp", PR: 7, Token: ""},
	} {
		if _, err := Post(ctx, opts, findings); err == nil {
			t.Errorf("%s: Post succeeded, want validation error", name)
		}
	}
}
