package prcomment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// repoPattern is the closed grammar for an "owner/name" reference, the same
// shape config validation accepts for ticketing.
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

// markerPattern extracts argus fingerprint markers from comment bodies. The
// fingerprint is exactly 32 hex chars (model.Fingerprint); anything else in a
// marker-looking string is ignored.
var markerPattern = regexp.MustCompile(`<!-- argus-fp:([0-9a-f]{32}) -->`)

// maxPages bounds every paginated GET. 10 pages of 100 covers any PR a human
// will review; a bigger PR gets bounded, not unbounded, behavior.
const maxPages = 10

// bodyLimit caps most API response reads. filesBodyLimit is larger because
// the files endpoint inlines unified-diff patches.
const (
	bodyLimit      = 1 << 20  // 1 MiB
	filesBodyLimit = 20 << 20 // 20 MiB
)

// client is a minimal hand-rolled GitHub REST client, deliberately mirroring
// internal/server's issue client: bearer header only, bounded reads, bounded
// error strings that never echo response bodies or the token.
type client struct {
	base  string
	repo  string
	pr    int
	token string
	http  *http.Client
}

func newClient(opts Options) (*client, error) {
	if !repoPattern.MatchString(opts.Repo) {
		return nil, fmt.Errorf("prcomment: repository must be \"owner/name\", got %q", opts.Repo)
	}
	if opts.PR <= 0 {
		return nil, fmt.Errorf("prcomment: pull request number must be positive")
	}
	if opts.Token == "" {
		return nil, fmt.Errorf("prcomment: empty token")
	}
	base := opts.APIBase
	if base == "" {
		base = "https://api.github.com"
	}
	return &client{
		base:  base,
		repo:  opts.Repo,
		pr:    opts.PR,
		token: opts.Token,
		http:  &http.Client{Timeout: 20 * time.Second},
	}, nil
}

// do issues one request with the standard headers and returns the response
// body (bounded by limit) when the status matches want. Errors are bounded
// and carry the HTTP status, never the response body or the token.
func (c *client) do(ctx context.Context, method, path string, payload []byte, limit int64, want int, what string) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, fmt.Errorf("prcomment: %s: build request", what)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prcomment: %s: request failed (network)", what)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	if resp.StatusCode != want {
		return nil, fmt.Errorf("prcomment: %s failed (HTTP %d)", what, resp.StatusCode)
	}
	return data, nil
}

// prPath is the API path prefix for this pull request.
func (c *client) prPath() string {
	return "/repos/" + c.repo + "/pulls/" + strconv.Itoa(c.pr)
}

// headSHA fetches the PR's head commit, the commit_id a review anchors to.
func (c *client) headSHA(ctx context.Context) (string, error) {
	data, err := c.do(ctx, http.MethodGet, c.prPath(), nil, bodyLimit, http.StatusOK, "fetch pull request")
	if err != nil {
		return "", err
	}
	var out struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Head.SHA == "" {
		return "", fmt.Errorf("prcomment: fetch pull request: unexpected response shape")
	}
	return out.Head.SHA, nil
}

// changedFiles fetches the PR's changed files and parses each patch into the
// set of new-side lines a review comment may attach to.
func (c *client) changedFiles(ctx context.Context) (diffLines, error) {
	diff := diffLines{}
	for page := 1; page <= maxPages; page++ {
		path := c.prPath() + "/files?per_page=100&page=" + strconv.Itoa(page)
		data, err := c.do(ctx, http.MethodGet, path, nil, filesBodyLimit, http.StatusOK, "fetch pull request files")
		if err != nil {
			return nil, err
		}
		var files []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
			Patch    string `json:"patch"`
		}
		if err := json.Unmarshal(data, &files); err != nil {
			return nil, fmt.Errorf("prcomment: fetch pull request files: unexpected response shape")
		}
		for _, f := range files {
			// A removed file has no new side; a file with no patch (binary,
			// or too large for the API to inline) has no commentable lines.
			if f.Status == "removed" || f.Patch == "" {
				continue
			}
			diff[f.Filename] = commentableLines(f.Patch)
		}
		if len(files) < 100 {
			break
		}
	}
	return diff, nil
}

// postedMarkers collects the fingerprints argus already posted on this PR,
// from inline review comments and from review bodies (where non-inline
// findings are listed). This is what makes re-posting idempotent.
func (c *client) postedMarkers(ctx context.Context) (map[string]struct{}, error) {
	posted := map[string]struct{}{}
	collect := func(bodies []string) {
		for _, b := range bodies {
			for _, m := range markerPattern.FindAllStringSubmatch(b, -1) {
				posted[m[1]] = struct{}{}
			}
		}
	}
	for _, src := range []struct{ suffix, what string }{
		{"/comments", "list pull request comments"},
		{"/reviews", "list pull request reviews"},
	} {
		for page := 1; page <= maxPages; page++ {
			path := c.prPath() + src.suffix + "?per_page=100&page=" + strconv.Itoa(page)
			data, err := c.do(ctx, http.MethodGet, path, nil, filesBodyLimit, http.StatusOK, src.what)
			if err != nil {
				return nil, err
			}
			var items []struct {
				Body string `json:"body"`
			}
			if err := json.Unmarshal(data, &items); err != nil {
				return nil, fmt.Errorf("prcomment: %s: unexpected response shape", src.what)
			}
			bodies := make([]string, 0, len(items))
			for _, it := range items {
				bodies = append(bodies, it.Body)
			}
			collect(bodies)
			if len(items) < 100 {
				break
			}
		}
	}
	return posted, nil
}

// reviewComment is one inline comment in the batched review, in the shape
// the reviews API expects.
type reviewComment struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Side string `json:"side"`
	Body string `json:"body"`
}

// postReview publishes the batched review: one API call, event COMMENT (never
// APPROVE or REQUEST_CHANGES: the severity gate is the verdict, this is the
// explanation).
func (c *client) postReview(ctx context.Context, commitID, body string, comments []reviewComment) error {
	if comments == nil {
		comments = []reviewComment{}
	}
	payload, err := json.Marshal(map[string]any{
		"commit_id": commitID,
		"event":     "COMMENT",
		"body":      body,
		"comments":  comments,
	})
	if err != nil {
		return fmt.Errorf("prcomment: post review: encode")
	}
	_, err = c.do(ctx, http.MethodPost, c.prPath()+"/reviews", payload, bodyLimit, http.StatusOK, "post review")
	return err
}
