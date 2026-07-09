// Package prcomment posts new-since-baseline findings as review comments on
// a GitHub pull request. This is the CI adoption loop closing: the baseline
// keeps the backlog out of the gate, and this package puts exactly the delta
// (what the PR adds) in front of the developer, on the changed lines.
//
// Design rules, in order:
//
//   - Advisory only. Posting never changes the scan's exit code: the gate is
//     the gate. Every failure here is a warning on stderr.
//   - One batched review per run (POST /pulls/{n}/reviews with the whole
//     comment set), never N single comments: atomic, quiet, rate-limit kind.
//   - Idempotent. Every posted finding carries an invisible HTML marker with
//     its stable fingerprint; a re-push re-scans without duplicating comments.
//   - Inline only where GitHub allows it: a finding lands on its line only if
//     that (path, line) is present on the new side of the PR diff. Everything
//     else (cloud findings, lines outside hunks) rolls into the review body,
//     so the API never 422s on out-of-diff positions by construction.
//   - SECRET findings get a minimal body (severity, rule, category): never a
//     description, remediation text, or snippet that could restate matched
//     credential material. Placement (file:line) is already visible in the PR.
//   - The token is read by the caller from the configured env var, used in
//     the Authorization header, and never stored, logged, or echoed in errors.
package prcomment

import (
	"context"
	"fmt"

	"github.com/zer0d4y5/argus/internal/model"
)

// maxInline caps the inline comments in one review. A review with hundreds of
// comments is unusable and risks API rejection; overflow findings are still
// reported, in the review body.
const maxInline = 50

// maxSummaryRows caps the review-body table. Beyond it the body says how many
// more there are (no silent truncation).
const maxSummaryRows = 30

// Options identifies the pull request to comment on.
type Options struct {
	Repo    string // "owner/name"
	PR      int    // pull request number
	Token   string // bearer token; header-only, never logged
	APIBase string // "" = https://api.github.com (tests and GHES override)
}

// Result reports what a Post did, for the CLI's stderr note.
type Result struct {
	Inline    int // findings posted as inline comments
	InBody    int // findings listed in the review body only
	Duplicate int // findings skipped: already posted on this PR
}

// Post publishes findings on the pull request as one review. It is the only
// entry point; the caller has already narrowed findings to the set worth
// posting (new since baseline, disposition-filtered). A nil error with an
// all-zero Result means there was nothing new to say and no review was made.
func Post(ctx context.Context, opts Options, findings []model.Finding) (Result, error) {
	c, err := newClient(opts)
	if err != nil {
		return Result{}, err
	}

	// Dedupe within the run (correlation should have merged same-ID findings
	// already; defense in depth), then against everything argus previously
	// posted on this PR, inline or in a review body.
	findings = dedupeByID(findings)
	posted, err := c.postedMarkers(ctx)
	if err != nil {
		return Result{}, err
	}
	var fresh []model.Finding
	dup := 0
	for _, f := range findings {
		if f.ID != "" {
			if _, ok := posted[f.ID]; ok {
				dup++
				continue
			}
		}
		fresh = append(fresh, f)
	}
	if len(fresh) == 0 {
		return Result{Duplicate: dup}, nil
	}

	headSHA, err := c.headSHA(ctx)
	if err != nil {
		return Result{}, err
	}
	diff, err := c.changedFiles(ctx)
	if err != nil {
		return Result{}, err
	}

	// Partition: inline where the finding's (file, line) is on the new side
	// of the diff, review body for everything else, with a hard inline cap.
	var inline []model.Finding
	var body []model.Finding
	for _, f := range fresh {
		if len(inline) < maxInline && diff.commentable(f.Location.File, f.Location.StartLine) {
			inline = append(inline, f)
			continue
		}
		body = append(body, f)
	}

	comments := make([]reviewComment, 0, len(inline))
	for _, f := range inline {
		comments = append(comments, reviewComment{
			Path: f.Location.File,
			Line: f.Location.StartLine,
			Side: "RIGHT",
			Body: inlineBody(f),
		})
	}
	review := summaryBody(len(inline), body)
	if err := c.postReview(ctx, headSHA, review, comments); err != nil {
		return Result{}, err
	}
	return Result{Inline: len(inline), InBody: len(body), Duplicate: dup}, nil
}

// dedupeByID keeps the first finding per fingerprint; empty-ID findings are
// kept as-is (they cannot be matched, so they must not shadow each other).
func dedupeByID(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if f.ID != "" {
			if _, dup := seen[f.ID]; dup {
				continue
			}
			seen[f.ID] = struct{}{}
		}
		out = append(out, f)
	}
	return out
}

// String renders the result for the CLI's stderr note.
func (r Result) String() string {
	return fmt.Sprintf("%d inline, %d in review body, %d already posted", r.Inline, r.InBody, r.Duplicate)
}
