package prcomment

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

// ErrNotAPullRequest means no pull request could be identified: no --pr flag
// and the environment is not a GitHub Actions pull_request run. Callers treat
// it as "nothing to do" (a NOTE, not a WARN), so --pr-comments is safe to
// leave on in a workflow that also runs on push.
var ErrNotAPullRequest = errors.New("not a pull request context")

// pullRef extracts the PR number from a GitHub Actions pull_request ref,
// "refs/pull/123/merge".
var pullRef = regexp.MustCompile(`^refs/pull/([0-9]+)/`)

// Resolve fills in the PR coordinates from explicit inputs and the GitHub
// Actions environment. flagPR beats auto-detection; GITHUB_REPOSITORY beats
// the config repo (in CI the current repo is the truth; the ticketing config
// may point elsewhere). The API base honors GITHUB_API_URL for GHES.
// The token is deliberately NOT resolved here: the caller reads it from the
// configured env var at the last moment, header-only.
func Resolve(flagPR int, configRepo string) (repo string, pr int, apiBase string, err error) {
	repo = os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		repo = configRepo
	}
	if repo == "" {
		return "", 0, "", fmt.Errorf("no repository: set GITHUB_REPOSITORY or ticketing.github.repo in argus.yml")
	}
	if !repoPattern.MatchString(repo) {
		return "", 0, "", fmt.Errorf("repository must be \"owner/name\", got %q", repo)
	}

	pr = flagPR
	if pr == 0 {
		if m := pullRef.FindStringSubmatch(os.Getenv("GITHUB_REF")); m != nil {
			pr, _ = strconv.Atoi(m[1])
		}
	}
	if pr <= 0 {
		return "", 0, "", ErrNotAPullRequest
	}
	return repo, pr, os.Getenv("GITHUB_API_URL"), nil
}
