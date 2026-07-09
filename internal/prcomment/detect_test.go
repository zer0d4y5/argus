package prcomment

import (
	"errors"
	"testing"
)

// clearActionsEnv pins every env var Resolve consults, so tests behave the
// same on a laptop and inside GitHub Actions (where all three are set).
func clearActionsEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_REF", "")
	t.Setenv("GITHUB_API_URL", "")
}

func TestResolveFromActionsEnv(t *testing.T) {
	clearActionsEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "acme/webapp")
	t.Setenv("GITHUB_REF", "refs/pull/123/merge")
	t.Setenv("GITHUB_API_URL", "https://ghe.example/api/v3")
	repo, pr, base, err := Resolve(0, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if repo != "acme/webapp" || pr != 123 || base != "https://ghe.example/api/v3" {
		t.Errorf("Resolve = %q %d %q", repo, pr, base)
	}
}

func TestResolveFlagBeatsRef(t *testing.T) {
	clearActionsEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "acme/webapp")
	t.Setenv("GITHUB_REF", "refs/pull/123/merge")
	_, pr, _, err := Resolve(7, "")
	if err != nil || pr != 7 {
		t.Errorf("Resolve(flag 7) = %d, %v; want 7, nil", pr, err)
	}
}

// TestResolveEnvRepoBeatsConfig: in CI the current repo is the truth; the
// ticketing config may point at a different tracker repo.
func TestResolveEnvRepoBeatsConfig(t *testing.T) {
	clearActionsEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "acme/webapp")
	repo, _, _, err := Resolve(1, "acme/tracker")
	if err != nil || repo != "acme/webapp" {
		t.Errorf("Resolve = %q, %v; want acme/webapp, nil", repo, err)
	}
}

func TestResolveConfigFallback(t *testing.T) {
	clearActionsEnv(t)
	repo, pr, _, err := Resolve(9, "acme/tracker")
	if err != nil || repo != "acme/tracker" || pr != 9 {
		t.Errorf("Resolve = %q %d, %v", repo, pr, err)
	}
}

func TestResolveNotAPullRequest(t *testing.T) {
	clearActionsEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "acme/webapp")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	_, _, _, err := Resolve(0, "")
	if !errors.Is(err, ErrNotAPullRequest) {
		t.Errorf("push ref: err = %v, want ErrNotAPullRequest", err)
	}
}

func TestResolveNoRepo(t *testing.T) {
	clearActionsEnv(t)
	if _, _, _, err := Resolve(1, ""); err == nil || errors.Is(err, ErrNotAPullRequest) {
		t.Errorf("no repo anywhere: err = %v, want a repo error", err)
	}
}

func TestResolveBadRepo(t *testing.T) {
	clearActionsEnv(t)
	for _, bad := range []string{"no-slash", "a/b/c", "owner/", "own er/repo"} {
		if _, _, _, err := Resolve(1, bad); err == nil || errors.Is(err, ErrNotAPullRequest) {
			t.Errorf("repo %q: err = %v, want a validation error", bad, err)
		}
	}
}
