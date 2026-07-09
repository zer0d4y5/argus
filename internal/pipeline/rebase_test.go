package pipeline

import (
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

// TestRebaseRawPaths pins the diff-scope path contract: findings from a
// mirror scan carry exactly the paths a direct scan of the report root would
// have produced, because fingerprints hash the path. Unprefixed and empty
// paths (cloud findings) pass through untouched.
func TestRebaseRawPaths(t *testing.T) {
	raws := []model.RawFinding{
		{File: "/tmp/mirror-x/app/db.go"},
		{File: "/tmp/mirror-x/main.tf"},
		{File: "/tmp/mirror-x"},      // degenerate: the root itself
		{File: "elsewhere/other.go"}, // no mirror prefix: left alone
		{File: ""},                   // cloud finding: no file
	}

	rebased := append([]model.RawFinding(nil), raws...)
	RebaseRawPaths(rebased, "/tmp/mirror-x", ".")
	for i, want := range []string{"app/db.go", "main.tf", "", "elsewhere/other.go", ""} {
		if rebased[i].File != want {
			t.Errorf("rebase to \".\": [%d] = %q, want %q", i, rebased[i].File, want)
		}
	}

	rebased = append([]model.RawFinding(nil), raws...)
	RebaseRawPaths(rebased, "/tmp/mirror-x", "repos/web")
	for i, want := range []string{"repos/web/app/db.go", "repos/web/main.tf", "repos/web", "elsewhere/other.go", ""} {
		if rebased[i].File != want {
			t.Errorf("rebase to dir: [%d] = %q, want %q", i, rebased[i].File, want)
		}
	}
}
