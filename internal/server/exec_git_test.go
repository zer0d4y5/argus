package server

// End-to-end git-target execution: registry entry with a (test-only) file://
// workspace sync, real pipeline, real runstore. Requires gitleaks on PATH —
// skipped otherwise (CI without scanners still runs every boundary test).

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/gitws"
	"github.com/zer0d4y5/argus/internal/jobs"
	"github.com/zer0d4y5/argus/internal/targets"
)

func TestGitTargetScanEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not on PATH")
	}

	// A bare origin with a planted secret in a subdirectory.
	base := t.TempDir()
	bare := filepath.Join(base, "origin.git")
	work := filepath.Join(base, "work")
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git(base, "init", "--bare", "--initial-branch=main", bare)
	git(base, "clone", bare, work)
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The same clearly-fake GitHub PAT the smoke fixture plants (a canonical
	// AWS example key would hit gitleaks's known-example allowlist).
	secretLine := "GITHUB_TOKEN=ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6\n"
	if err := os.WriteFile(filepath.Join(work, "src", "config.env"), []byte(secretLine), 0o644); err != nil {
		t.Fatal(err)
	}
	git(work, "add", ".")
	git(work, "commit", "-m", "plant")
	git(work, "push", "origin", "HEAD:main")

	// Registry with a git target. AddGit refuses file:// by design, so the
	// entry is written the way a tampered/hand-edited file would carry it —
	// which also proves the executor path handles whatever the file says.
	served := t.TempDir()
	reg := targets.ForRepo(served)
	entry := targets.Target{ID: "t-e2e", Name: "remote", Type: targets.TypeGit, URL: "file://" + bare, Branch: "main", Scanners: []string{"gitleaks"}}
	writeRegistry(t, served, entry)

	execFn := ScanExecutor(reg, nil, gitws.NewInsecureFileForTest(), "")
	job := jobs.Job{ID: "j-1", TargetID: "t-e2e", LaunchedBy: "test", Options: jobs.Options{Scope: "src"}}
	var progress []string
	res, err := execFn(context.Background(), job, func(l string) { progress = append(progress, l) })
	if err != nil {
		t.Fatalf("exec: %v\nprogress: %s", err, strings.Join(progress, ""))
	}
	if res.Commit == "" || res.RunID == "" {
		t.Fatalf("result missing provenance: %+v", res)
	}
	joined := strings.Join(progress, "")
	if !strings.Contains(joined, "at commit "+res.Commit) {
		t.Errorf("progress lacks the commit line: %s", joined)
	}

	// The run landed in the WORKSPACE's own store, found the planted secret,
	// and (S4) the SECRET finding carries no snippet.
	ws := reg.Root(entry)
	raw, err := os.ReadFile(filepath.Join(ws, ".appsec", "runs", res.RunID+".json"))
	if err != nil {
		t.Fatalf("run file: %v", err)
	}
	var doc struct {
		Findings []struct {
			Category string `json:"category"`
			Location struct {
				Snippet *json.RawMessage `json:"snippet"`
			} `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) == 0 {
		t.Fatal("planted secret not found by the scoped git scan")
	}
	for _, f := range doc.Findings {
		if f.Category == "SECRET" && f.Location.Snippet != nil {
			t.Fatal("SECRET finding has a snippet in a git-target run file")
		}
	}
}

// writeRegistry writes a targets.json directly (bypassing Add validation) —
// modeling a hand-edited registry file.
func writeRegistry(t *testing.T, repo string, entries ...targets.Target) {
	t.Helper()
	dir := filepath.Join(repo, ".appsec")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"schema": 1, "targets": entries}
	data, _ := json.MarshalIndent(payload, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "targets.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
