package scanner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leaky-hub/appsec/internal/model"
)

func rawSecret(rule, file string, line int, desc string) model.RawFinding {
	return model.RawFinding{
		Tool: "gitleaks", Category: model.CategorySecret,
		RuleID: rule, File: file, StartLine: line, EndLine: line,
		Description: desc,
		Meta:        map[string]string{"entropy": "4.20"},
	}
}

func TestMergeGitHistory(t *testing.T) {
	worktree := []model.RawFinding{rawSecret("aws-access-token", "config.env", 3, "AWS")}

	stillPresent := rawSecret("aws-access-token", "config.env", 7, "AWS") // same rule+file, older line
	rotated := rawSecret("github-pat", "deploy/old.env", 2, "GitHub PAT")
	rotated.Meta["commit"] = "0123456789abcdef0123456789abcdef01234567"
	rotatedDup := rotated // same rule+file+line in a second commit
	rotatedDup.Meta = map[string]string{"commit": "fedcba9876543210fedcba9876543210fedcba98", "entropy": "4.20"}

	out := mergeGitHistory(worktree, []model.RawFinding{stillPresent, rotated, rotatedDup}, false)
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2 (worktree + one history-only)", len(out))
	}
	// The worktree finding is untouched — no history label.
	if out[0].Meta["gitHistory"] != "" {
		t.Error("worktree finding must not be labeled gitHistory")
	}
	h := out[1]
	if h.Meta["gitHistory"] != "true" || h.Meta["commit"] == "" {
		t.Errorf("history-only finding must carry gitHistory+commit, got %v", h.Meta)
	}
	if !strings.Contains(h.Description, "rotate the credential") ||
		!strings.Contains(h.Description, "0123456789ab") {
		t.Errorf("history description must say rotation + commit, got %q", h.Description)
	}
	if strings.Contains(h.Description, "shallow") {
		t.Error("non-shallow repo must not claim shallow-limited history")
	}

	// Shallow clones say so — single-commit history is not full history.
	out = mergeGitHistory(nil, []model.RawFinding{rotated}, true)
	if out[0].Meta["gitShallow"] != "true" || !strings.Contains(out[0].Description, "single commit") {
		t.Errorf("shallow history finding must say so, got %v / %q", out[0].Meta, out[0].Description)
	}
}

func TestGitHistoryEligible(t *testing.T) {
	dir := t.TempDir()
	if GitHistoryEligible(dir) {
		t.Error("plain directory must not be history-eligible")
	}
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !GitHistoryEligible(dir) {
		t.Error(".git directory must enable history mode")
	}
	file := filepath.Join(dir, "f.txt")
	os.WriteFile(file, nil, 0o644)
	if GitHistoryEligible(file) {
		t.Error("file targets must never be history-eligible")
	}
	if GitShallow(dir) {
		t.Error("no shallow marker → not shallow")
	}
	os.WriteFile(filepath.Join(dir, ".git", "shallow"), nil, 0o644)
	if !GitShallow(dir) {
		t.Error(".git/shallow must mark the repo shallow")
	}
}

// TestGitleaksHistorySmoke runs the real gitleaks against a real git repo in
// which a secret was committed and then deleted: the worktree pass cannot see
// it, the history pass must — labeled, and with the secret value scrubbed
// (S4 extension: history scanning must not exfiltrate secret material into
// findings). Skipped in -short mode and when git/gitleaks are missing.
func TestGitleaksHistorySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("invokes real git + gitleaks")
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}

	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	// A fake, randomly-generated AWS-shaped key. NOT the canonical
	// AKIAIOSFODNN7EXAMPLE — gitleaks allowlists that one, so this test would
	// pass vacuously (worktree AND history both empty).
	const planted = "AKIAQ3EGRJ7NWNKV4XSM"
	run("init", "-q")
	os.WriteFile(filepath.Join(dir, "creds.env"), []byte("AWS_ACCESS_KEY_ID="+planted+"\n"), 0o644)
	run("add", ".")
	run("commit", "-qm", "add creds")
	run("rm", "-q", "creds.env")
	run("commit", "-qm", "remove creds (rotation NOT done)")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	findings, err := (&Gitleaks{}).Scan(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	var history *model.RawFinding
	for i, f := range findings {
		if f.Meta["gitHistory"] == "true" && strings.Contains(f.File, "creds.env") {
			history = &findings[i]
		}
	}
	if history == nil {
		t.Fatalf("no history-labeled finding for the deleted secret; got %d findings: %+v", len(findings), findings)
	}
	if history.Meta["commit"] == "" {
		t.Error("history finding must carry the commit hash")
	}
	// Scrub holds across the history path: the secret value appears nowhere.
	blob, _ := json.Marshal(findings)
	if strings.Contains(string(blob), planted) {
		t.Fatal("plaintext secret leaked through the history scan path")
	}
}
