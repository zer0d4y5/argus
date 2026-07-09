package diffscope

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// mustGit runs git in dir with a pinned identity, failing the test loudly.
func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"-c", "commit.gpgsign=false", "-c", "protocol.file.allow=never"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// repo builds: main with a.go/b.go/gone.go, a feature branch that commits a
// change to a.go, adds sub/c.go, deletes gone.go, then leaves b.go edited
// but uncommitted and d.go untracked. main moves on independently after the
// fork (trunk.go) to prove merge-base semantics.
func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	mustGit(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "a.go", "package a\n")
	write(t, dir, "b.go", "package b\n")
	write(t, dir, "gone.go", "package gone\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-q", "-m", "base")

	mustGit(t, dir, "checkout", "-q", "-b", "feat")
	write(t, dir, "a.go", "package a // changed\n")
	write(t, dir, "sub/c.go", "package sub\n")
	mustGit(t, dir, "rm", "-q", "gone.go")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-q", "-m", "feat work")

	// main moves on after the fork; its file must NOT count as a change.
	mustGit(t, dir, "checkout", "-q", "main")
	write(t, dir, "trunk.go", "package trunk\n")
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-q", "-m", "trunk moved on")
	mustGit(t, dir, "checkout", "-q", "feat")

	// Working-tree edits: uncommitted change and an untracked file.
	write(t, dir, "b.go", "package b // dirty\n")
	write(t, dir, "d.go", "package d\n")
	return dir
}

func TestChangedFiles(t *testing.T) {
	dir := repo(t)
	got, err := ChangedFiles(context.Background(), dir, "main")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	want := []string{"a.go", "b.go", "d.go", "sub/c.go"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ChangedFiles = %v, want %v (deleted gone.go and trunk-only trunk.go excluded)", got, want)
	}
}

func TestChangedFilesRefValidation(t *testing.T) {
	dir := repo(t)
	for _, bad := range []string{"-evil", "--exec=sh", "", "a b", "ref\x00x"} {
		if _, err := ChangedFiles(context.Background(), dir, bad); err == nil {
			t.Errorf("ref %q accepted", bad)
		}
	}
	if _, err := ChangedFiles(context.Background(), dir, "no-such-ref"); err == nil {
		t.Error("unknown ref accepted")
	}
}

func TestChangedFilesNotARepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	if _, err := ChangedFiles(context.Background(), t.TempDir(), "main"); err == nil {
		t.Error("non-repo accepted")
	}
}

func TestMirror(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", "package a\n")
	write(t, root, "sub/c.go", "package sub\n")
	write(t, root, "link-target.txt", "secret\n")
	if err := os.Symlink(filepath.Join(root, "link-target.txt"), filepath.Join(root, "link.go")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	files := []string{"a.go", "sub/c.go", "link.go", "missing.go", "../escape.go", "/abs.go", ".appsec/runs/x.json", ".git/config"}
	dir, skipped, cleanup, err := Mirror(root, files)
	if err != nil {
		t.Fatalf("Mirror: %v", err)
	}
	defer cleanup()

	for rel, content := range map[string]string{"a.go": "package a\n", "sub/c.go": "package sub\n"} {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil || string(data) != content {
			t.Errorf("mirror %s = %q, %v", rel, data, err)
		}
	}
	wantSkipped := []string{"link.go", "missing.go", "../escape.go", "/abs.go", ".appsec/runs/x.json", ".git/config"}
	if !reflect.DeepEqual(skipped, wantSkipped) {
		t.Errorf("skipped = %v, want %v", skipped, wantSkipped)
	}
	// Nothing beyond the two real files made it in, and cleanup removes all.
	var count int
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			count++
		}
		return nil
	})
	if count != 2 {
		t.Errorf("mirror holds %d files, want 2", count)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("cleanup left the mirror behind")
	}
}

func TestContained(t *testing.T) {
	for rel, want := range map[string]bool{
		"a.go":          true,
		"sub/deep/x.tf": true,
		"..":            false,
		"a/../../b":     false,
		"/etc/passwd":   false,
		".git/config":   false,
		".appsec/x":     false,
		"a/.git/hook":   false,
		"./a.go":        false, // not git's clean form
		"":              false,
	} {
		if got := contained(rel); got != want {
			t.Errorf("contained(%q) = %v, want %v", rel, got, want)
		}
	}
}
