package coverage

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAccount(t *testing.T) {
	root := t.TempDir()
	write(t, root, "src/app.py", []byte("print('hi')\n"))
	write(t, root, "src/lib.rs", []byte("fn main() {}\n"))           // unsupported source
	write(t, root, "deploy/Dockerfile", []byte("FROM scratch\n"))    // iac
	write(t, root, "notes.md", []byte("# notes\n"))                  // secrets-only text
	write(t, root, "blob.bin", []byte{0x7f, 'E', 'L', 'F', 0, 0, 1}) // binary (NUL)
	write(t, root, ".git/config", []byte("[core]\n"))                // skipped dir
	write(t, root, ".appsec/runs/x.json", []byte("{}"))              // skipped dir
	big := make([]byte, OversizeLimitBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	write(t, root, "dump.sql.txt", big) // oversize wins over other buckets

	acc := Account(root)
	if acc.FilesTotal != 6 {
		t.Errorf("filesTotal = %d, want 6 (.git and .appsec never walked)", acc.FilesTotal)
	}
	if acc.SastCovered != 1 || acc.IacConfig != 1 || acc.SecretsOnly != 1 {
		t.Errorf("buckets = sast %d, iac %d, secretsOnly %d; want 1/1/1",
			acc.SastCovered, acc.IacConfig, acc.SecretsOnly)
	}
	if acc.UnsupportedSource != 1 || len(acc.UnsupportedSample) != 1 || acc.UnsupportedSample[0] != "src/lib.rs" {
		t.Errorf("unsupported = %d %v, want 1 [src/lib.rs]", acc.UnsupportedSource, acc.UnsupportedSample)
	}
	if acc.Binary != 1 || acc.Oversize != 1 {
		t.Errorf("binary %d / oversize %d, want 1/1", acc.Binary, acc.Oversize)
	}
	if !acc.GitRepo {
		t.Error("a .git directory under the root must report GitRepo=true (history-eligible)")
	}
}

func TestAccountGitFacts(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	acc := Account(root)
	if !acc.GitRepo || acc.GitShallow {
		t.Errorf("gitRepo/gitShallow = %v/%v, want true/false", acc.GitRepo, acc.GitShallow)
	}
	write(t, root, ".git/shallow", []byte("abc\n"))
	acc = Account(root)
	if !acc.GitShallow {
		t.Error("shallow marker must be reported")
	}
	// File target: accounts exactly that file.
	write(t, root, "one.py", []byte("x=1\n"))
	acc = Account(filepath.Join(root, "one.py"))
	if acc.FilesTotal != 1 || acc.SastCovered != 1 || acc.GitRepo {
		t.Errorf("file-target accounting = %+v", acc)
	}
}
