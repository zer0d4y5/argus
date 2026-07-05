package targets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path   string
		wantOK bool
	}{
		{dir, true},
		{"relative/path", false},
		{"./also-relative", false},
		{dir + "/..", false},                      // ".." rejected loudly
		{filepath.Join(dir, "..", "x"), false},    // embedded ".."
		{"/", false},                              // filesystem root
		{file, false},                             // not a directory
		{filepath.Join(dir, "does-not-exist"), false},
	}
	for _, c := range cases {
		_, err := ValidatePath(c.path)
		if ok := err == nil; ok != c.wantOK {
			t.Errorf("ValidatePath(%q): err=%v, wantOK=%v", c.path, err, c.wantOK)
		}
	}
}

func TestRegistryLifecycle(t *testing.T) {
	repo := t.TempDir()
	scanDir := t.TempDir()
	r := ForRepo(repo)

	tgt, err := r.Add("payments", scanDir, []string{"gitleaks"}, "fast")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tgt.ID, "t-") {
		t.Errorf("id = %q", tgt.ID)
	}

	// Duplicates by name and by path are refused.
	if _, err := r.Add("payments", t.TempDir(), nil, ""); err == nil {
		t.Error("duplicate name accepted")
	}
	if _, err := r.Add("other", scanDir, nil, ""); err == nil {
		t.Error("duplicate path accepted")
	}
	// Unknown scanner and profile are refused (closed enums).
	if _, err := r.Add("bad-scanner", t.TempDir(), []string{"nmap"}, ""); err == nil {
		t.Error("unknown scanner accepted")
	}
	if _, err := r.Add("bad-profile", t.TempDir(), nil, "yolo"); err == nil {
		t.Error("unknown profile accepted")
	}

	// Get is by ID only — never by name.
	if _, err := r.Get(tgt.ID); err != nil {
		t.Errorf("Get by id: %v", err)
	}
	if _, err := r.Get("payments"); err == nil {
		t.Error("Get resolved a name; the scan API must be ID-only")
	}

	// Registry file is 0600.
	fi, err := os.Stat(filepath.Join(repo, ".appsec", "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("targets.json mode = %v, want 0600", fi.Mode().Perm())
	}

	if _, err := r.Remove(tgt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(tgt.ID); err == nil {
		t.Error("removed target still resolvable")
	}
}
