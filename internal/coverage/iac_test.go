package coverage

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// iacPaths derives the IaC fixture paths from this test file's location.
func iacPaths(t *testing.T) (iacRoot, labelsPath string) {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	repoRoot := filepath.Join(filepath.Dir(self), "..", "..")
	iacRoot = filepath.Join(repoRoot, "testdata", "iac")
	labelsPath = filepath.Join(iacRoot, "labels.json")
	return
}

// requireIaCTools skips when the IaC engines cannot run. Both are required:
// some canaries are only detected by one engine, so a partial toolchain would
// report false misses.
func requireIaCTools(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping IaC coverage scan in -short mode")
	}
	for _, bin := range []string{"checkov", "trivy"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH; skipping IaC coverage scan", bin)
		}
	}
}

// TestLoadIaCLabels validates the manifest without needing the engines — a
// fast unit check that the canary data is well-formed.
func TestLoadIaCLabels(t *testing.T) {
	_, labelsPath := iacPaths(t)
	labels, err := LoadIaCLabels(labelsPath)
	if err != nil {
		t.Fatalf("LoadIaCLabels: %v", err)
	}
	if len(labels) < 3 {
		t.Fatalf("expected >=3 fixture files in manifest, got %d", len(labels))
	}
	for _, l := range labels {
		if l.Kind == "" || l.File == "" {
			t.Errorf("label with empty kind/file: %+v", l)
		}
		if len(l.Canaries) < 3 {
			t.Errorf("%s: expected >=3 misconfig classes, got %d", l.File, len(l.Canaries))
		}
		for _, c := range l.Canaries {
			if c.Name == "" || len(c.Rules) == 0 {
				t.Errorf("%s: canary with empty name/rules", l.File)
			}
		}
	}
}

// TestIaCCoverage is the IaC eagle-eye guard: every planted misconfiguration
// must be detected by at least one IaC engine, via the real adapter path.
func TestIaCCoverage(t *testing.T) {
	requireIaCTools(t)
	iacRoot, labelsPath := iacPaths(t)

	labels, err := LoadIaCLabels(labelsPath)
	if err != nil {
		t.Fatalf("LoadIaCLabels: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	findings, err := ScanIaC(ctx, iacRoot)
	if err != nil {
		t.Fatalf("iac scan: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("iac scan returned no findings at all — adapter wiring broken?")
	}

	if missing := MissingIaCCanaries(labels, DetectedRules(findings)); len(missing) > 0 {
		t.Errorf("IaC engines missed %d canary plant(s):", len(missing))
		for _, m := range missing {
			t.Errorf("  MISS: %s", m)
		}
	}

	// Canaries accept rules from either engine, so full canary coverage alone
	// would not notice one engine going dark. Both engines must produce at
	// least one finding on every fixture format.
	perToolFiles := map[string]map[string]bool{}
	for _, f := range findings {
		files := perToolFiles[f.Tool]
		if files == nil {
			files = map[string]bool{}
			perToolFiles[f.Tool] = files
		}
		files[iacRelPath(f.Location.File)] = true
	}
	for _, tool := range []string{"checkov", "trivy-config"} {
		for _, l := range labels {
			if !perToolFiles[tool][l.File] {
				t.Errorf("%s produced no findings on %s — engine dark on that format?", tool, l.File)
			}
		}
	}
}
