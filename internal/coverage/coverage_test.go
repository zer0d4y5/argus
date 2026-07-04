package coverage

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/leaky-hub/appsec/internal/scanner"
)

// paths derives repo-relative paths from this test file's location, so the
// test is runnable from any working directory.
func paths(t *testing.T) (polyglotRoot, labelsPath, docsPath string) {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	repoRoot := filepath.Join(filepath.Dir(self), "..", "..")
	polyglotRoot = filepath.Join(repoRoot, "testdata", "polyglot")
	labelsPath = filepath.Join(polyglotRoot, "labels.json")
	docsPath = filepath.Join(repoRoot, "docs", "coverage.md")
	return
}

// requireSemgrep skips the test when the environment cannot run it. Coverage is
// an integration guard: it shells out to semgrep and needs the network on first
// run (to fetch registry packs). Both are unavailable in plain unit CI.
func requireSemgrep(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping coverage scan in -short mode")
	}
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH; skipping coverage scan")
	}
}

// TestLoadLabels validates the manifest without needing semgrep — it is a fast
// unit check that the canary data is well-formed and non-empty per language.
func TestLoadLabels(t *testing.T) {
	_, labelsPath, _ := paths(t)
	labels, err := LoadLabels(labelsPath)
	if err != nil {
		t.Fatalf("LoadLabels: %v", err)
	}
	if len(labels) < 8 {
		t.Fatalf("expected >=8 languages in manifest, got %d", len(labels))
	}
	for _, l := range labels {
		if l.File == "" || len(l.Canaries) == 0 {
			t.Errorf("language %q: empty file or no canaries", l.Language)
		}
		for _, c := range l.Canaries {
			if c.CWE == "" || c.Name == "" {
				t.Errorf("language %q: canary with empty cwe/name", l.Language)
			}
		}
	}
}

// TestPolyglotCoverage is the eagle-eye guard: every canary must be detected
// under the `standard` profile. It also regenerates docs/coverage.md when
// APPSEC_UPDATE_COVERAGE is set, from live standard + max scans.
func TestPolyglotCoverage(t *testing.T) {
	requireSemgrep(t)
	polyglotRoot, labelsPath, docsPath := paths(t)

	labels, err := LoadLabels(labelsPath)
	if err != nil {
		t.Fatalf("LoadLabels: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stdFindings, err := Scan(ctx, scanner.ProfileStandard, polyglotRoot)
	if err != nil {
		t.Fatalf("standard scan: %v", err)
	}
	stdDetected := DetectedCWEs(stdFindings)

	if missing := MissingCanaries(labels, stdDetected); len(missing) > 0 {
		t.Errorf("standard profile missed %d canary plant(s):", len(missing))
		for _, m := range missing {
			t.Errorf("  MISS: %s", m)
		}
	}

	if os.Getenv("APPSEC_UPDATE_COVERAGE") == "" {
		return
	}

	maxFindings, err := Scan(ctx, scanner.ProfileMax, polyglotRoot)
	if err != nil {
		t.Fatalf("max scan: %v", err)
	}

	// The published matrix includes the IaC section from Phase 4 on, so a
	// doc-regenerating run requires the full toolchain — a doc without IaC
	// rows would silently understate coverage.
	for _, bin := range []string{"checkov", "trivy"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("APPSEC_UPDATE_COVERAGE requires %s on PATH (docs/coverage.md includes the IaC section)", bin)
		}
	}
	iacRoot, iacLabelsPath := iacPaths(t)
	iacLabels, err := LoadIaCLabels(iacLabelsPath)
	if err != nil {
		t.Fatalf("LoadIaCLabels: %v", err)
	}
	iacFindings, err := ScanIaC(ctx, iacRoot)
	if err != nil {
		t.Fatalf("iac scan: %v", err)
	}

	md := GenerateMarkdown(labels, stdDetected, DetectedCWEs(maxFindings)) +
		"\n" + GenerateIaCSection(iacLabels, iacFindings)
	if err := os.WriteFile(docsPath, []byte(md), 0o644); err != nil {
		t.Fatalf("write %s: %v", docsPath, err)
	}
	t.Logf("regenerated %s", docsPath)
}
