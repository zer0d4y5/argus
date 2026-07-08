package snippet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func numberedLines(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		b.WriteString(strings.Repeat("x", 5))
		b.WriteString("\n")
	}
	return b.String()
}

func finding(file string, start, end int, category string) model.Finding {
	return model.Finding{
		Category: category,
		Location: model.Location{File: file, StartLine: start, EndLine: end},
	}
}

func TestCaptureBasicFrame(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.py"), "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\n")

	fs := []model.Finding{finding(filepath.Join(root, "a.py"), 6, 6, model.CategorySAST)}
	Capture(root, fs)

	sn := fs[0].Location.Snippet
	if sn == nil {
		t.Fatal("expected a snippet")
	}
	if sn.StartLine != 3 {
		t.Errorf("startLine = %d, want 3 (flagged 6 minus 3 context)", sn.StartLine)
	}
	want := []string{"l3", "l4", "l5", "l6", "l7", "l8", "l9"}
	if len(sn.Lines) != len(want) {
		t.Fatalf("lines = %q, want %q", sn.Lines, want)
	}
	for i := range want {
		if sn.Lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, sn.Lines[i], want[i])
		}
	}
}

func TestCaptureClampsToMaxLines(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), numberedLines(100))

	// Flagged range 10..90 is far beyond the frame cap.
	fs := []model.Finding{finding(filepath.Join(root, "a.go"), 10, 90, model.CategorySAST)}
	Capture(root, fs)

	sn := fs[0].Location.Snippet
	if sn == nil {
		t.Fatal("expected a snippet")
	}
	if len(sn.Lines) > 10 {
		t.Errorf("frame has %d lines, cap is 10", len(sn.Lines))
	}
	if sn.StartLine != 7 {
		t.Errorf("startLine = %d, want 7", sn.StartLine)
	}
}

func TestSecretFindingsNeverGetSnippets(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "creds.env"), "AWS_KEY=AKIA1234567890EXAMPLE\n")

	fs := []model.Finding{finding(filepath.Join(root, "creds.env"), 1, 1, model.CategorySecret)}
	Capture(root, fs)

	if fs[0].Location.Snippet != nil {
		t.Fatal("SECRET finding must never carry a snippet (S4)")
	}
}

func TestSymlinkEscapeYieldsNoSnippet(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.txt"), "outside contents\n")
	root := t.TempDir()
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	fs := []model.Finding{finding(link, 1, 1, model.CategorySAST)}
	Capture(root, fs)

	if fs[0].Location.Snippet != nil {
		t.Fatal("symlink escaping the root must not produce a snippet")
	}
}

func TestBinaryFileSkipped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "blob.bin"), "line1\nli\x00ne2\nline3\n")

	fs := []model.Finding{finding(filepath.Join(root, "blob.bin"), 2, 2, model.CategorySAST)}
	Capture(root, fs)

	if fs[0].Location.Snippet != nil {
		t.Fatal("binary content must be skipped whole")
	}
}

func TestMinifiedFileSkipped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.min.js"), "short\n"+strings.Repeat("a", 600)+"\nshort\n")

	fs := []model.Finding{finding(filepath.Join(root, "app.min.js"), 1, 1, model.CategorySAST)}
	Capture(root, fs)

	if fs[0].Location.Snippet != nil {
		t.Fatal("minified content must be skipped whole")
	}
}

func TestLongLinesTruncated(t *testing.T) {
	root := t.TempDir()
	// 400 runes: below the minified cutoff, above the stored cap.
	writeFile(t, filepath.Join(root, "wide.go"), strings.Repeat("b", 400)+"\n")

	fs := []model.Finding{finding(filepath.Join(root, "wide.go"), 1, 1, model.CategorySAST)}
	Capture(root, fs)

	sn := fs[0].Location.Snippet
	if sn == nil {
		t.Fatal("expected a snippet")
	}
	if got := len([]rune(sn.Lines[0])); got > maxStoredLineRunes+1 { // +1 for the ellipsis
		t.Errorf("stored line is %d runes, cap %d", got, maxStoredLineRunes)
	}
}

func TestNonexistentAndUnlocatedSkipped(t *testing.T) {
	root := t.TempDir()
	fs := []model.Finding{
		finding(filepath.Join(root, "missing.go"), 3, 3, model.CategorySAST),
		finding("", 0, 0, model.CategorySCA), // no location (e.g. lockfile-wide SCA)
	}
	Capture(root, fs)
	for i, f := range fs {
		if f.Location.Snippet != nil {
			t.Errorf("finding %d should have no snippet", i)
		}
	}
}

func TestPerRunBudgetStopsCapture(t *testing.T) {
	root := t.TempDir()
	// Each frame stores 10 lines × ~200 bytes ≈ 2000 bytes (below the 2 KiB
	// per-finding cap). 600 findings ≈ 1.2 MiB demanded > 1 MiB budget.
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString(strings.Repeat("y", 200))
		b.WriteString("\n")
	}
	writeFile(t, filepath.Join(root, "big.go"), b.String())

	fs := make([]model.Finding, 600)
	for i := range fs {
		// Wide flagged range ⇒ the full 10-line frame ⇒ ~2000 bytes each.
		fs[i] = finding(filepath.Join(root, "big.go"), 8, 12, model.CategorySAST)
	}
	Capture(root, fs)

	total := 0
	captured := 0
	for _, f := range fs {
		if sn := f.Location.Snippet; sn != nil {
			captured++
			for _, l := range sn.Lines {
				total += len(l)
			}
		}
	}
	if total > MaxBytesPerRun {
		t.Errorf("total snippet bytes %d exceed the per-run budget %d", total, MaxBytesPerRun)
	}
	if captured == 0 || captured == len(fs) {
		t.Errorf("expected the budget to bite partway: captured %d of %d", captured, len(fs))
	}
}

func TestContainedPathRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "in.txt"), "inside\n")
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "out.txt"), "outside\n")

	if _, err := ContainedPath(root, filepath.Join(root, "in.txt")); err != nil {
		t.Errorf("in-root path rejected: %v", err)
	}
	if _, err := ContainedPath(root, filepath.Join(outside, "out.txt")); err == nil {
		t.Error("out-of-root path accepted")
	}
	if _, err := ContainedPath(root, filepath.Join(root, "..", "elsewhere")); err == nil {
		t.Error("dot-dot path accepted")
	}
}
