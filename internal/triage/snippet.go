package triage

// Snippet extraction reads scanned source from disk to give the model
// context. Security constraints: the finding's file path is attacker-
// controlled (a hostile repo names its own files), so reads are confined to
// the scan root after symlink resolution — a symlink pointing at
// ~/.aws/credentials must not leak file contents into a prompt (and, with a
// cloud provider, off the machine). Paths resolve relative to the process
// CWD, matching how scanners report them (see containedPath). Output is
// bounded in lines, line length, and total bytes.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
)

const (
	snippetContextLines = 12
	maxSnippetBytes     = 4000
	maxSnippetLineRunes = 240
	maxScannedLineBytes = 1 << 20
)

// extractSnippet returns a line-numbered window around the finding location,
// or ("", nil) when the finding has no usable location. Errors mean the file
// was unreadable or escaped the scan root; callers degrade to metadata-only.
func extractSnippet(root string, f model.Finding) (string, error) {
	if f.Location.File == "" || f.Location.StartLine <= 0 {
		return "", nil
	}
	path, err := containedPath(root, f.Location.File)
	if err != nil {
		return "", err
	}

	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()

	start := f.Location.StartLine - snippetContextLines
	if start < 1 {
		start = 1
	}
	flaggedEnd := f.Location.EndLine
	if flaggedEnd < f.Location.StartLine {
		flaggedEnd = f.Location.StartLine
	}
	end := flaggedEnd + snippetContextLines

	var b strings.Builder
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), maxScannedLineBytes)
	line := 0
	for sc.Scan() {
		line++
		if line < start {
			continue
		}
		if line > end || b.Len() >= maxSnippetBytes {
			break
		}
		marker := "  "
		if line >= f.Location.StartLine && line <= flaggedEnd {
			marker = ">>"
		}
		fmt.Fprintf(&b, "%s%5d | %s\n", marker, line, truncateRunes(sc.Text(), maxSnippetLineRunes))
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return b.String(), nil
}

// containedPath resolves a finding path (following symlinks) and guarantees
// the result stays inside the scan root.
//
// Scanners report file paths exactly as the scan was invoked — relative to
// the process CWD including the scan-target prefix ("testdata/iac/main.tf"
// when scanning testdata/iac), or absolute when the target was an absolute
// path. So the path resolves relative to the process CWD, NOT by joining it
// onto the scan root (the old behavior, which silently broke snippet reads
// for subdirectory and absolute-path scans and degraded triage to
// metadata-only). Containment is unchanged: after symlink resolution the
// file must still be inside the resolved scan root, wherever the path
// pointed syntactically.
func containedPath(root, file string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(filepath.FromSlash(file))
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	relBack, err := filepath.Rel(realRoot, real)
	if err != nil || relBack == ".." || strings.HasPrefix(relBack, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("finding path %q escapes scan root", file)
	}
	return real, nil
}

func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}
