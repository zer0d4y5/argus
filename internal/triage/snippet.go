package triage

// Snippet extraction reads scanned source from disk to give the model
// context. Security constraints: the finding's file path is attacker-
// controlled (a hostile repo names its own files), so reads are confined to
// the scan root after symlink resolution — a symlink pointing at
// ~/.aws/credentials must not leak file contents into a prompt (and, with a
// cloud provider, off the machine). Paths resolve relative to the process
// CWD, matching how scanners report them (see snippet.ContainedPath). Output is
// bounded in lines, line length, and total bytes.

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/leaky-hub/argus/internal/model"
	"github.com/leaky-hub/argus/internal/snippet"
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
	path, err := snippet.ContainedPath(root, f.Location.File)
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

// Path confinement lives in internal/snippet (snippet.ContainedPath): ONE
// symlink-resolving containment implementation shared by prompt snippets and
// persisted run-file snippets.

func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}
