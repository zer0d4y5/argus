// Package snippet captures bounded code frames into findings and owns the
// path-confinement primitive shared with AI triage.
//
// SECURITY-CRITICAL (docs/console-ops.md S4): a finding's file path is
// attacker-controlled (a hostile repo names its own files), so every read is
// confined to the scan root after symlink resolution. Snippets persist into
// run files, so the bounds here are persistence bounds, not just prompt
// bounds: SECRET-category findings never get a snippet (the same rule the
// triage prompt applies — credential material must not be copied into
// .appsec/runs), size is capped per finding and per run, and binary or
// minified content is skipped rather than truncated into garbage.
package snippet

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/leaky-hub/argus/internal/model"
)

const (
	// contextLines is how far the frame extends above and below the flagged
	// range before the line cap applies.
	contextLines = 3
	// maxLines bounds one finding's frame (docs/console-ops.md §12.4).
	maxLines = 10
	// maxBytesPerFinding bounds one frame's stored size.
	maxBytesPerFinding = 2048
	// MaxBytesPerRun bounds the total snippet bytes added to one run; once
	// reached, remaining findings stay snippet-less (never partially cut).
	MaxBytesPerRun = 1 << 20
	// maxStoredLineRunes truncates stored lines (matches triage's cap).
	maxStoredLineRunes = 240
	// minifiedLineRunes: any window line longer than this marks the file as
	// minified/generated and the whole frame is skipped.
	minifiedLineRunes = 500
	// maxScannedLineBytes guards the scanner buffer; a longer line is not
	// source code a human frame helps with.
	maxScannedLineBytes = 1 << 20
)

// Capture fills Location.Snippet in place for every eligible finding. It is
// called after the pipeline completes and before the run is saved — a
// snippet is presentation context, never finding identity (fingerprints are
// computed long before this runs). Failures are per-finding and silent by
// design: an unreadable, escaping, binary, or minified file simply yields no
// snippet, exactly like a pre-1.4.0 run.
func Capture(root string, findings []model.Finding) {
	budget := MaxBytesPerRun
	for i := range findings {
		if budget <= 0 {
			return
		}
		f := &findings[i]
		// SECRET findings are metadata-only in run files, always (S4).
		if f.Category == model.CategorySecret {
			continue
		}
		if f.Location.File == "" || f.Location.StartLine <= 0 {
			continue
		}
		sn, err := captureOne(root, *f)
		if err != nil || sn == nil {
			continue
		}
		size := 0
		for _, l := range sn.Lines {
			size += len(l)
		}
		if size > budget {
			return
		}
		budget -= size
		f.Location.Snippet = sn
	}
}

// captureOne reads one finding's frame. It returns (nil, nil) when the file
// is ineligible (binary, minified, window empty) and an error when it is
// unreadable or escapes the root.
func captureOne(root string, f model.Finding) (*model.Snippet, error) {
	path, err := ContainedPath(root, f.Location.File)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	start := f.Location.StartLine - contextLines
	if start < 1 {
		start = 1
	}
	flaggedEnd := f.Location.EndLine
	if flaggedEnd < f.Location.StartLine {
		flaggedEnd = f.Location.StartLine
	}
	end := flaggedEnd + contextLines
	if end-start+1 > maxLines {
		end = start + maxLines - 1
	}

	var lines []string
	bytes := 0
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), maxScannedLineBytes)
	line := 0
	for sc.Scan() {
		line++
		if line < start {
			continue
		}
		if line > end {
			break
		}
		text := sc.Text()
		// Binary and minified content is skipped whole, never truncated into
		// a misleading frame.
		if strings.ContainsRune(text, 0) {
			return nil, nil
		}
		if len([]rune(text)) > minifiedLineRunes {
			return nil, nil
		}
		text = truncateRunes(text, maxStoredLineRunes)
		if bytes+len(text) > maxBytesPerFinding {
			break
		}
		bytes += len(text)
		lines = append(lines, text)
	}
	if err := sc.Err(); err != nil {
		// bufio.ErrTooLong ⇒ a >1MiB line ⇒ not human-readable source.
		return nil, nil
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return &model.Snippet{StartLine: start, Lines: lines}, nil
}

// ContainedPath resolves a finding path (following symlinks) and guarantees
// the result stays inside the scan root. Shared by snippet capture and AI
// triage — ONE confinement implementation, not two.
//
// Scanners report file paths exactly as the scan was invoked — relative to
// the process CWD including the scan-target prefix ("testdata/iac/main.tf"
// when scanning testdata/iac), or absolute when the target was an absolute
// path. So the path resolves relative to the process CWD, NOT by joining it
// onto the scan root. Containment is unchanged either way: after symlink
// resolution the file must still be inside the resolved scan root, wherever
// the path pointed syntactically.
func ContainedPath(root, file string) (string, error) {
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
