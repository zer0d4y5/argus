package prcomment

import (
	"regexp"
	"strconv"
	"strings"
)

// diffLines maps a changed file's path (slash-form, relative to repo root,
// exactly how both GitHub and the findings model spell it) to the new-side
// line numbers present in the PR diff.
type diffLines map[string]map[int]struct{}

// commentable reports whether an inline comment may attach to (file, line):
// GitHub accepts a RIGHT-side review comment only on a line the diff shows.
func (d diffLines) commentable(file string, line int) bool {
	if file == "" || line <= 0 {
		return false
	}
	lines, ok := d[file]
	if !ok {
		return false
	}
	_, ok = lines[line]
	return ok
}

// hunkHeader matches a unified-diff hunk header and captures the new-side
// start line: "@@ -12,5 +40,7 @@ optional section".
var hunkHeader = regexp.MustCompile(`^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,[0-9]+)? @@`)

// commentableLines parses the patch fragment GitHub returns per changed file
// and collects the new-side line numbers it shows: context lines and added
// lines. Deleted lines exist only on the old side; "\ No newline at end of
// file" markers are not lines. Malformed input yields fewer commentable lines
// (fails safe: the finding falls back to the review body, never a 422).
func commentableLines(patch string) map[int]struct{} {
	lines := map[int]struct{}{}
	newLine := 0
	inHunk := false
	for _, raw := range strings.Split(patch, "\n") {
		if m := hunkHeader.FindStringSubmatch(raw); m != nil {
			n, err := strconv.Atoi(m[1])
			if err != nil || n <= 0 {
				inHunk = false
				continue
			}
			newLine = n
			inHunk = true
			continue
		}
		if !inHunk || raw == "" {
			continue
		}
		switch raw[0] {
		case '+', ' ':
			lines[newLine] = struct{}{}
			newLine++
		case '-', '\\':
			// old side only, or the no-newline marker: no new-side line
		default:
			// not a diff line: stop trusting counters until the next header
			inHunk = false
		}
	}
	return lines
}
