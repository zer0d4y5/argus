package cloudscan

import (
	"regexp"
	"strings"
	"sync"
)

// tailBuffer keeps a bounded tail of a child's stderr for error reporting.
// Prowler's stderr is ANSI-heavy and can echo account identifiers, so the
// summary strips escape sequences and masks 12-digit account IDs — the
// error path must not leak what the progress path deliberately withholds
// (docs/console-ops.md C3).
type tailBuffer struct {
	mu   sync.Mutex
	tail []byte
}

const tailMax = 2048

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tail = append(b.tail, p...)
	if len(b.tail) > tailMax {
		b.tail = b.tail[len(b.tail)-tailMax:]
	}
	return len(p), nil
}

var (
	ansiSeq   = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	accountID = regexp.MustCompile(`\b\d{12}\b`)
)

// Summary returns the last meaningful stderr line, sanitized and bounded.
func (b *tailBuffer) Summary() string {
	b.mu.Lock()
	text := string(b.tail)
	b.mu.Unlock()

	text = ansiSeq.ReplaceAllString(text, "")
	text = accountID.ReplaceAllString(text, "############")
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 300 {
				l = l[:300] + "…"
			}
			return l
		}
	}
	return "no diagnostic output"
}
