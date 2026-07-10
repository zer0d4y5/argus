// Package audit is the console's append-only action log:
// <repo>/.appsec/audit.jsonl, one JSON object per line.
//
// Invariants (docs/console-ops.md T10): entries are written server-side
// only; user-controlled strings appear only as JSON string values (the
// encoder escapes them — no line forging); NO password material, session
// tokens, or finding content ever land here. The file is the durable
// record of who did what — job state is in-memory, this is not.
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const auditFileName = "audit.jsonl"

// Event names, kept to a closed vocabulary so the log is greppable.
const (
	EventLoginSuccess   = "login.success"
	EventLoginFailure   = "login.failure"
	EventUserCreate     = "user.create"
	EventUserUpdate     = "user.update"
	EventUserDelete     = "user.delete"
	EventTargetCreate   = "target.create"
	EventTargetUpdate   = "target.update"
	EventTargetDelete   = "target.delete"
	EventScanLaunch     = "scan.launch"
	EventScanFinish     = "scan.finish"
	EventScanExplain    = "scan.explain"
	EventScanRemediate  = "scan.remediate"
	EventScanValidate   = "scan.validate"
	EventSbomGenerate   = "sbom.generate"
	EventRunDelete      = "run.delete"
	EventFindingDispose = "finding.dispose"
	EventTicketCreate   = "ticket.create"
	EventTicketUpdate   = "ticket.update"
	EventTicketDelete   = "ticket.delete"
	EventTicketLink     = "ticket.link"
	EventTicketComment  = "ticket.comment"
	EventThreatModel    = "threat.model"    // create/delete a model
	EventThreatUpdate   = "threat.update"   // add/enumerate/status/link a threat or component
	EventConfigChange   = "config.change"   // admin edited console configuration (e.g. SSO)
	EventCloudRemediate = "cloud.remediate" // admin dry-ran or applied a curated cloud fix
	EventRuleAuthor     = "rule.author"     // admin drafted/tested/saved/deleted a custom semgrep rule
)

// Entry is one audit line.
type Entry struct {
	Time    time.Time         `json:"time"`
	Event   string            `json:"event"`
	Actor   string            `json:"actor,omitempty"` // username; "-" for pre-auth events
	Details map[string]string `json:"details,omitempty"`
}

// Log appends entries to the audit file, creating it 0600 on first write.
type Log struct {
	path string
	mu   sync.Mutex
}

// ForRepo returns the audit log for <repoRoot>/.appsec/audit.jsonl.
func ForRepo(repoRoot string) *Log {
	return &Log{path: filepath.Join(repoRoot, ".appsec", auditFileName)}
}

// Write appends one entry. The caller decides what a write failure means;
// the server warns on stderr but never fails the user action (the action
// already happened — dropping it silently would be worse than logging the
// logging failure loudly).
func (l *Log) Write(event, actor string, details map[string]string) error {
	e := Entry{Time: time.Now().UTC(), Event: event, Actor: actor, Details: details}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return fmt.Errorf("audit: mkdir: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: append: %w", err)
	}
	return nil
}

// Tail returns the last n parseable entries, newest last. A missing file is
// an empty log; a torn or corrupt line is skipped, never fatal.
func (l *Log) Tail(n int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: read: %w", err)
	}
	if n > 0 && len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	return entries, nil
}
