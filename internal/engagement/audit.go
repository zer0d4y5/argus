package engagement

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Audit is the engagement's tamper-evident, append-only action log. Each entry
// is hash-chained to its predecessor: hash = SHA-256(prevHash || core), where
// core is the canonical JSON of the entry's own fields. Any edit, reordering, or
// truncation of a prior line breaks the chain, which Verify detects and reports.
//
// It is the operator's evidence that testing stayed in bounds, so it records the
// permitted requests, the refusals (out-of-scope, budget-exhausted,
// window-closed, destructive-blocked), the confirmation steps, and credential
// USE - by env-var name and authenticated username only, NEVER a secret value or
// a response body, mirroring the finding-metadata discipline.
type Audit struct {
	path string
	mu   sync.Mutex
	last string // hex hash of the last entry; "" before the first
	seq  int64
	now  func() time.Time
}

// Audit event names, a closed vocabulary so the trail is greppable.
const (
	EventEngagementCreate = "engagement.create"
	EventScanStart        = "scan.start"
	EventScanFinish       = "scan.finish"
	EventRequest          = "request"           // an in-process request permitted by the gate
	EventToolDispatch     = "tool.dispatch"     // a subprocess engine dispatched against an endpoint
	EventRefused          = "refused"           // the gate refused a request (details.reason)
	EventAuthSuccess      = "auth.success"      // authenticated (details.user, never a secret)
	EventCredentialUse    = "credential.use"    // a credential referenced by env-var name was used
	EventDestructiveBlock = "destructive.block" // a destructive action was refused by the interlock
	EventDestructiveAllow = "destructive.allow" // a destructive action passed the double interlock
)

// Refusal reasons.
const (
	ReasonOutOfScope    = "out-of-scope"
	ReasonWindowClosed  = "window-closed"
	ReasonBudget        = "budget-exhausted"
	ReasonDestructive   = "destructive-not-authorized"
	ReasonHardForbidden = "hard-forbidden"
)

// chainCore is the hashed portion of an entry: everything except the resulting
// hash. Field order is fixed and json.Marshal sorts the details map, so the
// serialization is stable and reproducible for Verify.
type chainCore struct {
	Seq      int64             `json:"seq"`
	Time     time.Time         `json:"time"`
	Event    string            `json:"event"`
	Details  map[string]string `json:"details,omitempty"`
	PrevHash string            `json:"prevHash"`
}

// Entry is one persisted audit line: the core plus its chain hash.
type Entry struct {
	chainCore
	Hash string `json:"hash"`
}

// OpenAudit opens (creating on first write) the audit log at path and rewinds to
// its current chain head, so appends continue an existing chain. A corrupt tail
// is not repaired here; Verify surfaces it.
func OpenAudit(path string) (*Audit, error) {
	a := &Audit{path: path, now: func() time.Time { return time.Now().UTC() }}
	entries, err := readEntries(path)
	if err != nil {
		return nil, err
	}
	if n := len(entries); n > 0 {
		a.last = entries[n-1].Hash
		a.seq = entries[n-1].Seq
	}
	return a, nil
}

// Append adds one entry, extending the hash chain. A write failure is returned
// to the caller, which decides what it means (a scan warns loudly but does not
// unwind the action that already happened).
func (a *Audit) Append(event string, details map[string]string) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	a.seq++
	core := chainCore{
		Seq:      a.seq,
		Time:     a.now(),
		Event:    event,
		Details:  details,
		PrevHash: a.last,
	}
	sum, err := hashCore(core)
	if err != nil {
		a.seq--
		return err
	}
	entry := Entry{chainCore: core, Hash: sum}
	line, err := json.Marshal(entry)
	if err != nil {
		a.seq--
		return fmt.Errorf("audit: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		a.seq--
		return fmt.Errorf("audit: mkdir: %w", err)
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		a.seq--
		return fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		a.seq--
		return fmt.Errorf("audit: append: %w", err)
	}
	a.last = sum
	return nil
}

// hashCore computes hex(SHA-256(canonicalJSON(core))). PrevHash is a field of
// core, so the chain linkage is inside the hash.
func hashCore(core chainCore) (string, error) {
	b, err := json.Marshal(core)
	if err != nil {
		return "", fmt.Errorf("audit: hash marshal: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyResult reports the outcome of a chain check.
type VerifyResult struct {
	OK      bool   // the chain is intact
	Entries int    // number of entries checked
	BadSeq  int64  // 1-based seq of the first broken entry (0 when OK)
	Reason  string // human explanation of the break (empty when OK)
}

// Verify walks the audit file and confirms every entry's hash and its linkage to
// the previous entry. A single altered byte, a removed line, or a reordering
// breaks the recomputed hash or the prevHash linkage and is reported.
func Verify(path string) (VerifyResult, error) {
	entries, err := readEntries(path)
	if err != nil {
		return VerifyResult{}, err
	}
	prev := ""
	var prevSeq int64
	for i, e := range entries {
		if e.PrevHash != prev {
			return VerifyResult{Entries: i, BadSeq: e.Seq, Reason: "prevHash does not link to the previous entry"}, nil
		}
		if e.Seq != prevSeq+1 {
			return VerifyResult{Entries: i, BadSeq: e.Seq, Reason: fmt.Sprintf("sequence gap: expected %d, got %d", prevSeq+1, e.Seq)}, nil
		}
		want, err := hashCore(e.chainCore)
		if err != nil {
			return VerifyResult{}, err
		}
		if want != e.Hash {
			return VerifyResult{Entries: i, BadSeq: e.Seq, Reason: "entry hash does not match its contents (tampered)"}, nil
		}
		prev = e.Hash
		prevSeq = e.Seq
	}
	return VerifyResult{OK: true, Entries: len(entries)}, nil
}

// readEntries loads all parseable audit lines in order. A missing file is an
// empty log. A line that does not parse as JSON is reported as a break rather
// than silently skipped, because in a tamper-evident log a garbled line IS the
// signal.
func readEntries(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()

	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("audit: unparseable line (log integrity compromised): %w", err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: read: %w", err)
	}
	return out, nil
}
