// Package engagement is the authorization spine of Argus's offensive DAST: no
// active (payload-sending) module runs without an engagement, and every request
// an active module makes is checked against the engagement's scope, throttled by
// its intensity ceiling, and appended to its tamper-evident audit trail.
//
// An Engagement is a first-class, persisted object. It declares:
//
//   - the in-scope hosts / CIDRs / URL-prefixes and the out-of-scope exclusions
//     (Scope, consulted through the single gate InScope);
//   - an authorization reference (the CVP ticket / rules-of-engagement id that
//     makes the testing lawful) and an operator contact;
//   - a testing window outside which the gate refuses;
//   - an intensity ceiling (global rate, per-host concurrency, total request
//     budget) enforced by the Governor;
//   - a destructive-action latch (off by default) that, combined with a per-run
//     confirmation, is the only way a write/persist action is ever permitted -
//     and even then the hard limits (no DoS, destruction, persistence, bulk
//     exfiltration) always refuse.
//
// SECURITY-CRITICAL: this package is the generalization of the crawler's
// isAuthPath/logout self-preservation guard into a mandatory, audited gate every
// engine routes through. It is hand-written and never delegated. Nothing here
// stores credential material; the audit records credential USE by env-var name
// and the authenticated username only, mirroring the dastauth discipline.
package engagement

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	engagementFile  = "engagement.json"
	auditFileName   = "audit.jsonl"
	activePointer   = "active"
	schemaVersion   = "1.0.0"
	maxScopeEntries = 512
)

// ErrNotFound is returned when an engagement id does not exist.
var ErrNotFound = errors.New("engagement not found")

// idRe validates the server-assigned id shape, so an id from a pointer file or
// a flag can never traverse out of the engagements directory.
var idRe = regexp.MustCompile(`^e-[0-9a-f]{16}$`)

// nameRe keeps display names log- and path-friendly.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9 ._/-]{1,80}$`)

// Engagement is one authorized testing engagement.
type Engagement struct {
	Schema           string    `json:"schema"`
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	AuthorizationRef string    `json:"authorizationRef"` // CVP ticket / RoE id: the basis for testing
	Contact          string    `json:"contact"`          // operator contact of record
	Scope            Scope     `json:"scope"`
	Window           Window    `json:"window"`
	Intensity        Intensity `json:"intensity"`
	// Destructive is the engagement-level (first) latch of the destructive
	// interlock. Off by default: an engagement proves impact non-destructively.
	// A destructive action additionally needs a per-run confirmation (the second
	// latch), and the hard limits refuse regardless.
	Destructive bool      `json:"destructive"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Scope is the in/out-of-scope declaration the gate enforces. Entries may be a
// bare host (any port), a host:port, a CIDR (matched only against IP-literal
// targets), a URL-prefix (scheme://host[:port]/path...), or a "*.domain"
// subdomain wildcard. Out-of-scope entries always win over in-scope ones.
type Scope struct {
	InScope    []string `json:"inScope"`
	OutOfScope []string `json:"outOfScope,omitempty"`
}

// Window is the testing window. A zero Start means "no earlier bound"; a zero
// End means "no later bound". Outside the window the gate refuses.
type Window struct {
	Start time.Time `json:"start,omitempty"`
	End   time.Time `json:"end,omitempty"`
}

// Intensity is the "considerate guest" ceiling the operator dials.
type Intensity struct {
	RatePerSec         float64 `json:"ratePerSec"`         // global request-rate ceiling (req/s); <=0 => default
	PerHostConcurrency int     `json:"perHostConcurrency"` // max simultaneous in-process requests per host; <=0 => default
	RequestBudget      int64   `json:"requestBudget"`      // total metered requests for the engagement; <=0 => default
}

// Defaults for an unset intensity ceiling: deliberately conservative, so an
// operator who dials nothing still tests like a considerate guest.
const (
	defaultRatePerSec         = 10.0
	defaultPerHostConcurrency = 4
	defaultRequestBudget      = 20000
)

// withDefaults returns the intensity with zero fields replaced by the
// conservative defaults. It never widens an operator-set ceiling.
func (in Intensity) withDefaults() Intensity {
	if in.RatePerSec <= 0 {
		in.RatePerSec = defaultRatePerSec
	}
	if in.PerHostConcurrency <= 0 {
		in.PerHostConcurrency = defaultPerHostConcurrency
	}
	if in.RequestBudget <= 0 {
		in.RequestBudget = defaultRequestBudget
	}
	return in
}

// New builds a validated engagement, assigning an id and creation time. It is
// the only constructor: it normalizes the intensity ceiling and rejects a
// malformed scope, so a persisted engagement is always well-formed.
func New(name string, scope Scope, opts Options) (*Engagement, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return nil, fmt.Errorf("engagement name must match %s", nameRe)
	}
	if strings.TrimSpace(opts.AuthorizationRef) == "" {
		return nil, errors.New("an authorization reference (CVP ticket / RoE id) is required: it is the basis for testing")
	}
	if err := validateScope(scope); err != nil {
		return nil, err
	}
	if !opts.Window.End.IsZero() && !opts.Window.Start.IsZero() && opts.Window.End.Before(opts.Window.Start) {
		return nil, errors.New("testing window end is before its start")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	return &Engagement{
		Schema:           schemaVersion,
		ID:               id,
		Name:             name,
		AuthorizationRef: strings.TrimSpace(opts.AuthorizationRef),
		Contact:          strings.TrimSpace(opts.Contact),
		Scope:            scope,
		Window:           opts.Window,
		Intensity:        opts.Intensity,
		Destructive:      opts.Destructive,
		CreatedAt:        time.Now().UTC(),
	}, nil
}

// Options carry the non-scope fields for New.
type Options struct {
	AuthorizationRef string
	Contact          string
	Window           Window
	Intensity        Intensity
	Destructive      bool
}

// WindowOpen reports whether now falls within the testing window.
func (e *Engagement) WindowOpen(now time.Time) bool {
	if e == nil {
		return false
	}
	if !e.Window.Start.IsZero() && now.Before(e.Window.Start) {
		return false
	}
	if !e.Window.End.IsZero() && now.After(e.Window.End) {
		return false
	}
	return true
}

// EffectiveIntensity is the intensity with defaults applied.
func (e *Engagement) EffectiveIntensity() Intensity { return e.Intensity.withDefaults() }

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("engagement: id: %w", err)
	}
	return "e-" + hex.EncodeToString(b), nil
}

// Store persists engagements under a directory (conventionally
// <root>/.appsec/engagements). Each engagement is a subdirectory holding its
// object and its audit trail; a single "active" pointer file names the
// engagement active modules use by default.
type Store struct {
	Dir string
}

func (s *Store) engDir(id string) string { return filepath.Join(s.Dir, id) }

// AuditPath returns the tamper-evident audit-trail path for an engagement.
func (s *Store) AuditPath(id string) string {
	return filepath.Join(s.engDir(id), auditFileName)
}

// Save writes the engagement atomically (temp file + rename), 0600.
func (s *Store) Save(e *Engagement) error {
	if e == nil || !idRe.MatchString(e.ID) {
		return errors.New("engagement: refusing to save a malformed engagement")
	}
	dir := s.engDir(e.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("engagement: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("engagement: marshal: %w", err)
	}
	path := filepath.Join(dir, engagementFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("engagement: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("engagement: rename: %w", err)
	}
	return nil
}

// Load reads one engagement by id.
func (s *Store) Load(id string) (*Engagement, error) {
	if !idRe.MatchString(id) {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(s.engDir(id), engagementFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("engagement: read: %w", err)
	}
	var e Engagement
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("engagement: parse %s: %w", id, err)
	}
	return &e, nil
}

// List returns all persisted engagements, newest first.
func (s *Store) List() ([]*Engagement, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("engagement: list: %w", err)
	}
	var out []*Engagement
	for _, ent := range entries {
		if !ent.IsDir() || !idRe.MatchString(ent.Name()) {
			continue
		}
		e, err := s.Load(ent.Name())
		if err != nil {
			continue // a torn engagement is skipped, never fatal to a list
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// SetActive records id as the default engagement for active modules.
func (s *Store) SetActive(id string) error {
	if _, err := s.Load(id); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("engagement: mkdir: %w", err)
	}
	tmp := filepath.Join(s.Dir, activePointer+".tmp")
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0o600); err != nil {
		return fmt.Errorf("engagement: write active: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.Dir, activePointer)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("engagement: set active: %w", err)
	}
	return nil
}

// Active returns the active engagement, or (nil, nil) when none is set. A
// pointer to a deleted engagement is treated as none, not an error.
func (s *Store) Active() (*Engagement, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, activePointer))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("engagement: read active: %w", err)
	}
	id := strings.TrimSpace(string(data))
	e, err := s.Load(id)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return e, err
}
