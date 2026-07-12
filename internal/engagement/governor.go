package engagement

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Governor enforces an engagement's scope, testing window, and intensity ceiling
// on every active request, and records each decision to the audit trail. It has
// two enforcement planes for the two kinds of module:
//
//   - In-process HTTP (crawler, auth, the native cmdi detector): Client returns
//     an *http.Client whose transport checks scope, waits on the rate limiter,
//     holds a per-host concurrency slot, spends one unit of request budget, and
//     audits - PER REQUEST. Hard enforcement: an out-of-scope or over-budget
//     request never reaches the network.
//
//   - Subprocess tools (nuclei, sqlmap, dalfox): their HTTP is out of our
//     process, so they are gated at DISPATCH via Guard/FilterEndpoints - every
//     endpoint is scope-checked before the tool is handed it, out-of-scope
//     endpoints are dropped and audited, and each dispatch spends budget. The
//     tool's own rate/concurrency flags are set from the ceiling.
//
// The destructive interlock is a double latch: the engagement's Destructive flag
// AND a per-run confirmation must both be set, and even then the hard limits
// refuse. No current engine performs a destructive action; the interlock is the
// spine a future one must pass through.
type Governor struct {
	eng   *Engagement
	audit *Audit

	limiter   *rateLimiter
	remaining int64 // atomic request budget
	budgetCap int64

	hostCap int
	mu      sync.Mutex
	sems    map[string]chan struct{}

	destructiveConfirmed bool // the per-run (second) latch
}

// Sentinel errors surfaced to callers (and, for in-process requests, returned
// from the HTTP transport so the request never leaves).
var (
	ErrNoEngagement    = errors.New("no active engagement: active DAST modules require an authorized engagement (see `argus engagement`); refusing to send any request")
	ErrWindowClosed    = errors.New("engagement testing window is closed")
	ErrBudgetExhausted = errors.New("engagement request budget is exhausted")
)

// ScopeError is returned when a request targets a URL outside the engagement
// scope. It carries the URL for a clear message and is distinguishable by type.
type ScopeError struct{ URL string }

func (e *ScopeError) Error() string {
	return fmt.Sprintf("refused: %s is outside the engagement scope", e.URL)
}

// NewGovernor builds the enforcer for an engagement. audit may be nil (no trail
// written); eng must be non-nil. destructiveConfirmed is the per-run second
// latch of the destructive interlock.
func NewGovernor(eng *Engagement, audit *Audit, destructiveConfirmed bool) *Governor {
	in := eng.EffectiveIntensity()
	return &Governor{
		eng:                  eng,
		audit:                audit,
		limiter:              newRateLimiter(in.RatePerSec),
		remaining:            in.RequestBudget,
		budgetCap:            in.RequestBudget,
		hostCap:              in.PerHostConcurrency,
		sems:                 map[string]chan struct{}{},
		destructiveConfirmed: destructiveConfirmed,
	}
}

// Engagement returns the governed engagement.
func (g *Governor) Engagement() *Engagement { return g.eng }

// Audit returns the audit trail (may be nil).
func (g *Governor) Audit() *Audit { return g.audit }

// Event records an engagement-level audit event (scan start/finish, auth). It is
// a thin, nil-safe pass-through so callers do not each guard the audit.
func (g *Governor) Event(event string, details map[string]string) {
	if g == nil || g.audit == nil {
		return
	}
	_ = g.audit.Append(event, details)
}

// BudgetRemaining reports the metered request budget left.
func (g *Governor) BudgetRemaining() int64 { return atomic.LoadInt64(&g.remaining) }

// spendBudget consumes one unit; false means the budget is exhausted.
func (g *Governor) spendBudget() bool {
	if g.budgetCap <= 0 {
		return true
	}
	return atomic.AddInt64(&g.remaining, -1) >= 0
}

// acquireHost blocks until a per-host concurrency slot is free and returns a
// release func. cap <= 0 disables the limit.
func (g *Governor) acquireHost(ctx context.Context, host string) (func(), error) {
	if g.hostCap <= 0 {
		return func() {}, nil
	}
	g.mu.Lock()
	sem, ok := g.sems[host]
	if !ok {
		sem = make(chan struct{}, g.hostCap)
		g.sems[host] = sem
	}
	g.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// Client returns an *http.Client that enforces the engagement on every request,
// borrowing base's Jar, Timeout, and underlying Transport. Pass the result to
// the crawler, the auth flow, and the cmdi detector: they become scope-gated,
// throttled, budgeted, and audited for free.
func (g *Governor) Client(base *http.Client) *http.Client {
	baseRT := http.DefaultTransport
	var jar http.CookieJar
	var timeout time.Duration
	if base != nil {
		if base.Transport != nil {
			baseRT = base.Transport
		}
		jar = base.Jar
		timeout = base.Timeout
	}
	return &http.Client{
		Transport: &govTransport{base: baseRT, gov: g},
		Jar:       jar,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			// A redirect that leaves scope is not followed: return the 3xx as-is
			// rather than chasing it out of bounds. The transport would refuse it
			// anyway; this is the clean stop.
			if !g.eng.InScope(req.URL.String()) {
				g.Event(EventRefused, map[string]string{"reason": ReasonOutOfScope, "url": req.URL.String(), "via": "redirect"})
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// govTransport is the in-process enforcement plane: one gate for every request
// the wrapped client makes, including each redirect hop.
type govTransport struct {
	base http.RoundTripper
	gov  *Governor
}

func (t *govTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	g := t.gov
	u := req.URL.String()

	if !g.eng.WindowOpen(time.Now()) {
		g.Event(EventRefused, map[string]string{"reason": ReasonWindowClosed, "url": u})
		return nil, ErrWindowClosed
	}
	if !g.eng.InScope(u) {
		g.Event(EventRefused, map[string]string{"reason": ReasonOutOfScope, "url": u})
		return nil, &ScopeError{URL: u}
	}
	if !g.spendBudget() {
		g.Event(EventRefused, map[string]string{"reason": ReasonBudget, "url": u})
		return nil, ErrBudgetExhausted
	}

	release, err := g.acquireHost(req.Context(), req.URL.Hostname())
	if err != nil {
		return nil, err
	}
	defer release()

	if err := g.limiter.wait(req.Context()); err != nil {
		return nil, err
	}
	g.Event(EventRequest, map[string]string{"method": req.Method, "url": u})
	return t.base.RoundTrip(req)
}

// FilterEndpoints is the subprocess-plane gate: it returns only the endpoints in
// scope and spends one budget unit per kept endpoint, dropping and auditing the
// rest. tool labels the engine for the audit trail. It also refuses everything
// once the window is closed or the budget is exhausted, so a subprocess engine
// is never dispatched out of bounds.
func (g *Governor) FilterEndpoints(tool string, urls []string) []string {
	if !g.eng.WindowOpen(time.Now()) {
		g.Event(EventRefused, map[string]string{"reason": ReasonWindowClosed, "tool": tool})
		return nil
	}
	var kept []string
	for _, u := range urls {
		if !g.eng.InScope(u) {
			g.Event(EventRefused, map[string]string{"reason": ReasonOutOfScope, "tool": tool, "url": u})
			continue
		}
		if !g.spendBudget() {
			g.Event(EventRefused, map[string]string{"reason": ReasonBudget, "tool": tool, "url": u})
			break
		}
		g.Event(EventToolDispatch, map[string]string{"tool": tool, "url": u})
		kept = append(kept, u)
	}
	return kept
}

// ToolRateLimit returns the per-second request ceiling to pass to a subprocess
// tool's own rate flag (e.g. nuclei -rate-limit), rounded down, minimum 1.
func (g *Governor) ToolRateLimit() int {
	r := int(g.eng.EffectiveIntensity().RatePerSec)
	if r < 1 {
		return 1
	}
	return r
}

// ToolConcurrency returns the per-host concurrency ceiling to pass to a
// subprocess tool's worker/thread flag.
func (g *Governor) ToolConcurrency() int {
	return g.eng.EffectiveIntensity().PerHostConcurrency
}

// RequireDestructive is the destructive interlock. It permits a destructive
// action only when BOTH latches are set (the engagement's Destructive flag and
// the per-run confirmation) and the action is not among the platform hard
// limits. Every decision is audited. It returns nil to permit, an error to
// refuse. No current engine calls it with a destructive action; it is the gate a
// future one must pass.
func (g *Governor) RequireDestructive(action string) error {
	if isHardForbidden(action) {
		g.Event(EventDestructiveBlock, map[string]string{"action": action, "reason": ReasonHardForbidden})
		return fmt.Errorf("refused: %q is a platform hard limit (no DoS, destruction, persistence, or bulk exfiltration) and is never permitted", action)
	}
	if !g.eng.Destructive || !g.destructiveConfirmed {
		g.Event(EventDestructiveBlock, map[string]string{"action": action, "reason": ReasonDestructive})
		return fmt.Errorf("refused: %q is a destructive action; it needs the engagement's destructive flag AND a per-run --i-have-authorization confirmation", action)
	}
	g.Event(EventDestructiveAllow, map[string]string{"action": action})
	return nil
}

// hardForbidden action classes: refused regardless of any flag or confirmation.
// These keep Argus a sanctioned testing tool. The check is substring-based on a
// normalized action label so a caller cannot slip a forbidden class past it.
var hardForbidden = []string{
	"dos", "denial-of-service", "flood", "exhaust", "resource-exhaustion",
	"destroy", "delete", "wipe", "drop-table", "truncate", "corrupt",
	"persist", "implant", "backdoor", "webshell", "c2", "beacon", "propagate", "worm",
	"exfiltrate", "dump-all", "bulk-export", "mass-",
}

func isHardForbidden(action string) bool {
	a := normalizeAction(action)
	for _, f := range hardForbidden {
		if strings.Contains(a, f) {
			return true
		}
	}
	return false
}

func normalizeAction(s string) string {
	b := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			b = append(b, r+('a'-'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b = append(b, r)
		default:
			b = append(b, '-') // collapse spaces/underscores/punctuation to a separator
		}
	}
	return string(b)
}

// rateLimiter is a minimal reservation limiter (no external dependency): it
// spaces requests interval apart on a shared timeline, so the average rate stays
// at ratePerSec even under concurrent callers. A non-positive rate disables it.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(ratePerSec float64) *rateLimiter {
	if ratePerSec <= 0 {
		return &rateLimiter{}
	}
	return &rateLimiter{interval: time.Duration(float64(time.Second) / ratePerSec)}
}

func (l *rateLimiter) wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		if ctx != nil {
			return ctx.Err()
		}
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	d := time.Until(at)
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	if ctx == nil {
		<-timer.C
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
