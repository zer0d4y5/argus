package engagement

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingRT records how many requests reach the underlying transport, so a test
// can prove an out-of-scope request was refused BEFORE any dial.
type countingRT struct {
	n    int32
	base http.RoundTripper
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.n, 1)
	return c.base.RoundTrip(r)
}

func govFor(t *testing.T, in Intensity, inScope ...string) (*Governor, *Audit) {
	t.Helper()
	eng := &Engagement{Scope: Scope{InScope: inScope}, Intensity: in}
	audit, err := OpenAudit(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return NewGovernor(eng, audit, false), audit
}

func TestRoundTripRefusesOutOfScopeBeforeDial(t *testing.T) {
	gov, audit := govFor(t, Intensity{}, "127.0.0.1")
	counter := &countingRT{base: http.DefaultTransport}
	client := gov.Client(&http.Client{Transport: counter})

	_, err := client.Get("http://10.255.255.1/secret")
	var se *ScopeError
	if !errors.As(err, &se) {
		t.Fatalf("out-of-scope request must return a ScopeError, got %v", err)
	}
	if atomic.LoadInt32(&counter.n) != 0 {
		t.Fatal("an out-of-scope request must never reach the network")
	}
	// The refusal is on the record.
	if res, _ := Verify(audit.path); !res.OK {
		t.Fatal("audit chain must stay intact")
	}
	if !auditHas(t, audit.path, EventRefused, ReasonOutOfScope) {
		t.Error("the out-of-scope refusal must be audited")
	}
}

func TestRoundTripInScopeReachesAndSpendsBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	gov, audit := govFor(t, Intensity{RequestBudget: 100}, "127.0.0.1")
	client := gov.Client(nil)
	resp, err := client.Get(srv.URL) // httptest binds 127.0.0.1
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gov.BudgetRemaining() != 99 {
		t.Errorf("an in-scope request must spend one budget unit, remaining=%d", gov.BudgetRemaining())
	}
	if !auditHas(t, audit.path, EventRequest, "") {
		t.Error("a permitted request must be audited")
	}
}

func TestBudgetExhaustion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	gov, _ := govFor(t, Intensity{RequestBudget: 2}, "127.0.0.1")
	client := gov.Client(nil)

	for i := 0; i < 2; i++ {
		if resp, err := client.Get(srv.URL); err != nil {
			t.Fatalf("request %d within budget failed: %v", i, err)
		} else {
			resp.Body.Close()
		}
	}
	if _, err := client.Get(srv.URL); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("the over-budget request must be refused, got %v", err)
	}
}

func TestWindowClosedRefuses(t *testing.T) {
	eng := &Engagement{
		Scope:  Scope{InScope: []string{"127.0.0.1"}},
		Window: Window{End: time.Now().Add(-time.Hour)},
	}
	gov := NewGovernor(eng, nil, false)
	counter := &countingRT{base: http.DefaultTransport}
	client := gov.Client(&http.Client{Transport: counter})
	if _, err := client.Get("http://127.0.0.1:1/x"); !errors.Is(err, ErrWindowClosed) {
		t.Fatalf("a closed window must refuse, got %v", err)
	}
	if atomic.LoadInt32(&counter.n) != 0 {
		t.Fatal("a window-closed request must never dial")
	}
}

func TestPerHostConcurrencyCap(t *testing.T) {
	gov, _ := govFor(t, Intensity{PerHostConcurrency: 2}, "h")
	ctx := context.Background()

	r1, err := gov.acquireHost(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := gov.acquireHost(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}

	// A third acquire for the same host must block until a slot frees.
	acquired := make(chan struct{})
	go func() {
		r3, _ := gov.acquireHost(ctx, "h")
		close(acquired)
		r3()
	}()
	select {
	case <-acquired:
		t.Fatal("the third concurrent acquire must block at the cap")
	case <-time.After(50 * time.Millisecond):
	}
	r1() // free one slot
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("releasing a slot must unblock the waiter")
	}
	r2()

	// A different host is independent.
	other, err := gov.acquireHost(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	other()
}

func TestRateLimiterSpacing(t *testing.T) {
	l := newRateLimiter(20) // 20/s => 50ms spacing
	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := l.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// 4 reservations at 50ms spacing: the first is immediate, the next three add
	// ~150ms. Allow slack for slow CI.
	if elapsed := time.Since(start); elapsed < 120*time.Millisecond {
		t.Errorf("rate limiter did not space requests: %v elapsed for 4 at 20/s", elapsed)
	}
}

func TestRateLimiterConcurrentAverage(t *testing.T) {
	l := newRateLimiter(50) // 20ms spacing
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.wait(context.Background())
		}()
	}
	wg.Wait()
	// 10 concurrent waiters share one timeline: ~9*20ms = 180ms minimum.
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("concurrent waiters must still respect the average rate: %v", elapsed)
	}
}

func TestFilterEndpoints(t *testing.T) {
	gov, audit := govFor(t, Intensity{RequestBudget: 10}, "in.example.com")
	urls := []string{
		"https://in.example.com/a?x=1",
		"https://out.example.com/b?x=1", // dropped: out of scope
		"https://in.example.com/c?x=1",
	}
	kept := gov.FilterEndpoints("nuclei", urls)
	if len(kept) != 2 || kept[0] != urls[0] || kept[1] != urls[2] {
		t.Fatalf("only in-scope endpoints must pass, got %v", kept)
	}
	if gov.BudgetRemaining() != 8 {
		t.Errorf("each kept endpoint spends one budget unit, remaining=%d", gov.BudgetRemaining())
	}
	if !auditHas(t, audit.path, EventRefused, ReasonOutOfScope) {
		t.Error("the dropped endpoint must be audited")
	}
	if !auditHas(t, audit.path, EventToolDispatch, "nuclei") {
		t.Error("dispatched endpoints must be audited with the tool name")
	}
}

func TestFilterEndpointsStopsAtBudget(t *testing.T) {
	gov, _ := govFor(t, Intensity{RequestBudget: 1}, "in.example.com")
	kept := gov.FilterEndpoints("sqlmap", []string{
		"https://in.example.com/a",
		"https://in.example.com/b",
	})
	if len(kept) != 1 {
		t.Fatalf("filtering must stop at the budget, got %d", len(kept))
	}
}

func TestFilterEndpointsWindowClosed(t *testing.T) {
	eng := &Engagement{Scope: Scope{InScope: []string{"in.example.com"}}, Window: Window{End: time.Now().Add(-time.Hour)}}
	gov := NewGovernor(eng, nil, false)
	if kept := gov.FilterEndpoints("nuclei", []string{"https://in.example.com/a"}); kept != nil {
		t.Fatal("a closed window must dispatch no endpoints")
	}
}

func TestDestructiveInterlock(t *testing.T) {
	scope := Scope{InScope: []string{"in.example.com"}}

	// Neither latch: refused.
	g1 := NewGovernor(&Engagement{Scope: scope, Destructive: false}, nil, false)
	if err := g1.RequireDestructive("write-file"); err == nil {
		t.Error("destructive action must be refused with neither latch set")
	}
	// Only the engagement flag (first latch): still refused.
	g2 := NewGovernor(&Engagement{Scope: scope, Destructive: true}, nil, false)
	if err := g2.RequireDestructive("write-file"); err == nil {
		t.Error("destructive action must be refused without the per-run confirmation")
	}
	// Only the confirmation (second latch): still refused.
	g3 := NewGovernor(&Engagement{Scope: scope, Destructive: false}, nil, true)
	if err := g3.RequireDestructive("write-file"); err == nil {
		t.Error("destructive action must be refused without the engagement flag")
	}
	// Both latches: permitted.
	g4 := NewGovernor(&Engagement{Scope: scope, Destructive: true}, nil, true)
	if err := g4.RequireDestructive("write-file"); err != nil {
		t.Errorf("both latches set must permit a non-forbidden destructive action, got %v", err)
	}
}

func TestHardLimitsNeverPermitted(t *testing.T) {
	// Even with both latches set, the platform hard limits always refuse.
	g := NewGovernor(&Engagement{Scope: Scope{InScope: []string{"x"}}, Destructive: true}, nil, true)
	for _, action := range []string{"DROP TABLE users", "deploy a webshell", "start a DoS flood", "bulk-export the database", "install persistence beacon"} {
		if err := g.RequireDestructive(action); err == nil {
			t.Errorf("hard-limit action %q must never be permitted", action)
		}
	}
}

// auditHas reports whether the audit file contains an entry with the event and,
// if reasonOrTool is non-empty, that substring anywhere in the line.
func auditHas(t *testing.T, path, event, reasonOrTool string) bool {
	t.Helper()
	entries, err := readEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Event != event {
			continue
		}
		if reasonOrTool == "" {
			return true
		}
		for _, v := range e.Details {
			if v == reasonOrTool {
				return true
			}
		}
	}
	return false
}
