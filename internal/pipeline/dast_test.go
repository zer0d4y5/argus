package pipeline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastscan"
	"github.com/zer0d4y5/argus/internal/engagement"
)

// TestRunDASTRefusesWithoutEngagement is the "no engagement, no offense" gate:
// with a nil Governor, RunDAST refuses before it even checks for nuclei, so no
// active module can run without authorization. CI-safe (no tools required).
func TestRunDASTRefusesWithoutEngagement(t *testing.T) {
	_, err := RunDAST(context.Background(), DASTOptions{URL: "http://127.0.0.1/"}, nil)
	if !errors.Is(err, engagement.ErrNoEngagement) {
		t.Fatalf("a scan without an engagement must refuse with ErrNoEngagement, got %v", err)
	}
}

// TestRunDASTRefusesOutOfScopeTarget proves the scope gate refuses a target
// outside the engagement, records the refusal to the audit trail, and never
// reaches the scanner. Requires nuclei on PATH (the availability check precedes
// the scope check), so it is skipped when nuclei is absent.
func TestRunDASTRefusesOutOfScopeTarget(t *testing.T) {
	if !dastscan.Available() {
		t.Skip("nuclei not installed; the scope refusal is checked after the availability probe")
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := engagement.OpenAudit(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	eng := &engagement.Engagement{
		Name:  "scoped",
		Scope: engagement.Scope{InScope: []string{"in.example.com"}},
	}
	gov := engagement.NewGovernor(eng, audit, false)

	_, err = RunDAST(context.Background(), DASTOptions{
		URL:      "http://out.example.com/secret",
		Governor: gov,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "outside the engagement") {
		t.Fatalf("an out-of-scope target must be refused, got %v", err)
	}
	res, err := engagement.Verify(auditPath)
	if err != nil || !res.OK {
		t.Fatalf("audit chain must stay intact: %+v %v", res, err)
	}
	log := readFile(t, auditPath)
	if !strings.Contains(log, `"event":"refused"`) {
		t.Error("the out-of-scope target refusal must be audited")
	}
	if strings.Contains(log, `"event":"scan.start"`) {
		t.Error("a refused target must never reach scan.start")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
