package cloudremediate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeExec records what it was asked to run and returns canned output.
type fakeExec struct {
	calls    [][]string
	profiles []string
	out      string
	err      error
}

func (f *fakeExec) Run(_ context.Context, argv []string, profile string) (string, error) {
	f.calls = append(f.calls, argv)
	f.profiles = append(f.profiles, profile)
	return f.out, f.err
}

func s3Plan(t *testing.T) Plan {
	t.Helper()
	r, _ := ByID("aws-s3-block-public-access")
	p, err := Build(r, cloudFinding("s3_bucket_public_access", map[string]string{"service": "s3", "resourceName": "prod-assets"}))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunDryRunAndApply(t *testing.T) {
	fx := &fakeExec{out: "ok"}
	r := &Runner{Exec: fx, ValidProfile: func(string) bool { return true }}
	plan := s3Plan(t)

	if _, err := r.Run(context.Background(), plan, DryRun, "sec-write"); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if len(fx.calls) != 1 || fx.calls[0][1] != "s3api" || fx.calls[0][2] != "get-public-access-block" {
		t.Errorf("dry-run ran the wrong command: %v", fx.calls)
	}
	if fx.profiles[0] != "sec-write" {
		t.Errorf("profile not passed to executor: %v", fx.profiles)
	}

	fx.calls = nil
	if _, err := r.Run(context.Background(), plan, Apply, "sec-write"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if fx.calls[0][2] != "put-public-access-block" {
		t.Errorf("apply ran the wrong command: %v", fx.calls)
	}
}

func TestRunProfileValidation(t *testing.T) {
	fx := &fakeExec{out: "ok"}
	r := &Runner{Exec: fx, ValidProfile: func(name string) bool { return name == "known" }}
	plan := s3Plan(t)
	if _, err := r.Run(context.Background(), plan, Apply, "unknown"); err == nil {
		t.Error("unknown profile must be refused")
	}
	if _, err := r.Run(context.Background(), plan, Apply, ""); err == nil {
		t.Error("empty profile must be refused")
	}
	if len(fx.calls) != 0 {
		t.Error("executor ran despite an invalid profile")
	}
}

// TestRunSafetyGuard: a plan carrying a command that violates the argv guard is
// refused before ANY command runs — defense in depth over the catalog.
func TestRunSafetyGuard(t *testing.T) {
	fx := &fakeExec{out: "ok"}
	r := &Runner{Exec: fx, ValidProfile: func(string) bool { return true }}

	bad := []struct {
		name string
		plan Plan
	}{
		{"non-allowlisted binary", Plan{ID: "x", Apply: []Command{{"curl", "http://evil"}}}},
		{"destructive verb", Plan{ID: "x", Apply: []Command{{"aws", "s3api", "delete-bucket", "--bucket", "b"}}}},
		{"shell metachar", Plan{ID: "x", Apply: []Command{{"aws", "s3api", "get", "b; rm -rf /"}}}},
		{"pipe", Plan{ID: "x", Apply: []Command{{"aws", "x", "| sh"}}}},
	}
	for _, tc := range bad {
		if _, err := r.Run(context.Background(), tc.plan, Apply, "p"); err == nil {
			t.Errorf("%s: guard did not refuse", tc.name)
		}
	}
	if len(fx.calls) != 0 {
		t.Errorf("a guarded command reached the executor: %v", fx.calls)
	}
}

// TestRunStopsAtFirstFailure: a failing command halts the sequence and the
// error carries the tail of its output.
func TestRunStopsAtFirstFailure(t *testing.T) {
	fx := &fakeExec{out: "AccessDenied: not authorized", err: errors.New("exit 254")}
	r := &Runner{Exec: fx, ValidProfile: func(string) bool { return true }}
	res, err := r.Run(context.Background(), s3Plan(t), Apply, "p")
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("failure not surfaced: %v", err)
	}
	if len(res) != 1 || res[0].Err == "" {
		t.Errorf("result did not record the failure: %+v", res)
	}
}
