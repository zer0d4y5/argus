package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
)

// Smoke test: run the real scanners against the planted fixture repo and make
// sure each one finds its plant. Skipped with -short and when a scanner is
// not installed. Semgrep needs network access for --config auto.
func TestSmokeFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("smoke test invokes real scanner binaries; skipped in -short mode")
	}
	fixture, err := filepath.Abs("../../testdata/fixture")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		adapter Adapter
		// substring expected in at least one finding's field
		wantIn  func(model.RawFinding) bool
		wantMsg string
	}{
		{
			adapter: &Semgrep{},
			wantIn: func(f model.RawFinding) bool {
				return strings.Contains(strings.ToLower(f.RuleID+f.Description), "sql") ||
					containsCWE(f.CWEs, "89")
			},
			wantMsg: "SQL injection plant (app.py)",
		},
		{
			adapter: &Gitleaks{},
			wantIn: func(f model.RawFinding) bool {
				return strings.Contains(f.File, "config.env")
			},
			wantMsg: "hardcoded AWS key plant (config.env)",
		},
		{
			adapter: &Trivy{},
			wantIn: func(f model.RawFinding) bool {
				return strings.HasPrefix(strings.ToLower(f.Package), "pyyaml@") ||
					strings.HasPrefix(strings.ToLower(f.Package), "flask@")
			},
			wantMsg: "vulnerable dependency plant (requirements.txt)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.adapter.Name(), func(t *testing.T) {
			if !tt.adapter.Available() {
				t.Skipf("%s not installed", tt.adapter.Name())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			raws, err := tt.adapter.Scan(ctx, fixture)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(raws) == 0 {
				t.Fatalf("no findings — expected at least the %s", tt.wantMsg)
			}
			found := false
			for _, f := range raws {
				if f.Tool != tt.adapter.Name() || f.Category != tt.adapter.Category() {
					t.Errorf("finding has tool/category %q/%q, want %q/%q",
						f.Tool, f.Category, tt.adapter.Name(), tt.adapter.Category())
				}
				if tt.wantIn(f) {
					found = true
				}
			}
			if !found {
				t.Errorf("did not find the %s in %d findings", tt.wantMsg, len(raws))
			}
			// Secret hygiene: no finding may carry the planted secret values.
			for _, f := range raws {
				blob := f.Description + f.Title + string(f.RawPayload)
				for k, v := range f.Meta {
					blob += k + v
				}
				if strings.Contains(blob, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") {
					t.Error("plaintext secret leaked into a finding")
				}
			}
		})
	}
}

func containsCWE(cwes []string, num string) bool {
	for _, c := range cwes {
		if strings.Contains(c, num) {
			return true
		}
	}
	return false
}
