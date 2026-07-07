package scanner

import "testing"

// TestPickSemgrepBinary: the override wins when present; otherwise semgrep is
// preferred, then opengrep, then a semgrep fallback for error messages.
func TestPickSemgrepBinary(t *testing.T) {
	onPath := func(have ...string) func(string) bool {
		set := map[string]bool{}
		for _, h := range have {
			set[h] = true
		}
		return func(b string) bool { return set[b] }
	}
	cases := []struct {
		name     string
		override string
		have     []string
		want     string
	}{
		{"override present wins", "opengrep", []string{"semgrep", "opengrep"}, "opengrep"},
		{"override absent ignored", "opengrep", []string{"semgrep"}, "semgrep"},
		{"prefer semgrep", "", []string{"semgrep", "opengrep"}, "semgrep"},
		{"opengrep when only it", "", []string{"opengrep"}, "opengrep"},
		{"fallback names semgrep", "", nil, "semgrep"},
	}
	for _, tc := range cases {
		if got := pickSemgrepBinary(tc.override, onPath(tc.have...)); got != tc.want {
			t.Errorf("%s: pickSemgrepBinary(%q, have=%v) = %q, want %q", tc.name, tc.override, tc.have, got, tc.want)
		}
	}
}
