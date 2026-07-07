package cloudscan

import (
	"strings"
	"testing"
)

func TestParseToolVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Prowler 5.31.0 (You are running the latest version, yay!)\n", "Prowler 5.31.0"},
		{"\nProwler 4.6.1\n", "Prowler 4.6.1"},
		{"", ""},
		{"\x1b[32mProwler 5.0.0\x1b[0m\n", "[32mProwler 5.0.0[0m"}, // control bytes stripped, text kept
		{strings.Repeat("x", 500), strings.Repeat("x", 60)},        // capped
	}
	for _, tc := range cases {
		if got := parseToolVersion(tc.in); got != tc.want {
			t.Errorf("parseToolVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
