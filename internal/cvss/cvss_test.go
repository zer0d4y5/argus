package cvss

import (
	"math"
	"testing"
)

// TestScoreKnownVectors checks the arithmetic against published CVSS 3.1
// examples so a refactor can't drift the formula.
func TestScoreKnownVectors(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		sev    string
	}{
		// Classic reflected XSS (scope changed).
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"},
		// Unauth RCE — the canonical 9.8.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"},
		// SQLi reading data, no integrity/availability impact.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"},
		// Local, low impact.
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "Low"},
		// All-none → 0.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"},
		// Scope-changed max: the 1.08 multiplier caps at 10.0.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"},
		// Scope-changed with no impact still floors at 0 (impact goes negative).
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N", 0.0, "None"},
		// PR:L carries the heavier 0.68 weight when scope changed.
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "Medium"},
		// PR:H changed-scope weight (0.50) vs the same vector unchanged (0.27).
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", 5.5, "Medium"},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N", 3.8, "Low"},
		// Exercises the 3.25*(ISS-0.02)^15 term materially.
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.2, "High"},
		// Scope flip on identical CIA: the 1.08 multiplier lifts 6.5 to 7.2.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5, "Medium"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2, "High"},
		// The global minimum non-zero score, in the roundup floor region.
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"},
		// High/Critical band boundary from a real vector.
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0, "Critical"},
	}
	for _, c := range cases {
		b, err := Parse(c.vector)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.vector, err)
		}
		got := b.Score()
		if math.Abs(got-c.want) > 0.001 {
			t.Errorf("Score(%q) = %.1f, want %.1f", c.vector, got, c.want)
		}
		if s := Severity(got); s != c.sev {
			t.Errorf("Severity(%.1f) = %s, want %s", got, s, c.sev)
		}
		// Round-trips through the canonical vector.
		if b.Vector() != c.vector {
			t.Errorf("Vector() = %q, want %q", b.Vector(), c.vector)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "CVSS:3.1/AV:N", // missing metrics
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // invalid AV
		"garbage",
		// A duplicated metric must be rejected, not silently last-one-wins:
		// here the stray AV:L would drop a true 9.8 to 8.4.
		"CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should have failed", bad)
		}
	}
}
