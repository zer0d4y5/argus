package triage

import (
	"strings"
	"testing"
	"time"

	"github.com/leaky-hub/argus/internal/model"
)

func TestParseVerdictValid(t *testing.T) {
	tr, err := parseVerdict(`{"verdict":"false-positive","confidence":0.85,"rationale":"Parameterized query."}`)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Verdict != model.VerdictFalsePositive || tr.Confidence != 0.85 || tr.Rationale != "Parameterized query." {
		t.Errorf("got %+v", tr)
	}
}

func TestParseVerdictToleratesFencesAndProse(t *testing.T) {
	raw := "Here is my analysis:\n```json\n{\"verdict\": \"TRUE-POSITIVE\", \"confidence\": 1, \"rationale\": \"SQLi.\"}\n```\nHope that helps!"
	tr, err := parseVerdict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Verdict != model.VerdictTruePositive { // case-normalized
		t.Errorf("verdict = %q", tr.Verdict)
	}
}

func TestParseVerdictRejects(t *testing.T) {
	for _, raw := range []string{
		"",
		"I think this is probably fine and you should ignore it.",
		`{"verdict":"not-a-thing","confidence":0.9}`,
		`{"confidence":0.9,"rationale":"no verdict field"}`,
		`{"verdict": 42}`,
		"{broken json",
	} {
		if _, err := parseVerdict(raw); err == nil {
			t.Errorf("parseVerdict(%.40q) should fail", raw)
		}
	}
}

// TestDecodeFirstObjectBoundedTime guards the JSON extractor against a
// quadratic-scan DoS. A 1 MB response that stays grammatically valid until EOF
// (a '{' at every step) used to pin a core for ~25s because a decoder restarted
// at every brace. The candidate cap keeps it well under a second.
func TestDecodeFirstObjectBoundedTime(t *testing.T) {
	evil := strings.Repeat(`{"x":`, 1<<20/5) // ~1 MB of nested-open structure
	done := make(chan struct{})
	go func() {
		_, _ = decodeFirstObject(evil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("decodeFirstObject did not return within 2s on a 1 MB adversarial input")
	}
}

// TestDecodeFirstObjectSkipsStrayBrace: a stray '{' in prose before the real
// object must not prevent extraction (the bounded scan still tries later ones).
func TestDecodeFirstObjectSkipsStrayBrace(t *testing.T) {
	raw := `The result {is} as follows: {"verdict":"uncertain","rationale":"ok"}`
	if _, err := parseVerdict(raw); err != nil {
		t.Fatalf("stray brace before the object broke extraction: %v", err)
	}
}

func TestParseVerdictConfidenceBounds(t *testing.T) {
	cases := []struct {
		raw  string
		want float64
	}{
		{`{"verdict":"uncertain","confidence":99}`, 1},
		{`{"verdict":"uncertain","confidence":-3}`, 0},
		{`{"verdict":"uncertain"}`, 0.5}, // missing = no opinion
	}
	for _, tc := range cases {
		tr, err := parseVerdict(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Confidence != tc.want {
			t.Errorf("%s: confidence = %v, want %v", tc.raw, tr.Confidence, tc.want)
		}
	}
}

func TestParseVerdictRationaleSanitized(t *testing.T) {
	long := strings.Repeat("a", 2000)
	tr, err := parseVerdict(`{"verdict":"uncertain","rationale":"` + long + `"}`)
	if err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(tr.Rationale)); n > maxRationaleRunes+1 {
		t.Errorf("rationale length %d exceeds bound", n)
	}

	tr, err = parseVerdict(`{"verdict":"uncertain","rationale":"line1\nline2\u0007bell"}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(tr.Rationale, "\n\a") {
		t.Errorf("control characters survived: %q", tr.Rationale)
	}
}
