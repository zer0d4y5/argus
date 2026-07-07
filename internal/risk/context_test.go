package risk

import (
	"math"
	"testing"

	"github.com/leaky-hub/argus/internal/model"
)

// The stage-2 flagship scenario from docs/risk-scoring.md: one Dockerfile
// carrying both a detected cloud secret (gitleaks) and the DS-0031
// secret-exposure pattern (trivy-config), scored in the same run so
// co-location fires both ways.
func flagshipRun() []model.Finding {
	return []model.Finding{
		{ // worked example #3
			Tool: "gitleaks", Category: model.CategorySecret,
			RuleID:   "aws-access-token",
			Severity: model.SeverityHigh,
			Location: model.Location{File: "deploy/Dockerfile"},
			Meta:     map[string]string{"entropy": "5.20"},
		},
		{ // worked example #4
			Tool: "trivy-config", Category: model.CategoryIaC,
			RuleID:      "DS-0031",
			Severity:    model.SeverityCritical,
			Remediation: "Do not store secrets in ENV",
			Location:    model.Location{File: "deploy/Dockerfile"},
			Meta:        map[string]string{"message": `Possible exposure of secret env "AWS_SECRET_ACCESS_KEY" in ENV`},
		},
	}
}

// TestContextWorkedExamples pins the v2 worked-example table from
// docs/risk-scoring.md verbatim. If this test needs changing, the doc changes
// with it.
func TestContextWorkedExamples(t *testing.T) {
	ds0031 := func(msg string) model.Finding {
		return model.Finding{
			Tool: "trivy-config", Category: model.CategoryIaC,
			RuleID: "DS-0031", Severity: model.SeverityCritical,
			Remediation: "Do not store secrets in ENV",
			Location:    model.Location{File: "Dockerfile"},
			Meta:        map[string]string{"message": msg},
		}
	}

	cases := []struct {
		name string
		fs   []model.Finding
		want []float64
	}{
		{
			name: "#1 DS-0031 alone, generic env name",
			fs:   []model.Finding{ds0031(`Possible exposure of secret env "BUILD_TOKEN" in ARG`)},
			want: []float64{7.8},
		},
		{
			name: "#2 DS-0031 alone, cloud credential env name",
			fs:   []model.Finding{ds0031(`Possible exposure of secret env "AWS_SECRET_ACCESS_KEY" in ENV`)},
			want: []float64{8.3},
		},
		{
			name: "#3+#4 flagship pair: co-located secret and exposure pattern",
			fs:   flagshipRun(),
			want: []float64{9.4, 9.0},
		},
		{
			name: "#5 same cloud secret in fixtures with low entropy",
			fs: []model.Finding{{
				Tool: "gitleaks", Category: model.CategorySecret,
				RuleID: "aws-access-token", Severity: model.SeverityHigh,
				Location: model.Location{File: "testdata/fixtures/creds.env"},
				Meta:     map[string]string{"entropy": "2.10"},
			}},
			want: []float64{5.0},
		},
		{
			name: "#9 SAST finding in test code",
			fs: []model.Finding{{
				Tool: "semgrep", Category: model.CategorySAST,
				Severity: model.SeverityHigh, CWEs: []string{"CWE-89"},
				Location: model.Location{File: "tests/api_test.py"},
			}},
			want: []float64{6.5},
		},
		{
			name: "#11 IAC world-open ingress",
			fs: []model.Finding{{
				Tool: "trivy-config", Category: model.CategoryIaC,
				RuleID: "AVD-AWS-0107", Severity: model.SeverityHigh,
				Remediation: "Restrict ingress CIDRs",
				Location:    model.Location{File: "main.tf"},
			}},
			want: []float64{8.0},
		},
		{
			name: "#13 secret with no context metadata is neutral",
			fs: []model.Finding{{
				Tool: "gitleaks", Category: model.CategorySecret,
				Severity: model.SeverityHigh,
			}},
			want: []float64{8.0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			Apply(tc.fs)
			for i := range tc.fs {
				if got := *tc.fs[i].RiskScore; got != tc.want[i] {
					t.Errorf("finding %d score = %v, want %v (signals: %+v)",
						i, got, tc.want[i], tc.fs[i].RiskSignals)
				}
			}
		})
	}
}

// TestFlagshipOrdering pins the acceptance ordering the v2 stage exists for:
// co-located real-looking secret > its DS-0031 > DS-0031 alone > the same
// secret in fixtures.
func TestFlagshipOrdering(t *testing.T) {
	pair := flagshipRun()
	Apply(pair)
	secretScore, dsPairScore := *pair[0].RiskScore, *pair[1].RiskScore

	alone := []model.Finding{{
		Tool: "trivy-config", Category: model.CategoryIaC,
		RuleID: "DS-0031", Severity: model.SeverityCritical,
		Remediation: "Do not store secrets in ENV",
		Location:    model.Location{File: "Dockerfile"},
		Meta:        map[string]string{"message": `Possible exposure of secret env "BUILD_TOKEN" in ARG`},
	}}
	Apply(alone)
	dsAloneScore := *alone[0].RiskScore

	fixture := []model.Finding{{
		Tool: "gitleaks", Category: model.CategorySecret,
		RuleID: "aws-access-token", Severity: model.SeverityHigh,
		Location: model.Location{File: "testdata/fixtures/creds.env"},
		Meta:     map[string]string{"entropy": "2.10"},
	}}
	Apply(fixture)
	fixtureScore := *fixture[0].RiskScore

	if !(secretScore > dsPairScore && dsPairScore > dsAloneScore && dsAloneScore > fixtureScore) {
		t.Errorf("acceptance ordering violated: secret+colocated %v > DS-0031+colocated %v > DS-0031 alone %v > fixture secret %v",
			secretScore, dsPairScore, dsAloneScore, fixtureScore)
	}
}

// TestVerifiedHook: validity is carried, never assumed. Only an explicit
// live value reaches the top of the critical band; invalid collapses the
// heuristics; anything else is unchecked = neutral.
func TestVerifiedHook(t *testing.T) {
	withVerified := func(v string) []model.Finding {
		fs := flagshipRun()
		fs[0].Meta["verified"] = v
		return fs
	}

	live := withVerified("live")
	Apply(live)
	if got := *live[0].RiskScore; got != 10.0 { // worked example #6
		t.Errorf("verified live = %v, want 10.0", got)
	}

	invalid := withVerified("invalid")
	Apply(invalid)
	if got := *invalid[0].RiskScore; got != 5.0 { // worked example #7
		t.Errorf("verified invalid = %v, want 5.0", got)
	}
	if n := len(invalid[0].RiskSignals); n != 1 || invalid[0].RiskSignals[0].Code != "secret.verified_invalid" {
		t.Errorf("verified invalid must suppress every other signal, got %+v", invalid[0].RiskSignals)
	}

	// Unknown values are unchecked, not a fourth state.
	weird := withVerified("LIVE!!") // not an exact match
	Apply(weird)
	if got := *weird[0].RiskScore; got != 9.4 {
		t.Errorf("unknown verified value must count as unchecked: %v, want 9.4", got)
	}
}

// TestUnverifiedCeiling: no static heuristic stack — and no triage verdict —
// puts an unverified secret-shaped finding into [9.5, 10]. That band is
// reserved for meta.verified=live.
func TestUnverifiedCeiling(t *testing.T) {
	// Critical-severity secret with high tool confidence: baseline alone
	// saturates at 10; the ceiling must pull it to 9.4.
	fs := []model.Finding{{
		Category: model.CategorySecret, Severity: model.SeverityCritical,
		Confidence: "high",
	}}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 9.4 {
		t.Errorf("unverified critical secret = %v, want 9.4", got)
	}

	// A triage TP cannot vault the ceiling either: the LLM never sees the
	// secret value, so it cannot confirm liveness.
	tp := flagshipRun()
	tp[0].Triage = &model.Triage{Verdict: model.VerdictTruePositive, Confidence: 1.0}
	Apply(tp)
	if got := *tp[0].RiskScore; got != 9.4 {
		t.Errorf("triage TP vaulted the unverified ceiling: %v, want 9.4", got)
	}

	// An FP verdict still deprioritizes below the ceiling as usual.
	fpv := flagshipRun()
	fpv[0].Triage = &model.Triage{Verdict: model.VerdictFalsePositive, Confidence: 1.0}
	Apply(fpv)
	if got := *fpv[0].RiskScore; got != 5.4 {
		t.Errorf("FP under ceiling = %v, want 5.4", got)
	}
}

// TestContextCap: the summed context delta can never exceed ±3.0, and the
// synthetic rows keep baseline + Σdeltas equal to the stage-2 output.
func TestContextCap(t *testing.T) {
	// Stack every negative secret signal plus an FP-ish path: raw −3.0 is at
	// the cap; add verified=invalid variants elsewhere. Construct a case that
	// would exceed the cap: test path (−2.0) + low entropy (−1.0) + DS-0031
	// co-located? Negatives available sum to exactly −3.0 for SECRET, so use
	// a hand-built oversized table check via the positive side: high-value
	// (+0.75) + prod path (+0.5) + co-location (+0.75) + live (+1.5) = +3.5.
	fs := []model.Finding{
		{
			Tool: "gitleaks", Category: model.CategorySecret,
			RuleID: "aws-access-token", Severity: model.SeverityLow,
			Location: model.Location{File: "prod/Dockerfile"},
			Meta:     map[string]string{"entropy": "5.00", "verified": "live"},
		},
		{
			Tool: "trivy-config", Category: model.CategoryIaC,
			RuleID: "DS-0031", Severity: model.SeverityCritical,
			Location: model.Location{File: "prod/Dockerfile"},
			Meta:     map[string]string{"message": `Possible exposure of secret env "AWS_SECRET_ACCESS_KEY" in ENV`},
		},
	}
	Apply(fs)

	raw, capped := 0.0, 0.0
	sawCap := false
	for _, sg := range fs[0].RiskSignals {
		if sg.Code == "context.cap" {
			sawCap = true
		}
		raw += sg.Delta
	}
	capped = raw // rows include the synthetic cap row, so the sum IS the applied delta
	if !sawCap {
		t.Fatalf("expected context.cap row on +3.5 raw delta, got %+v", fs[0].RiskSignals)
	}
	if capped != 3.0 {
		t.Errorf("applied context delta = %v, want capped 3.0", capped)
	}
	// baseline 4.0 (low 3.0 + SECRET 1.0) + capped 3.0; verified live so no ceiling.
	if got := *fs[0].RiskScore; got != 7.0 {
		t.Errorf("capped score = %v, want 7.0", got)
	}
}

// TestSignalSumsMatchScore: for a spread of findings, baseline + Σ signal
// deltas reproduces the final score (absent triage and the [0,10] clamp) —
// the "evidence, not assertion" property the console relies on.
func TestSignalSumsMatchScore(t *testing.T) {
	fs := flagshipRun()
	fs = append(fs, model.Finding{
		Tool: "semgrep", Category: model.CategorySAST,
		Severity: model.SeverityMedium,
		Location: model.Location{File: "tests/util_test.py"},
	})
	Apply(fs)
	for i, f := range fs {
		sum := Baseline(f)
		for _, sg := range f.RiskSignals {
			sum += sg.Delta
		}
		if math.Abs(sum-*f.RiskScore) > 0.051 { // one-decimal rounding slack
			t.Errorf("finding %d: baseline+Σdeltas = %v but riskScore = %v (signals %+v)",
				i, sum, *f.RiskScore, f.RiskSignals)
		}
	}
}

// TestPrioritizationOnly: stage 2 moves riskScore and riskSignals — nothing
// else. Severity (and therefore the gate) is untouched.
func TestPrioritizationOnly(t *testing.T) {
	fs := flagshipRun()
	Apply(fs)
	if fs[0].Severity != model.SeverityHigh || fs[1].Severity != model.SeverityCritical {
		t.Errorf("severity changed: %v / %v", fs[0].Severity, fs[1].Severity)
	}
	if fs[1].Remediation != "Do not store secrets in ENV" {
		t.Errorf("non-risk field changed: %q", fs[1].Remediation)
	}
}

// TestUnknownNeutral: no metadata, no path, no verdict → no signals, baseline
// score. Absence of evidence never moves a score.
func TestUnknownNeutral(t *testing.T) {
	fs := []model.Finding{
		{Category: model.CategorySecret, Severity: model.SeverityHigh},
		{Category: model.CategorySAST, Severity: model.SeverityMedium},
		{Category: model.CategorySCA, Severity: model.SeverityCritical, Remediation: "upgrade"},
		{Category: model.CategoryIaC, RuleID: "DS-0002", Severity: model.SeverityHigh},
	}
	Apply(fs)
	want := []float64{8.0, 5.0, 9.3, 7.0}
	for i := range fs {
		if got := *fs[i].RiskScore; got != want[i] {
			t.Errorf("finding %d = %v, want baseline %v", i, got, want[i])
		}
		if i != 0 && len(fs[i].RiskSignals) != 0 {
			t.Errorf("finding %d emitted signals with no evidence: %+v", i, fs[i].RiskSignals)
		}
	}
	// The critical secret does get the ceiling row (it saturates at 9+):
	// checked separately in TestUnverifiedCeiling; the high secret here must
	// have no rows at all.
	if len(fs[0].RiskSignals) != 0 {
		t.Errorf("neutral secret emitted signals: %+v", fs[0].RiskSignals)
	}
}

// TestPathTokenization: exact-token semantics — "contest" is not "test",
// fixtures dirs named prod stay test-context.
func TestPathTokenization(t *testing.T) {
	cases := []struct {
		path string
		want float64
	}{
		{"src/contest/score.py", 5.0},           // no token match → baseline
		{"src/latest/score.py", 5.0},            // "latest" ≠ "test"
		{"tests/score.py", 4.0},                 // -1.0
		{"pkg/score_test.go", 4.0},              // token split on _ and .
		{"testdata/prod/creds.py", 4.0},         // test wins over prod tokens
		{"docs/production-notes/score.py", 5.0}, // prod tokens don't touch SAST
	}
	for _, tc := range cases {
		fs := []model.Finding{{
			Category: model.CategorySAST, Severity: model.SeverityMedium,
			Location: model.Location{File: tc.path},
		}}
		Apply(fs)
		if got := *fs[0].RiskScore; got != tc.want {
			t.Errorf("%s = %v, want %v", tc.path, got, tc.want)
		}
	}

	// SECRET precedence 3: test path suppresses prod-path and high-value
	// positives but keeps stacking negatives.
	fs := []model.Finding{{
		Category: model.CategorySecret, RuleID: "aws-access-token",
		Severity: model.SeverityHigh,
		Location: model.Location{File: "fixtures/prod/creds.env"},
		Meta:     map[string]string{"entropy": "5.0"},
	}}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 6.0 { // 8.0 - 2.0, no +0.75/+0.5
		t.Errorf("test-path precedence: %v, want 6.0", got)
	}
}

// TestScrubInvariant: the scorer never needs — and never sees — a secret
// value. A fully-redacted finding (match scrubbed, no snippet) still gets the
// full context treatment from rule/entropy/path alone.
func TestScrubInvariant(t *testing.T) {
	fs := []model.Finding{{
		Tool: "gitleaks", Category: model.CategorySecret,
		RuleID: "github-pat", Severity: model.SeverityHigh,
		Location: model.Location{File: "cmd/server/main.go"},
		Meta: map[string]string{
			"entropy": "4.68",
			"match":   "token := \"[REDACTED]\"",
		},
	}}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 8.8 { // 8.0 + 0.75 high-value → 8.75
		t.Errorf("redacted high-value secret = %v, want 8.8", got)
	}
	for _, sg := range fs[0].RiskSignals {
		if sg.Note == "" || len(sg.Note) > 200 {
			t.Errorf("signal note must be a fixed short string: %+v", sg)
		}
	}
}

// TestCloudSignals covers the CLOUD stage-2 table: stacking, the reviewed
// admin-policy set, unknown-is-neutral, and positive-only deltas.
func TestCloudSignals(t *testing.T) {
	mk := func(rule, cats string) model.Finding {
		f := model.Finding{Category: model.CategoryCloud, RuleID: rule}
		if cats != "" {
			f.Meta = map[string]string{"categories": cats}
		}
		return f
	}

	t.Run("stacking public+encryption", func(t *testing.T) {
		sig := contextSignals(mk("s3_bucket_public_and_plain", "encryption,internet-exposed"), runContext{})
		if len(sig) != 2 {
			t.Fatalf("got %d signals, want 2: %+v", len(sig), sig)
		}
	})
	t.Run("admin policy by rule ID, no categories", func(t *testing.T) {
		sig := contextSignals(mk("iam_user_administrator_access_policy", ""), runContext{})
		if len(sig) != 1 || sig[0].Code != "cloud.iam_wildcard" {
			t.Fatalf("got %+v, want cloud.iam_wildcard", sig)
		}
	})
	t.Run("privilege-escalation category", func(t *testing.T) {
		sig := contextSignals(mk("some_future_check", "privilege-escalation"), runContext{})
		if len(sig) != 1 || sig[0].Code != "cloud.iam_wildcard" {
			t.Fatalf("got %+v, want cloud.iam_wildcard", sig)
		}
	})
	t.Run("unknown is neutral", func(t *testing.T) {
		if sig := contextSignals(mk("s3_bucket_lifecycle_enabled", ""), runContext{}); len(sig) != 0 {
			t.Fatalf("no metadata must mean no delta, got %+v", sig)
		}
		if sig := contextSignals(mk("x", "resilience,gen-ai"), runContext{}); len(sig) != 0 {
			t.Fatalf("unlisted categories must be neutral, got %+v", sig)
		}
	})
	t.Run("positive only", func(t *testing.T) {
		for _, cats := range []string{"internet-exposed", "privilege-escalation", "encryption", "logging",
			"internet-exposed,privilege-escalation,encryption,logging"} {
			for _, s := range contextSignals(mk("iam_policy_allows_privilege_escalation", cats), runContext{}) {
				if s.Delta <= 0 {
					t.Errorf("cloud signal %s has non-positive delta %v — the table is positive-only by design", s.Code, s.Delta)
				}
			}
		}
	})
	t.Run("banding flows through unchanged", func(t *testing.T) {
		crit := model.SeverityCritical
		fs := []model.Finding{{
			Category: model.CategoryCloud, RuleID: "iam_group_administrator_access_policy",
			Severity: crit, ToolSeverity: &crit, Remediation: "detach",
		}}
		ApplyAndBand(fs)
		if fs[0].Severity != model.SeverityCritical {
			t.Errorf("banded severity = %v, want critical (det 10.0)", fs[0].Severity)
		}
	})
}
