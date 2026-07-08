package risk

import (
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func fp(v float64) *float64 { return &v }

// TestWorkedExamples pins the exact worked examples from docs/risk-scoring.md.
// If this test needs changing, the doc changes with it.
func TestWorkedExamples(t *testing.T) {
	cases := []struct {
		name string
		f    model.Finding
		want float64
	}{
		{
			name: "semgrep SQLi TP",
			f: model.Finding{
				Severity: model.SeverityHigh, Category: model.CategorySAST,
				CWEs:   []string{"CWE-89"},
				Triage: &model.Triage{Verdict: model.VerdictTruePositive, Confidence: 0.9},
			},
			want: 8.4,
		},
		{
			name: "gitleaks AWS key untriaged",
			f: model.Finding{
				Severity: model.SeverityHigh, Category: model.CategorySecret,
				CWEs: []string{"CWE-798"},
			},
			want: 8.5,
		},
		{
			name: "trivy critical CVE with fix",
			f: model.Finding{
				Severity: model.SeverityCritical, Category: model.CategorySCA,
				Remediation: "upgrade to 2.1.4",
			},
			want: 9.3,
		},
		{
			name: "shell=True constant marked FP",
			f: model.Finding{
				Severity: model.SeverityMedium, Category: model.CategorySAST,
				Triage: &model.Triage{Verdict: model.VerdictFalsePositive, Confidence: 1.0},
			},
			want: 1.0,
		},
		{
			name: "example secret marked FP",
			f: model.Finding{
				Severity: model.SeverityHigh, Category: model.CategorySecret,
				CWEs:   []string{"CWE-798"},
				Triage: &model.Triage{Verdict: model.VerdictFalsePositive, Confidence: 0.8},
			},
			want: 5.3,
		},
		{
			// Worked example #14: 9.25 baseline + 0.75 iam wildcard = 10.0.
			name: "prowler admin policy critical",
			f: model.Finding{
				Severity: model.SeverityCritical, Category: model.CategoryCloud,
				RuleID:      "iam_aws_attached_policy_no_administrative_privileges",
				Remediation: "detach the policy",
			},
			want: 10.0,
		},
		{
			// Worked example #15: 7.25 + 0.75 public exposure = 8.0.
			name: "prowler public EC2 instance high",
			f: model.Finding{
				Severity: model.SeverityHigh, Category: model.CategoryCloud,
				RuleID:      "ec2_instance_public_ip",
				Remediation: "remove the public IP",
				Meta:        map[string]string{"categories": "internet-exposed"},
			},
			want: 8.0,
		},
		{
			// Worked example #16: 5.25 + 0.25 unencrypted at rest = 5.5.
			name: "prowler unencrypted bucket medium",
			f: model.Finding{
				Severity: model.SeverityMedium, Category: model.CategoryCloud,
				RuleID:      "s3_bucket_kms_encryption",
				Remediation: "enable KMS encryption",
				Meta:        map[string]string{"categories": "encryption"},
			},
			want: 5.5,
		},
		{
			// Worked example #17: 3.25 + 0.25 logging disabled = 3.5.
			name: "prowler logging gap low",
			f: model.Finding{
				Severity: model.SeverityLow, Category: model.CategoryCloud,
				RuleID:      "s3_bucket_server_access_logging_enabled",
				Remediation: "enable access logging",
				Meta:        map[string]string{"categories": "logging"},
			},
			want: 3.5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := []model.Finding{tc.f}
			Apply(fs)
			if fs[0].RiskScore == nil {
				t.Fatal("RiskScore not set")
			}
			if got := *fs[0].RiskScore; got != tc.want {
				t.Errorf("score = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEveryFindingScored(t *testing.T) {
	fs := []model.Finding{
		{Severity: model.SeverityInfo},
		{Severity: model.SeverityCritical, Category: model.CategorySecret, CWEs: []string{"CWE-798"}, Confidence: "HIGH", Remediation: "rotate"},
		{}, // zero value
	}
	Apply(fs)
	for i, f := range fs {
		if f.RiskScore == nil {
			t.Fatalf("finding %d has no risk score", i)
		}
		if *f.RiskScore < 0 || *f.RiskScore > 10 {
			t.Fatalf("finding %d score %v out of [0,10]", i, *f.RiskScore)
		}
	}
}

// TestBounds: a hostile/hallucinating model can move a score at most
// -4.0/+1.0 from baseline, and an FP verdict can never zero a finding out.
func TestBounds(t *testing.T) {
	base := model.Finding{Severity: model.SeverityLow, Category: model.CategorySAST}

	tp := base
	tp.Triage = &model.Triage{Verdict: model.VerdictTruePositive, Confidence: 99} // out-of-range confidence
	fs := []model.Finding{tp}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 4.0 { // 3.0 + capped 1.0*1
		t.Errorf("TP with wild confidence = %v, want 4.0", got)
	}

	fpF := base
	fpF.Triage = &model.Triage{Verdict: model.VerdictFalsePositive, Confidence: 1}
	fpF.Severity = model.SeverityInfo // baseline 1.0, adjustment -4 → floored
	fs = []model.Finding{fpF}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 0.5 {
		t.Errorf("FP floor = %v, want 0.5", got)
	}

	unk := base
	unk.Triage = &model.Triage{Verdict: "delete-everything", Confidence: 1} // unknown verdict: no adjustment
	fs = []model.Finding{unk}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 3.0 {
		t.Errorf("unknown verdict adjusted the score: %v, want 3.0", got)
	}
}

func TestConfidenceModifiers(t *testing.T) {
	for _, tc := range []struct {
		conf string
		want float64
	}{
		{"high", 5.5}, {"HIGH", 5.5}, {"low", 4.0}, {"medium", 5.0}, {"", 5.0}, {"weird", 5.0},
	} {
		f := model.Finding{Severity: model.SeverityMedium, Confidence: tc.conf}
		if got := Baseline(f); got != tc.want {
			t.Errorf("confidence %q: baseline = %v, want %v", tc.conf, got, tc.want)
		}
	}
}

// TestBaselineUsesToolSeverity pins the anti-circularity property of schema
// 2.0.0: stage 1 reads the tool-normalized severity (ToolSeverity), never the
// banded output Severity. Otherwise banding would feed its own output back
// into the next score and self-amplify.
func TestBaselineUsesToolSeverity(t *testing.T) {
	low := model.SeverityLow
	f := model.Finding{
		Category:     model.CategorySAST,
		Severity:     model.SeverityCritical, // banded output — must be ignored
		ToolSeverity: &low,                   // stage-1 input
	}
	if got := Baseline(f); got != 3.0 {
		t.Errorf("Baseline = %v, want 3.0 (from toolSeverity=low, not severity=critical)", got)
	}
	// Old-document fallback: no ToolSeverity means the stored severity IS the
	// tool-normalized value, so it is the correct stage-1 input.
	f.ToolSeverity = nil
	if got := Baseline(f); got != 9.0 {
		t.Errorf("Baseline = %v, want 9.0 (stored severity fallback for ≤1.4.0 docs)", got)
	}
}

// TestDeterministicScoreReturned: Apply's return value is the stage-2 score —
// worked example #8 of docs/risk-scoring.md: det 7.5, final (stored) 8.4.
func TestDeterministicScoreReturned(t *testing.T) {
	fs := []model.Finding{{
		Severity: model.SeverityHigh, Category: model.CategorySAST,
		CWEs:     []string{"CWE-89"},
		Location: model.Location{File: "src/api/users.py"},
		Triage:   &model.Triage{Verdict: model.VerdictTruePositive, Confidence: 0.9},
	}}
	det := Apply(fs)
	if len(det) != 1 || det[0] != 7.5 {
		t.Fatalf("deterministic score = %v, want [7.5]", det)
	}
	if *fs[0].RiskScore != 8.4 {
		t.Errorf("stored riskScore = %v, want stage-3 8.4", *fs[0].RiskScore)
	}
}

// TestTriageFlipMovesScoreNeverSeverity is the load-bearing safety property
// of severity banding: flipping a triage verdict changes riskScore within its
// bounds but can NEVER change the deterministic score — and therefore never
// the banded severity or the gate.
func TestTriageFlipMovesScoreNeverSeverity(t *testing.T) {
	mk := func(tr *model.Triage) []model.Finding {
		return []model.Finding{{
			Severity: model.SeverityHigh, Category: model.CategorySAST,
			CWEs:     []string{"CWE-89"},
			Location: model.Location{File: "src/api/users.py"},
			Triage:   tr,
		}}
	}
	verdicts := []*model.Triage{
		nil,
		{Verdict: model.VerdictTruePositive, Confidence: 1.0},
		{Verdict: model.VerdictFalsePositive, Confidence: 1.0},
		{Verdict: model.VerdictUncertain, Confidence: 1.0},
	}
	var dets []float64
	var finals []float64
	var sevs []model.Severity
	for _, v := range verdicts {
		fs := mk(v)
		det := Apply(fs)
		dets = append(dets, det[0])
		finals = append(finals, *fs[0].RiskScore)
		sevs = append(sevs, model.SeverityForScore(det[0]))
	}
	for i := 1; i < len(dets); i++ {
		if dets[i] != dets[0] {
			t.Errorf("verdict %d moved the deterministic score: %v != %v", i, dets[i], dets[0])
		}
		if sevs[i] != sevs[0] {
			t.Errorf("verdict %d moved the banded severity: %v != %v", i, sevs[i], sevs[0])
		}
	}
	// The verdicts DO move the stored riskScore (that is their job):
	// none 7.5, TP@1.0 8.5, FP@1.0 3.5, uncertain 7.5.
	wantFinals := []float64{7.5, 8.5, 3.5, 7.5}
	for i := range finals {
		if finals[i] != wantFinals[i] {
			t.Errorf("verdict %d riskScore = %v, want %v", i, finals[i], wantFinals[i])
		}
	}
	if sevs[0] != model.SeverityHigh {
		t.Errorf("banded severity = %v, want high (det 7.5)", sevs[0])
	}
}

// TestApplyAndBand: the end-to-end banding step. The flagship demo contrast —
// worked example #5: a gitleaks secret (tool says HIGH) in a fixtures path
// with entropy 2.1 lands at det 5.0 → banded MEDIUM, while the same secret on
// a prod path with DS-0031 co-location (#3) reaches det 9.4 → banded CRITICAL.
func TestApplyAndBand(t *testing.T) {
	high := model.SeverityHigh
	fixture := model.Finding{
		Category: model.CategorySecret, Severity: high, ToolSeverity: &high,
		RuleID:   "aws-access-token",
		Location: model.Location{File: "testdata/fixtures/creds.env"},
		Meta:     map[string]string{"entropy": "2.1"},
	}
	prod := model.Finding{
		Category: model.CategorySecret, Severity: high, ToolSeverity: &high,
		RuleID:   "aws-access-token",
		Location: model.Location{File: "deploy/Dockerfile"},
		Meta:     map[string]string{"entropy": "5.2"},
	}
	ds := model.Finding{
		Category: model.CategoryIaC, Severity: model.SeverityCritical, RuleID: "DS-0031",
		Location:    model.Location{File: "deploy/Dockerfile"},
		Meta:        map[string]string{"message": `Possible exposure of secret env "AWS_SECRET_ACCESS_KEY" in ENV`},
		Remediation: "Do not store secrets in ENV",
	}
	fs := []model.Finding{fixture, prod, ds}
	ApplyAndBand(fs)

	if fs[0].Severity != model.SeverityMedium {
		t.Errorf("fixtures secret banded %v, want medium (det 5.0; tool said high)", fs[0].Severity)
	}
	if fs[1].Severity != model.SeverityCritical {
		t.Errorf("corroborated prod secret banded %v, want critical (det 9.4)", fs[1].Severity)
	}
	// ToolSeverity is untouched — the "tool said" audit trail survives banding.
	if fs[0].ToolSeverity == nil || *fs[0].ToolSeverity != model.SeverityHigh {
		t.Error("banding must never touch toolSeverity")
	}

	// The gate reads the banded severity: this is the point of the change.
	// A "high" gate over ONLY the fixtures secret (tool said high, banded
	// medium) passes; over the corroborated prod secret (banded critical)
	// it fails.
	gate := model.SeverityHigh
	if model.GateExceeded(fs[:1], &gate) {
		t.Error("fixtures secret (banded medium) must not trip a high gate despite tool severity high")
	}
	if !model.GateExceeded(fs[1:2], &gate) {
		t.Error("corroborated prod secret (banded critical) must trip a high gate")
	}
}
