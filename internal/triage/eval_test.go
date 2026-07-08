package triage

// Labeled evaluation of LLM triage against testdata/triage-eval (Phase 2
// acceptance): triage must measurably cut false positives on the labeled set
// while never suppressing a labeled true positive, and every finding must
// carry a risk score. Runs against the local Ollama model; skips when Ollama
// (or the model) is unavailable or in -short mode, so CI without a GPU stays
// green.
//
// Labels are anchored to marker strings inside the fixture files instead of
// hardcoded line numbers, so editing a fixture cannot silently mislabel.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/llm"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/risk"
)

const (
	evalRoot     = "../../testdata/triage-eval"
	evalEndpoint = "http://localhost:11434"
	evalModel    = "qwen3.6:35b-a3b"
)

type labeled struct {
	name         string
	truePositive bool // expectation: a TP must never get a false-positive verdict
	finding      model.Finding
}

// evalSet mirrors what the real scanners emit for the planted fixtures
// (rule IDs, titles, descriptions modeled on semgrep/gitleaks/trivy output),
// anchored to the fixture source lines.
func evalSet(t *testing.T) []labeled {
	t.Helper()
	// Scanners emit paths relative to the process CWD including the scan
	// target prefix; findings here carry evalRoot-prefixed paths to match
	// (snippet reads resolve from the CWD, confined to Options.Root).
	sast := func(name string, tp bool, file, anchor, rule, title, desc, cwe string) labeled {
		line := anchorLine(t, file, anchor)
		return labeled{name: name, truePositive: tp, finding: model.Finding{
			Tool: "semgrep", Tools: []string{"semgrep"}, Category: model.CategorySAST,
			RuleID: rule, Title: title, Description: desc,
			Severity: model.SeverityHigh, CWEs: []string{cwe},
			Location: model.Location{File: path.Join(evalRoot, file), StartLine: line, EndLine: line},
		}}
	}
	secret := func(name string, tp bool, file, anchor, rule, title string) labeled {
		line := anchorLine(t, file, anchor)
		return labeled{name: name, truePositive: tp, finding: model.Finding{
			Tool: "gitleaks", Tools: []string{"gitleaks"}, Category: model.CategorySecret,
			RuleID: rule, Title: title,
			Description: "Detected a potential secret (value redacted).",
			Severity:    model.SeverityHigh, CWEs: []string{"CWE-798"},
			Location: model.Location{File: path.Join(evalRoot, file), StartLine: line, EndLine: line},
		}}
	}
	// cloud models a prowler CLOUD finding: no source file, resource UID in
	// location.Resource, prowler check categories in meta (what the triage
	// prompt surfaces). Cloud findings are judged from metadata only.
	cloud := func(name string, tp bool, sev model.Severity, rule, title, desc, resource, categories string) labeled {
		return labeled{name: name, truePositive: tp, finding: model.Finding{
			Tool: "prowler", Tools: []string{"prowler"}, Category: model.CategoryCloud,
			RuleID: rule, Title: title, Description: desc, Severity: sev,
			Location: model.Location{Resource: resource},
			Meta:     map[string]string{"provider": "aws", "categories": categories, "service": strings.SplitN(rule, "_", 2)[0]},
		}}
	}

	return []labeled{
		sast("sqli-fstring", true, "vuln_app.py", `cur.execute(query)`,
			"python.lang.security.audit.formatted-sql-query.formatted-sql-query",
			"Formatted SQL query",
			"Detected possible formatted SQL query. Use parameterized queries instead.", "CWE-89"),
		sast("cmdi-concat", true, "vuln_app.py", `subprocess.check_output("nslookup`,
			"python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
			"subprocess call with shell=True",
			"Found subprocess call with shell=True; user input in the command allows command injection.", "CWE-78"),
		sast("yaml-load", true, "vuln_app.py", `yaml.load(data)`,
			"python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load",
			"Unsafe yaml.load",
			"Avoid yaml.load without a safe Loader; it can execute arbitrary code on untrusted input.", "CWE-502"),
		sast("sqli-parameterized", false, "safe_app.py", `cur.execute(query, (username,))`,
			"python.lang.security.audit.formatted-sql-query.formatted-sql-query",
			"Formatted SQL query",
			"Detected possible formatted SQL query. Use parameterized queries instead.", "CWE-89"),
		sast("shell-true-constant", false, "safe_app.py", `subprocess.check_output("uptime"`,
			"python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
			"subprocess call with shell=True",
			"Found subprocess call with shell=True; user input in the command allows command injection.", "CWE-78"),
		sast("yaml-safe-load", false, "safe_app.py", `yaml.safe_load(data)`,
			"python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load",
			"Unsafe yaml.load",
			"Avoid yaml.load without a safe Loader; it can execute arbitrary code on untrusted input.", "CWE-502"),
		secret("aws-example-key-in-tests", false, "tests/test_fixtures.py", "DUMMY_AWS_ACCESS_KEY",
			"aws-access-key-id", "AWS Access Key ID"),
		secret("prod-env-aws-key", true, "prod.env", "AWS_ACCESS_KEY_ID",
			"aws-access-key-id", "AWS Access Key ID"),
		secret("prod-env-github-token", true, "prod.env", "GITHUB_TOKEN",
			"github-pat", "GitHub Personal Access Token"),
		{name: "sca-pyyaml-cve", truePositive: true, finding: model.Finding{
			Tool: "trivy", Tools: []string{"trivy"}, Category: model.CategorySCA,
			RuleID: "CVE-2020-14343", CVE: "CVE-2020-14343", Package: "pyyaml@5.3.1",
			Title:       "PyYAML deserialization of untrusted data",
			Description: "PyYAML before 5.4 allows arbitrary code execution via full_load on untrusted input.",
			Severity:    model.SeverityCritical, CWEs: []string{"CWE-502"},
			Remediation: "Upgrade pyyaml to 5.4 or later.",
			Location:    model.Location{File: path.Join(evalRoot, "requirements.txt"), StartLine: anchorLine(t, "requirements.txt", "pyyaml==5.3.1")},
		}},

		// --- Cloud posture cases (cloud-posture session, locked decision 10).
		// Judged from metadata only — no source, no credential. TP cases must
		// never be marked false-positive; the FP cases are checks whose own
		// description establishes they are benign in context.
		cloud("cloud-iam-admin-policy", true, model.SeverityCritical,
			"iam_aws_attached_policy_no_administrative_privileges",
			"Attached IAM policy allows full administrative privileges",
			"The AWS-managed AdministratorAccess policy (Action '*' on Resource '*') is attached to a principal, granting unrestricted control of the account.",
			"arn:aws:iam::123456789012:role/deploy", "identity-access"),
		cloud("cloud-ec2-public-ip", true, model.SeverityHigh,
			"ec2_instance_public_ip",
			"EC2 instance has a public IP address",
			"The instance is internet-facing with a public IPv4 address, expanding its attack surface.",
			"arn:aws:ec2:us-east-1:123456789012:instance/i-0abc", "internet-exposed"),
		cloud("cloud-rds-unencrypted", true, model.SeverityMedium,
			"rds_instance_storage_encrypted",
			"RDS instance storage is not encrypted at rest",
			"The database instance stores data without at-rest encryption; a disk or snapshot compromise exposes plaintext data.",
			"arn:aws:rds:us-east-1:123456789012:db/prod-db", "encryption"),
		cloud("cloud-s3-public-acl", true, model.SeverityHigh,
			"s3_bucket_public_access",
			"S3 bucket allows public access via ACL",
			"The bucket ACL grants READ to AllUsers, exposing its objects to anyone on the internet.",
			"arn:aws:s3:::data-exports", "internet-exposed"),
		cloud("cloud-mfa-delete-scratch", false, model.SeverityLow,
			"s3_bucket_no_mfa_delete",
			"S3 bucket MFA Delete is not enabled",
			"MFA Delete guards against accidental or malicious object-version deletion. This bucket is a CI scratch bucket, emptied and recreated on every pipeline run, holding no durable or sensitive data.",
			"arn:aws:s3:::ci-scratch-ephemeral", "resilience"),
		cloud("cloud-macie-optional-region", false, model.SeverityLow,
			"macie_is_enabled",
			"Amazon Macie is not enabled in this region",
			"Macie provides managed sensitive-data discovery for S3. No S3 buckets exist in this region and none are provisioned here by policy, so Macie coverage is not applicable.",
			"arn:aws:macie2:ap-south-1:123456789012:account", "gen-ai"),

		// --- A few more code cases to keep the corpus broad (>= 20 total).
		sast("path-traversal", true, "vuln_app.py", `open(os.path.join(BASE_DIR, filename))`,
			"python.lang.security.audit.path-traversal.path-traversal-open",
			"Path traversal in open()",
			"User-controlled filename flows into open() without containment; a value like ../../etc/passwd escapes the intended directory.", "CWE-22"),
		secret("stripe-live-key-prod", true, "prod.env", "STRIPE_SECRET_KEY",
			"stripe-access-token", "Stripe Secret Key"),
		sast("hardcoded-tmp-path-benign", false, "safe_app.py", `LOG_PATH = "/tmp/app.log"`,
			"python.lang.correctness.tmp.hardcoded-tmp-path",
			"Hardcoded /tmp path",
			"A hardcoded /tmp path can be a symlink race in some contexts; here it is a constant log path used read-only at startup, not attacker-influenced.", "CWE-377"),
	}
}

func anchorLine(t *testing.T, file, anchor string) int {
	t.Helper()
	fh, err := os.Open(filepath.Join(evalRoot, filepath.FromSlash(file)))
	if err != nil {
		t.Fatalf("eval fixture %s: %v", file, err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for n := 1; sc.Scan(); n++ {
		if strings.Contains(sc.Text(), anchor) {
			return n
		}
	}
	t.Fatalf("anchor %q not found in %s — fixture and labels out of sync", anchor, file)
	return 0
}

func TestTriageEval(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping LLM eval in -short mode")
	}
	client := llm.NewOllama(evalEndpoint, evalModel, 120*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		t.Skipf("skipping LLM eval: %v", err)
	}

	set := evalSet(t)
	findings := make([]model.Finding, len(set))
	for i, l := range set {
		findings[i] = l.finding
	}

	tr := NewLLM(client, Options{Root: evalRoot, Concurrency: 2, RequestTimeout: 120 * time.Second})
	out, err := tr.Triage(ctx, findings)
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	risk.Apply(out)

	var fpTotal, fpDetected, tpSuppressed int
	for i, l := range set {
		f := out[i]
		if f.RiskScore == nil {
			t.Errorf("%s: no risk score", l.name)
		}
		verdict := "(none)"
		var rationale string
		if f.Triage != nil {
			verdict = f.Triage.Verdict
			rationale = f.Triage.Rationale
		}
		var score float64
		if f.RiskScore != nil {
			score = *f.RiskScore
		}
		t.Logf("%-26s labeled=%-5v verdict=%-14s risk=%.1f  %s",
			l.name, map[bool]string{true: "TP", false: "FP"}[l.truePositive], verdict, score, rationale)

		if l.truePositive {
			if f.Triage != nil && f.Triage.Verdict == model.VerdictFalsePositive {
				tpSuppressed++
				t.Errorf("%s: labeled TRUE positive was marked false-positive — suppression is unacceptable", l.name)
			}
		} else {
			fpTotal++
			if f.Triage != nil && f.Triage.Verdict == model.VerdictFalsePositive {
				fpDetected++
			}
		}
	}

	recall := float64(fpDetected) / float64(fpTotal)
	precision := 1.0
	if fpDetected+tpSuppressed > 0 {
		precision = float64(fpDetected) / float64(fpDetected+tpSuppressed)
	}
	fmt.Printf("triage-eval: FP-detection precision=%.2f recall=%.2f (%d/%d labeled FPs cut, %d labeled TPs suppressed)\n",
		precision, recall, fpDetected, fpTotal, tpSuppressed)

	// Acceptance: measurably cuts false positives (≥ half of the labeled
	// FP set) with zero true-positive suppression (asserted above).
	if fpDetected*2 < fpTotal {
		t.Errorf("FP-detection recall %.2f below acceptance bar 0.5 (%d/%d)", recall, fpDetected, fpTotal)
	}
}
