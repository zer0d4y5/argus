package report

import (
	"os"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

// TestEmitSARIFForAJV writes a representative SARIF document (code + SCA +
// secret + CLOUD findings) to $APPSEC_SARIF_OUT when set, so the ajv schema
// validation harness (docs: node ajv+ajv-formats, ajv-cli chokes on the SARIF
// schemas) can run against a file that exercises the resource-URI fallback.
// A no-op in normal test runs.
func TestEmitSARIFForAJV(t *testing.T) {
	out := os.Getenv("APPSEC_SARIF_OUT")
	if out == "" {
		t.Skip("set APPSEC_SARIF_OUT to emit a SARIF file for ajv validation")
	}
	findings := append(sampleFindings(),
		model.Finding{
			ID: "cloud1", Tool: "prowler", Tools: []string{"prowler"},
			Category: model.CategoryCloud, RuleID: "s3_bucket_public_access",
			Title: "S3 bucket allows public access", Description: "public via ACL",
			Severity: model.SeverityHigh, Location: model.Location{Resource: "arn:aws:s3:::data-exports"},
			ComplianceControls: []string{"CIS-AWS:2.1"},
		},
		model.Finding{
			ID: "cloud2", Tool: "prowler", Tools: []string{"prowler"},
			Category: model.CategoryCloud, RuleID: "iam_user_administrator_access_policy",
			Title: "IAM user has AdministratorAccess", Severity: model.SeverityCritical,
			Location: model.Location{Resource: "arn:aws:iam::123456789012:user/deploy"},
		},
	)
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := WriteSARIF(f, findings); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote SARIF to %s", out)
}
