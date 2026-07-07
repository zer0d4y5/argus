package cloudremediate

import (
	"strings"
	"testing"

	"github.com/leaky-hub/argus/internal/model"
)

func cloudFinding(rule string, meta map[string]string) model.Finding {
	m := map[string]string{"provider": "aws"}
	for k, v := range meta {
		m[k] = v
	}
	return model.Finding{Category: model.CategoryCloud, RuleID: rule, Meta: m}
}

func TestApplicableMatching(t *testing.T) {
	cases := []struct {
		name string
		f    model.Finding
		want []string // expected remediation ids
	}{
		{"s3 public access",
			cloudFinding("s3_bucket_public_access", map[string]string{"service": "s3", "resourceName": "my-bucket"}),
			[]string{"aws-s3-block-public-access"}},
		{"s3 encryption",
			cloudFinding("s3_bucket_default_encryption", map[string]string{"service": "s3", "resourceName": "my-bucket"}),
			[]string{"aws-s3-default-encryption"}},
		{"ebs encryption",
			cloudFinding("ec2_ebs_default_encryption", map[string]string{"service": "ec2", "region": "us-east-1"}),
			[]string{"aws-ec2-ebs-encryption-by-default"}},
		{"s3 versioning",
			cloudFinding("s3_bucket_object_versioning", map[string]string{"service": "s3", "resourceName": "my-bucket"}),
			[]string{"aws-s3-enable-versioning"}},
		{"cloudtrail log validation",
			cloudFinding("cloudtrail_log_file_validation_enabled", map[string]string{"service": "cloudtrail", "resourceType": "AwsCloudTrailTrail", "resourceName": "org-trail"}),
			[]string{"aws-cloudtrail-log-file-validation"}},
		{"ec2 imdsv2",
			cloudFinding("ec2_instance_imdsv2_enabled", map[string]string{"service": "ec2", "resourceType": "AwsEc2Instance", "resourceName": "i-0abc1234"}),
			[]string{"aws-ec2-enforce-imdsv2"}},
		{"unrelated cloud finding",
			cloudFinding("iam_root_mfa_enabled", map[string]string{"service": "iam"}),
			nil},
		{"non-cloud finding never matches",
			model.Finding{Category: model.CategorySAST, RuleID: "s3_bucket_public_access"},
			nil},
		{"wrong provider",
			func() model.Finding { f := cloudFinding("s3_bucket_public_access", map[string]string{"service": "s3"}); f.Meta["provider"] = "gcp"; return f }(),
			nil},
	}
	for _, tc := range cases {
		got := Applicable(tc.f)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %d remediations, want %d (%v)", tc.name, len(got), len(tc.want), ids(got))
			continue
		}
		for i, id := range tc.want {
			if got[i].ID != id {
				t.Errorf("%s: [%d] = %s, want %s", tc.name, i, got[i].ID, id)
			}
		}
	}
}

func ids(rs []Remediation) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func TestBuildResolvesAndValidates(t *testing.T) {
	r, _ := ByID("aws-s3-block-public-access")
	f := cloudFinding("s3_bucket_public_access", map[string]string{"service": "s3", "resourceName": "prod-assets"})
	plan, err := Build(r, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Apply) != 1 || len(plan.DryRun) != 1 {
		t.Fatalf("plan commands wrong: %+v", plan)
	}
	joined := strings.Join(plan.Apply[0], " ")
	if !strings.Contains(joined, "prod-assets") || strings.Contains(joined, "{bucket}") {
		t.Errorf("apply not resolved: %q", joined)
	}
	if len(plan.Permissions) == 0 || !plan.Reversible {
		t.Errorf("plan metadata missing: %+v", plan)
	}
}

// TestBuildRejectsHostileResourceNames: a resource name that fails the grammar
// never reaches an argv slot, and a missing attribute is an honest error.
func TestBuildRejectsHostileResourceNames(t *testing.T) {
	r, _ := ByID("aws-s3-block-public-access")
	for _, bad := range []string{
		"bucket; rm -rf /",           // shell metacharacters
		"--profile hacker",           // flag injection attempt
		"$(curl evil)",               // command substitution
		"a",                          // too short for the grammar
		strings.Repeat("x", 100),     // too long
		"UPPER-case-not-allowed",     // S3 buckets are lowercase
	} {
		f := cloudFinding("s3_bucket_public_access", map[string]string{"service": "s3", "resourceName": bad})
		if _, err := Build(r, f); err == nil {
			t.Errorf("hostile bucket name accepted: %q", bad)
		}
	}
	// Missing attribute entirely.
	f := cloudFinding("s3_bucket_public_access", map[string]string{"service": "s3"})
	if _, err := Build(r, f); err == nil {
		t.Error("missing resourceName must error")
	}
}

func TestBuildRegionValidation(t *testing.T) {
	r, _ := ByID("aws-ec2-ebs-encryption-by-default")
	ok := cloudFinding("ec2_ebs_default_encryption", map[string]string{"service": "ec2", "region": "eu-west-1"})
	plan, err := Build(r, ok)
	if err != nil || plan.Region != "eu-west-1" {
		t.Fatalf("valid region: %v %+v", err, plan)
	}
	bad := cloudFinding("ec2_ebs_default_encryption", map[string]string{"service": "ec2", "region": "; evil"})
	if _, err := Build(r, bad); err == nil {
		t.Error("hostile region accepted")
	}
}

// TestCatalogNoDestructiveVerbs is a guard on the catalog itself: no apply
// template may contain a destructive verb, so a curated entry can never be a
// delete/terminate in disguise.
func TestCatalogNoDestructiveVerbs(t *testing.T) {
	banned := []string{"delete", "terminate", "remove", "rm", "destroy", "revoke", "detach", "disable", "drop"}
	for _, r := range Catalog {
		for _, tmpl := range r.Apply {
			joined := strings.ToLower(strings.Join(tmpl, " "))
			for _, b := range banned {
				if strings.Contains(joined, b) {
					t.Errorf("catalog entry %s apply contains banned verb %q: %v", r.ID, b, tmpl)
				}
			}
		}
		if len(r.Apply) == 0 || len(r.Permissions) == 0 {
			t.Errorf("catalog entry %s missing apply or permissions", r.ID)
		}
	}
}

// TestNewEntriesBuild validates the added fixes resolve their param and reject
// hostile values via the grammar.
func TestNewEntriesBuild(t *testing.T) {
	cases := []struct {
		id      string
		meta    map[string]string
		wantArg string // a token expected in the resolved apply command
		badName string // a value that must fail the grammar
	}{
		{"aws-s3-enable-versioning", map[string]string{"service": "s3", "resourceName": "prod-logs"}, "prod-logs", "Bad Bucket!"},
		{"aws-cloudtrail-log-file-validation", map[string]string{"service": "cloudtrail", "resourceType": "AwsCloudTrailTrail", "resourceName": "org-trail"}, "org-trail", "trail; rm -rf /"},
		{"aws-ec2-enforce-imdsv2", map[string]string{"service": "ec2", "resourceType": "AwsEc2Instance", "resourceName": "i-0abcdef12"}, "i-0abcdef12", "i-notvalid$(x)"},
	}
	for _, tc := range cases {
		r, ok := ByID(tc.id)
		if !ok {
			t.Fatalf("catalog missing %s", tc.id)
		}
		// figure out the check keyword-carrying rule id from the entry
		f := cloudFinding("x_"+strings.Join(r.CheckKeywords, "_")+"_y", tc.meta)
		plan, err := Build(r, f)
		if err != nil {
			t.Fatalf("%s build: %v", tc.id, err)
		}
		if !strings.Contains(strings.Join(plan.Apply[0], " "), tc.wantArg) {
			t.Errorf("%s apply missing %q: %v", tc.id, tc.wantArg, plan.Apply[0])
		}
		bad := tc.meta
		badCopy := map[string]string{}
		for k, v := range bad {
			badCopy[k] = v
		}
		badCopy["resourceName"] = tc.badName
		if _, err := Build(r, cloudFinding("x_"+strings.Join(r.CheckKeywords, "_")+"_y", badCopy)); err == nil {
			t.Errorf("%s accepted hostile value %q", tc.id, tc.badName)
		}
	}
}

