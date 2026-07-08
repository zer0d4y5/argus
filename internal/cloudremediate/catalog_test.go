package cloudremediate

import (
	"regexp"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func cloudFinding(rule string, meta map[string]string) model.Finding {
	m := map[string]string{"provider": "aws"}
	for k, v := range meta {
		m[k] = v
	}
	return model.Finding{Category: model.CategoryCloud, RuleID: rule, Meta: m}
}

// providerFinding builds a cloud finding for any provider, with the resource
// UID (Azure ARM id / ARN) in its Location like the normalizer puts it.
func providerFinding(provider, rule, resourceUID string, meta map[string]string) model.Finding {
	f := cloudFinding(rule, meta)
	f.Meta["provider"] = provider
	f.Location.Resource = resourceUID
	return f
}

// A well-formed Azure ARM id for a storage account, used across the tests.
const testARMID = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/prodassets"

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
		{"aws snapshot block public access",
			cloudFinding("ec2_ebs_snapshot_account_block_public_access", map[string]string{"service": "ec2", "region": "us-east-1"}),
			[]string{"aws-ebs-snapshot-block-public-access"}},
		{"aws public ami",
			cloudFinding("ec2_ami_public", map[string]string{"service": "ec2", "resourceName": "ami-0abc12345", "region": "us-east-1"}),
			[]string{"aws-ec2-ami-make-private"}},
		{"aws iam password policy",
			cloudFinding("iam_password_policy_minimum_length_14", map[string]string{"service": "iam"}),
			[]string{"aws-iam-strong-password-policy"}},
		{"azure blob public access",
			providerFinding("azure", "storage_blob_public_access_level_is_disabled", testARMID, map[string]string{"service": "storage", "resourceType": "microsoft.storage/storageaccounts", "resourceName": "prodassets"}),
			[]string{"azure-storage-disallow-blob-public-access"}},
		{"azure secure transfer",
			providerFinding("azure", "storage_secure_transfer_required_is_enabled", testARMID, map[string]string{"service": "storage", "resourceName": "prodassets"}),
			[]string{"azure-storage-require-secure-transfer"}},
		{"azure minimum tls",
			providerFinding("azure", "storage_ensure_minimum_tls_version_12", testARMID, map[string]string{"service": "storage", "resourceName": "prodassets"}),
			[]string{"azure-storage-minimum-tls-12"}},
		{"azure public NETWORK access is not the blob fix",
			providerFinding("azure", "storage_account_public_network_access_disabled", testARMID, map[string]string{"service": "storage"}),
			nil},
		{"azure blob versioning does not leak to the aws or gcp versioning fixes",
			providerFinding("azure", "storage_blob_versioning_is_enabled", testARMID, map[string]string{"service": "storage", "resourceName": "prodassets"}),
			nil},
		{"gcp bucket public access",
			providerFinding("gcp", "cloudstorage_bucket_public_access", "", map[string]string{"service": "cloudstorage", "resourceName": "my-bucket"}),
			[]string{"gcp-storage-public-access-prevention"}},
		{"gcp uniform bucket level access",
			providerFinding("gcp", "cloudstorage_bucket_uniform_bucket_level_access", "", map[string]string{"service": "cloudstorage", "resourceName": "my-bucket"}),
			[]string{"gcp-storage-uniform-bucket-level-access"}},
		{"gcp bucket versioning does not match the aws s3 versioning fix",
			providerFinding("gcp", "cloudstorage_bucket_versioning_enabled", "", map[string]string{"service": "cloudstorage", "resourceType": "storage.googleapis.com/Bucket", "resourceName": "my-bucket"}),
			[]string{"gcp-storage-enable-versioning"}},
		{"gcp project os login",
			providerFinding("gcp", "compute_project_os_login_enabled", "", map[string]string{"service": "compute", "account": "prod-project-123"}),
			[]string{"gcp-compute-project-os-login"}},
		{"gcp os login 2fa is NOT the os login fix",
			providerFinding("gcp", "compute_project_os_login_2fa_enabled", "", map[string]string{"service": "compute", "account": "prod-project-123"}),
			nil},
		{"unrelated cloud finding",
			cloudFinding("iam_root_mfa_enabled", map[string]string{"service": "iam"}),
			nil},
		{"non-cloud finding never matches",
			model.Finding{Category: model.CategorySAST, RuleID: "s3_bucket_public_access"},
			nil},
		{"wrong provider",
			func() model.Finding {
				f := cloudFinding("s3_bucket_public_access", map[string]string{"service": "s3"})
				f.Meta["provider"] = "gcp"
				return f
			}(),
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
		"bucket; rm -rf /",       // shell metacharacters
		"--profile hacker",       // flag injection attempt
		"$(curl evil)",           // command substitution
		"a",                      // too short for the grammar
		strings.Repeat("x", 100), // too long
		"UPPER-case-not-allowed", // S3 buckets are lowercase
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

// TestCatalogSelfGuard is a guard on the catalog itself: no template may
// contain a destructive verb (so a curated entry can never be a
// delete/terminate in disguise), every entry's commands invoke only its own
// provider's CLI, and every entry carries the full reviewed metadata. Verbs
// match on word boundaries: hyphenated subcommands count ("remove-iam-policy-
// binding" trips it), substrings inside a word do not ("unifoRM").
func TestCatalogSelfGuard(t *testing.T) {
	binaries := map[string]string{"aws": "aws", "azure": "az", "gcp": "gcloud"}
	banned := regexp.MustCompile(`(?i)\b(delete|terminate|remove|rm|destroy|revoke|detach|disable|drop|purge|abandon|mkfs)\b`)
	for _, r := range Catalog {
		bin, known := binaries[r.Provider]
		if !known {
			t.Errorf("catalog entry %s has unknown provider %q", r.ID, r.Provider)
			continue
		}
		if !strings.HasPrefix(r.ID, r.Provider+"-") {
			t.Errorf("catalog entry %s: id must be prefixed with its provider", r.ID)
		}
		for _, tmpl := range append(append([][]string{}, r.DryRun...), r.Apply...) {
			if len(tmpl) == 0 || tmpl[0] != bin {
				t.Errorf("catalog entry %s: command must invoke %q: %v", r.ID, bin, tmpl)
				continue
			}
			for _, tok := range tmpl {
				if banned.MatchString(tok) {
					t.Errorf("catalog entry %s contains banned verb in %q: %v", r.ID, tok, tmpl)
				}
			}
		}
		if len(r.DryRun) == 0 || len(r.Apply) == 0 || len(r.Permissions) == 0 {
			t.Errorf("catalog entry %s missing dry-run, apply, or permissions", r.ID)
		}
		if !r.Reversible || r.ReversalNote == "" {
			t.Errorf("catalog entry %s must be reversible with a reversal note", r.ID)
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

// TestProviderEntriesBuild: every Azure/GCP entry and the new AWS entries
// resolve their params from a well-formed finding, stamp the provider on the
// plan, and reject hostile values through the grammar, for every param
// source, including the ARM id and the project id.
func TestProviderEntriesBuild(t *testing.T) {
	hostileARMIDs := []string{
		"",
		"/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", // wrong resource type
		"/subscriptions/not-a-guid/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",                            // bad subscription
		testARMID + " --set allowSharedKeyAccess=true",                                                                          // flag smuggling
		testARMID + ";rm -rf /", // shell injection
		"/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/../providers/Microsoft.Storage/storageAccounts/sa", // traversal-shaped group
		"$(curl evil)",
	}
	hostileBuckets := []string{"", "MyBucket", "b", "bucket;rm -rf /", "--flag", "$(curl evil)", strings.Repeat("x", 80)}
	hostileProjects := []string{"", "UPPER", "p j", "proj;id", "--quiet", "1starts-with-digit", "ab"}

	azure := func(rule string) model.Finding {
		return providerFinding("azure", rule, testARMID, map[string]string{"service": "storage", "resourceName": "prodassets"})
	}
	gcpBucket := func(rule string) model.Finding {
		return providerFinding("gcp", rule, "", map[string]string{"service": "cloudstorage", "resourceName": "my-bucket"})
	}

	cases := []struct {
		id      string
		f       model.Finding
		wantArg string // a token expected in the resolved apply command
		mutate  func(f *model.Finding, v string)
		hostile []string
	}{
		{"azure-storage-disallow-blob-public-access", azure("storage_blob_public_access_level_is_disabled"),
			"--allow-blob-public-access",
			func(f *model.Finding, v string) { f.Location.Resource = v }, hostileARMIDs},
		{"azure-storage-require-secure-transfer", azure("storage_secure_transfer_required_is_enabled"),
			"--https-only",
			func(f *model.Finding, v string) { f.Location.Resource = v }, hostileARMIDs},
		{"azure-storage-minimum-tls-12", azure("storage_ensure_minimum_tls_version_12"),
			"TLS1_2",
			func(f *model.Finding, v string) { f.Location.Resource = v }, hostileARMIDs},
		{"gcp-storage-public-access-prevention", gcpBucket("cloudstorage_bucket_public_access"),
			"gs://my-bucket",
			func(f *model.Finding, v string) { f.Meta["resourceName"] = v }, hostileBuckets},
		{"gcp-storage-uniform-bucket-level-access", gcpBucket("cloudstorage_bucket_uniform_bucket_level_access"),
			"--uniform-bucket-level-access",
			func(f *model.Finding, v string) { f.Meta["resourceName"] = v }, hostileBuckets},
		{"gcp-storage-enable-versioning", gcpBucket("cloudstorage_bucket_versioning_enabled"),
			"--versioning",
			func(f *model.Finding, v string) { f.Meta["resourceName"] = v }, hostileBuckets},
		{"gcp-compute-project-os-login",
			providerFinding("gcp", "compute_project_os_login_enabled", "", map[string]string{"service": "compute", "account": "prod-project-123"}),
			"enable-oslogin=TRUE",
			func(f *model.Finding, v string) { f.Meta["account"] = v }, hostileProjects},
		{"aws-ebs-snapshot-block-public-access",
			cloudFinding("ec2_ebs_snapshot_account_block_public_access", map[string]string{"service": "ec2", "region": "eu-west-1"}),
			"block-all-sharing",
			func(f *model.Finding, v string) { f.Meta["region"] = v }, []string{"", "us east 1", "region;rm", "--region"}},
		{"aws-ec2-ami-make-private",
			cloudFinding("ec2_ami_public", map[string]string{"service": "ec2", "resourceName": "ami-0abc12345", "region": "us-east-1"}),
			"reset-image-attribute",
			func(f *model.Finding, v string) { f.Meta["resourceName"] = v }, []string{"", "ami-XYZ", "i-0abc12345", "ami-0abc12345;rm", "snap-0abc12345"}},
	}
	for _, tc := range cases {
		r, ok := ByID(tc.id)
		if !ok {
			t.Fatalf("catalog missing %s", tc.id)
		}
		plan, err := Build(r, tc.f)
		if err != nil {
			t.Errorf("%s build: %v", tc.id, err)
			continue
		}
		if plan.Provider != r.Provider {
			t.Errorf("%s plan provider = %q, want %q", tc.id, plan.Provider, r.Provider)
		}
		joined := strings.Join(plan.Apply[0], " ")
		if !strings.Contains(joined, tc.wantArg) || strings.Contains(joined, "{") {
			t.Errorf("%s apply not resolved: %q", tc.id, joined)
		}
		for _, bad := range tc.hostile {
			f := providerFinding(tc.f.Meta["provider"], tc.f.RuleID, tc.f.Location.Resource, tc.f.Meta)
			tc.mutate(&f, bad)
			if _, err := Build(r, f); err == nil {
				t.Errorf("%s accepted hostile value %q", tc.id, bad)
			}
		}
	}
}

// TestIAMPasswordPolicyBuilds: the one parameterless entry builds against a
// bare finding and resolves to fixed argv only.
func TestIAMPasswordPolicyBuilds(t *testing.T) {
	r, ok := ByID("aws-iam-strong-password-policy")
	if !ok {
		t.Fatal("catalog missing aws-iam-strong-password-policy")
	}
	plan, err := Build(r, cloudFinding("iam_password_policy_reuse_24", map[string]string{"service": "iam"}))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Provider != "aws" || len(plan.Apply) != 1 || len(plan.DryRun) != 1 {
		t.Fatalf("plan shape wrong: %+v", plan)
	}
	if !strings.Contains(strings.Join(plan.Apply[0], " "), "update-account-password-policy") {
		t.Errorf("apply wrong: %v", plan.Apply[0])
	}
}
