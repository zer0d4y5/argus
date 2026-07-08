// Package cloudremediate is Argus's CURATED cloud-remediation catalog: a small,
// vetted set of reversible, parameterized fixes for common cloud posture
// findings. It is the deterministic backbone of "approved cloud remediation".
//
// The core rule: the LLM never authors a command that runs. Execution is
// limited to the entries here — each a reviewed template whose only variables
// are resource attributes pulled from the finding and validated against a
// strict grammar. Commands are argv (never a shell string), so nothing the
// finding carries can inject. A separate opt-in write credential runs them;
// this package builds and describes, it does not execute (see runner.go).
//
// Every entry is idempotent and reversible, records the IAM permissions the
// write profile needs, and pairs a dry-run/preview with the apply. A fix never
// marks a finding fixed — only a re-scan clears it.
package cloudremediate

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// Remediation is one curated fix. Matching and command building are data-
// driven; the templates are reviewed argv with {param} placeholders.
type Remediation struct {
	ID          string // stable id, e.g. "aws-s3-block-public-access"
	Title       string // human summary of what applying does
	Provider    string // "aws" | "azure" | "gcp"
	Description string // one or two sentences for the console

	// Matching. An entry applies to a CLOUD finding when the provider matches,
	// any Service token appears in the finding's service/resourceType, and
	// every CheckKeyword appears in the finding's rule id (the prowler check).
	Services      []string
	CheckKeywords []string

	// Params are the resource attributes the templates need, each pulled from a
	// finding field and validated against a grammar before substitution.
	Params []Param

	// DryRun previews the change (reads current state or a --dry-run); Apply
	// makes it. Each is one or more argv templates with {param} placeholders.
	DryRun [][]string
	Apply  [][]string

	Reversible   bool
	ReversalNote string   // how to undo, for the operator
	Permissions  []string // IAM actions / RBAC permissions the write identity must allow
}

// Param names a resource attribute and how to extract + validate it.
type Param struct {
	Name    string         // placeholder name, e.g. "bucket"
	Source  paramSource    // where in the finding it comes from
	Pattern *regexp.Regexp // the value must match, or building fails
}

type paramSource int

const (
	fromResourceName paramSource = iota // finding Meta["resourceName"]
	fromRegion                          // finding Meta["region"]
	fromAccount                         // finding Meta["account"] (GCP project / Azure subscription id)
	fromResourceUID                     // finding Location.Resource (Azure ARM id, AWS ARN)
)

// value reads the param's raw value from the finding.
func (p paramSource) value(f model.Finding) string {
	switch p {
	case fromRegion:
		return f.Meta["region"]
	case fromAccount:
		return f.Meta["account"]
	case fromResourceUID:
		return f.Location.Resource
	default:
		return f.Meta["resourceName"]
	}
}

// describe names the finding field a source reads, for error messages.
func (p paramSource) describe() string {
	switch p {
	case fromRegion:
		return "region"
	case fromAccount:
		return "account id"
	case fromResourceUID:
		return "resource id"
	default:
		return "resource name"
	}
}

// Grammars for the resource attributes the templates substitute. Values come
// from prowler scanning the operator's own account, but they are validated
// anyway (defense in depth) so a malformed name can never reach an argv slot.
var (
	s3BucketPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionPattern     = regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d{1,2}$`)
	trailNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$`)
	instanceIDPattern = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	amiIDPattern      = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)

	// Azure: the full ARM id of a storage account, every segment bounded. The
	// skeleton is fixed (subscription GUID, resource group, provider, account
	// name), so nothing shell- or flag-shaped fits anywhere in it. Resource
	// group: Azure's documented charset, 1-90 chars, cannot end with a period
	// (which also refuses a ".." segment). Account name: lowercase
	// alphanumeric, 3-24. Case-insensitive because ARM ids round-trip with
	// inconsistent casing on the fixed segments.
	azureStorageIDPattern = regexp.MustCompile(`(?i)^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/resourceGroups/[a-z0-9._()-]{0,89}[a-z0-9_()-]/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}$`)

	// GCP: bucket names (lowercase, dots/dashes/underscores, 3-63) and project
	// ids (Google's published grammar: starts with a letter, 6-30 chars).
	gcpBucketPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)
	gcpProjectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
)

// Catalog is the reviewed set of remediations. Adding one is a vetted change:
// a new entry with its match rules, validated params, reversible templates,
// and required permissions.
var Catalog = []Remediation{
	{
		ID:            "aws-s3-block-public-access",
		Title:         "Block all public access on the bucket",
		Provider:      "aws",
		Description:   "Turns on all four S3 Block Public Access settings for the bucket, so ACLs and policies can't expose it.",
		Services:      []string{"s3", "bucket"},
		CheckKeywords: []string{"public"},
		Params:        []Param{{Name: "bucket", Source: fromResourceName, Pattern: s3BucketPattern}},
		DryRun: [][]string{
			{"aws", "s3api", "get-public-access-block", "--bucket", "{bucket}"},
		},
		Apply: [][]string{
			{"aws", "s3api", "put-public-access-block", "--bucket", "{bucket}",
				"--public-access-block-configuration",
				"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"},
		},
		Reversible:   true,
		ReversalNote: "Re-run put-public-access-block with the settings set to false to restore prior access (rarely wanted).",
		Permissions:  []string{"s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"},
	},
	{
		ID:            "aws-s3-default-encryption",
		Title:         "Enable default encryption on the bucket",
		Provider:      "aws",
		Description:   "Sets SSE-S3 (AES-256) default encryption so new objects are encrypted at rest.",
		Services:      []string{"s3", "bucket"},
		CheckKeywords: []string{"encryption"},
		Params:        []Param{{Name: "bucket", Source: fromResourceName, Pattern: s3BucketPattern}},
		DryRun: [][]string{
			{"aws", "s3api", "get-bucket-encryption", "--bucket", "{bucket}"},
		},
		Apply: [][]string{
			{"aws", "s3api", "put-bucket-encryption", "--bucket", "{bucket}",
				"--server-side-encryption-configuration",
				`{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}`},
		},
		Reversible:   true,
		ReversalNote: "Encryption is additive; existing objects are unchanged and can still be read.",
		Permissions:  []string{"s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration"},
	},
	{
		ID:            "aws-ec2-ebs-encryption-by-default",
		Title:         "Enable EBS encryption by default in the region",
		Provider:      "aws",
		Description:   "Turns on account-level EBS encryption by default for the region, so new volumes are encrypted.",
		Services:      []string{"ec2", "ebs", "volume"},
		CheckKeywords: []string{"ebs", "encryption"},
		Params:        []Param{{Name: "region", Source: fromRegion, Pattern: regionPattern}},
		DryRun: [][]string{
			{"aws", "ec2", "get-ebs-encryption-by-default", "--region", "{region}"},
		},
		Apply: [][]string{
			{"aws", "ec2", "enable-ebs-encryption-by-default", "--region", "{region}"},
		},
		Reversible:   true,
		ReversalNote: "Run disable-ebs-encryption-by-default to revert; existing volumes are unaffected either way.",
		Permissions:  []string{"ec2:GetEbsEncryptionByDefault", "ec2:EnableEbsEncryptionByDefault"},
	},
	{
		ID:            "aws-s3-enable-versioning",
		Title:         "Enable versioning on the bucket",
		Provider:      "aws",
		Description:   "Turns on S3 versioning so overwritten or deleted objects can be recovered.",
		Services:      []string{"s3", "bucket"},
		CheckKeywords: []string{"versioning"},
		Params:        []Param{{Name: "bucket", Source: fromResourceName, Pattern: s3BucketPattern}},
		DryRun: [][]string{
			{"aws", "s3api", "get-bucket-versioning", "--bucket", "{bucket}"},
		},
		Apply: [][]string{
			{"aws", "s3api", "put-bucket-versioning", "--bucket", "{bucket}",
				"--versioning-configuration", "Status=Enabled"},
		},
		Reversible:   true,
		ReversalNote: "Versioning can be suspended (Status=Suspended); already-stored versions remain.",
		Permissions:  []string{"s3:GetBucketVersioning", "s3:PutBucketVersioning"},
	},
	{
		ID:            "aws-cloudtrail-log-file-validation",
		Title:         "Enable CloudTrail log file validation",
		Provider:      "aws",
		Description:   "Turns on log-file integrity validation so tampering with delivered CloudTrail logs is detectable.",
		Services:      []string{"cloudtrail", "trail"},
		CheckKeywords: []string{"validation"},
		Params:        []Param{{Name: "trail", Source: fromResourceName, Pattern: trailNamePattern}},
		DryRun: [][]string{
			{"aws", "cloudtrail", "get-trail", "--name", "{trail}"},
		},
		Apply: [][]string{
			{"aws", "cloudtrail", "update-trail", "--name", "{trail}", "--enable-log-file-validation"},
		},
		Reversible:   true,
		ReversalNote: "Run update-trail with --no-enable-log-file-validation to revert.",
		Permissions:  []string{"cloudtrail:GetTrail", "cloudtrail:UpdateTrail"},
	},
	{
		ID:            "aws-ec2-enforce-imdsv2",
		Title:         "Require IMDSv2 on the instance",
		Provider:      "aws",
		Description:   "Sets the instance metadata service to token-required (IMDSv2), which blocks the SSRF-prone IMDSv1 path.",
		Services:      []string{"ec2", "instance"},
		CheckKeywords: []string{"imdsv2"},
		Params:        []Param{{Name: "instance", Source: fromResourceName, Pattern: instanceIDPattern}},
		DryRun: [][]string{
			{"aws", "ec2", "describe-instances", "--instance-ids", "{instance}"},
		},
		Apply: [][]string{
			{"aws", "ec2", "modify-instance-metadata-options", "--instance-id", "{instance}",
				"--http-tokens", "required", "--http-endpoint", "enabled"},
		},
		Reversible:   true,
		ReversalNote: "Set --http-tokens optional to allow IMDSv1 again (not recommended).",
		Permissions:  []string{"ec2:DescribeInstances", "ec2:ModifyInstanceMetadataOptions"},
	},
	{
		ID:            "aws-ebs-snapshot-block-public-access",
		Title:         "Block public access for EBS snapshots in the region",
		Provider:      "aws",
		Description:   "Turns on account-level EBS snapshot block public access (block-all-sharing) for the region, so no snapshot can be publicly shared.",
		Services:      []string{"ec2", "ebs"},
		CheckKeywords: []string{"snapshot", "block", "public"},
		Params:        []Param{{Name: "region", Source: fromRegion, Pattern: regionPattern}},
		DryRun: [][]string{
			{"aws", "ec2", "get-snapshot-block-public-access-state", "--region", "{region}"},
		},
		Apply: [][]string{
			{"aws", "ec2", "enable-snapshot-block-public-access", "--state", "block-all-sharing", "--region", "{region}"},
		},
		Reversible:   true,
		ReversalNote: "Run disable-snapshot-block-public-access to revert; prior sharing settings on each snapshot are preserved and take effect again.",
		Permissions:  []string{"ec2:GetSnapshotBlockPublicAccessState", "ec2:EnableSnapshotBlockPublicAccess"},
	},
	{
		ID:            "aws-ec2-ami-make-private",
		Title:         "Make the AMI private",
		Provider:      "aws",
		Description:   "Resets the AMI's launch permissions to the default (owner only), ending public sharing of the image.",
		Services:      []string{"ec2"},
		CheckKeywords: []string{"ami", "public"},
		Params: []Param{
			{Name: "image", Source: fromResourceName, Pattern: amiIDPattern},
			{Name: "region", Source: fromRegion, Pattern: regionPattern},
		},
		DryRun: [][]string{
			{"aws", "ec2", "describe-image-attribute", "--image-id", "{image}", "--attribute", "launchPermission", "--region", "{region}"},
		},
		Apply: [][]string{
			{"aws", "ec2", "reset-image-attribute", "--image-id", "{image}", "--attribute", "launchPermission", "--region", "{region}"},
		},
		Reversible:   true,
		ReversalNote: "Re-share with modify-image-attribute --launch-permission if specific accounts still need the image.",
		Permissions:  []string{"ec2:DescribeImageAttribute", "ec2:ResetImageAttribute"},
	},
	{
		ID:            "aws-iam-strong-password-policy",
		Title:         "Set a strong IAM account password policy",
		Provider:      "aws",
		Description:   "Sets the account password policy to the CIS-recommended baseline: 14+ characters, all four character classes, 24-password reuse prevention, 90-day maximum age. Replaces the whole policy. A dry-run error saying the policy cannot be found means no policy is set at all.",
		Services:      []string{"iam"},
		CheckKeywords: []string{"password", "policy"},
		DryRun: [][]string{
			{"aws", "iam", "get-account-password-policy"},
		},
		Apply: [][]string{
			{"aws", "iam", "update-account-password-policy",
				"--minimum-password-length", "14",
				"--require-uppercase-characters", "--require-lowercase-characters",
				"--require-numbers", "--require-symbols",
				"--password-reuse-prevention", "24", "--max-password-age", "90"},
		},
		Reversible:   true,
		ReversalNote: "Run update-account-password-policy again with the prior values (the dry-run output records them).",
		Permissions:  []string{"iam:GetAccountPasswordPolicy", "iam:UpdateAccountPasswordPolicy"},
	},
	{
		ID:            "azure-storage-disallow-blob-public-access",
		Title:         "Disallow blob public access on the storage account",
		Provider:      "azure",
		Description:   "Sets allowBlobPublicAccess to false on the storage account, so no container or blob can be made anonymously readable.",
		Services:      []string{"storage"},
		CheckKeywords: []string{"blob", "public"},
		Params:        []Param{{Name: "id", Source: fromResourceUID, Pattern: azureStorageIDPattern}},
		DryRun: [][]string{
			{"az", "storage", "account", "show", "--ids", "{id}", "--query", "[name,allowBlobPublicAccess]"},
		},
		Apply: [][]string{
			{"az", "storage", "account", "update", "--ids", "{id}", "--allow-blob-public-access", "false"},
		},
		Reversible:   true,
		ReversalNote: "Set --allow-blob-public-access true to restore per-container public access control (rarely wanted).",
		Permissions:  []string{"Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"},
	},
	{
		ID:            "azure-storage-require-secure-transfer",
		Title:         "Require secure transfer (HTTPS only) on the storage account",
		Provider:      "azure",
		Description:   "Turns on supportsHttpsTrafficOnly, so requests over plain HTTP (and SMB without encryption) are refused.",
		Services:      []string{"storage"},
		CheckKeywords: []string{"secure", "transfer"},
		Params:        []Param{{Name: "id", Source: fromResourceUID, Pattern: azureStorageIDPattern}},
		DryRun: [][]string{
			{"az", "storage", "account", "show", "--ids", "{id}", "--query", "[name,supportsHttpsTrafficOnly]"},
		},
		Apply: [][]string{
			{"az", "storage", "account", "update", "--ids", "{id}", "--https-only", "true"},
		},
		Reversible:   true,
		ReversalNote: "Set --https-only false to allow plain HTTP again (not recommended).",
		Permissions:  []string{"Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"},
	},
	{
		ID:            "azure-storage-minimum-tls-12",
		Title:         "Require TLS 1.2 as the minimum version on the storage account",
		Provider:      "azure",
		Description:   "Sets minimumTlsVersion to TLS1_2, refusing connections that negotiate older TLS.",
		Services:      []string{"storage"},
		CheckKeywords: []string{"minimum", "tls"},
		Params:        []Param{{Name: "id", Source: fromResourceUID, Pattern: azureStorageIDPattern}},
		DryRun: [][]string{
			{"az", "storage", "account", "show", "--ids", "{id}", "--query", "[name,minimumTlsVersion]"},
		},
		Apply: [][]string{
			{"az", "storage", "account", "update", "--ids", "{id}", "--min-tls-version", "TLS1_2"},
		},
		Reversible:   true,
		ReversalNote: "Set --min-tls-version back to the prior value (the dry-run output records it).",
		Permissions:  []string{"Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"},
	},
	{
		ID:            "gcp-storage-public-access-prevention",
		Title:         "Enforce public access prevention on the bucket",
		Provider:      "gcp",
		Description:   "Sets public access prevention to enforced on the bucket, so IAM bindings and ACLs cannot expose it to allUsers or allAuthenticatedUsers.",
		Services:      []string{"cloudstorage", "bucket"},
		CheckKeywords: []string{"bucket", "public"},
		Params:        []Param{{Name: "bucket", Source: fromResourceName, Pattern: gcpBucketPattern}},
		DryRun: [][]string{
			{"gcloud", "storage", "buckets", "describe", "gs://{bucket}", "--format", "value(public_access_prevention)"},
		},
		Apply: [][]string{
			{"gcloud", "storage", "buckets", "update", "gs://{bucket}", "--public-access-prevention"},
		},
		Reversible:   true,
		ReversalNote: "Run buckets update with --no-public-access-prevention to fall back to the inherited setting.",
		Permissions:  []string{"storage.buckets.get", "storage.buckets.update"},
	},
	{
		ID:            "gcp-storage-uniform-bucket-level-access",
		Title:         "Enable uniform bucket-level access on the bucket",
		Provider:      "gcp",
		Description:   "Turns on uniform bucket-level access, so IAM alone governs access and per-object ACLs stop applying.",
		Services:      []string{"cloudstorage", "bucket"},
		CheckKeywords: []string{"uniform"},
		Params:        []Param{{Name: "bucket", Source: fromResourceName, Pattern: gcpBucketPattern}},
		DryRun: [][]string{
			{"gcloud", "storage", "buckets", "describe", "gs://{bucket}", "--format", "value(uniform_bucket_level_access)"},
		},
		Apply: [][]string{
			{"gcloud", "storage", "buckets", "update", "gs://{bucket}", "--uniform-bucket-level-access"},
		},
		Reversible:   true,
		ReversalNote: "Reversible with --no-uniform-bucket-level-access within 90 days; after that GCP locks it on.",
		Permissions:  []string{"storage.buckets.get", "storage.buckets.update"},
	},
	{
		ID:            "gcp-storage-enable-versioning",
		Title:         "Enable object versioning on the bucket",
		Provider:      "gcp",
		Description:   "Turns on object versioning so overwritten or deleted objects can be recovered.",
		Services:      []string{"cloudstorage", "bucket"},
		CheckKeywords: []string{"versioning"},
		Params:        []Param{{Name: "bucket", Source: fromResourceName, Pattern: gcpBucketPattern}},
		DryRun: [][]string{
			{"gcloud", "storage", "buckets", "describe", "gs://{bucket}", "--format", "value(versioning.enabled)"},
		},
		Apply: [][]string{
			{"gcloud", "storage", "buckets", "update", "gs://{bucket}", "--versioning"},
		},
		Reversible:   true,
		ReversalNote: "Run buckets update with --no-versioning to suspend; already-stored versions remain.",
		Permissions:  []string{"storage.buckets.get", "storage.buckets.update"},
	},
	{
		ID:            "gcp-compute-project-os-login",
		Title:         "Enable OS Login for the project",
		Provider:      "gcp",
		Description:   "Sets enable-oslogin=TRUE in project metadata, so SSH access to instances is governed by IAM instead of static metadata keys. Instances relying on metadata SSH keys switch to IAM-based access.",
		Services:      []string{"compute"},
		CheckKeywords: []string{"os_login_enabled"},
		Params:        []Param{{Name: "project", Source: fromAccount, Pattern: gcpProjectPattern}},
		DryRun: [][]string{
			{"gcloud", "compute", "project-info", "describe", "--project", "{project}", "--format", "value(commonInstanceMetadata.items)"},
		},
		Apply: [][]string{
			{"gcloud", "compute", "project-info", "add-metadata", "--metadata", "enable-oslogin=TRUE", "--project", "{project}"},
		},
		Reversible:   true,
		ReversalNote: "Set enable-oslogin=FALSE with the same add-metadata command to revert.",
		Permissions:  []string{"compute.projects.get", "compute.projects.setCommonInstanceMetadata"},
	},
}

// Applicable returns the catalog entries that fit a finding, in catalog order.
// Only CLOUD findings match; a non-cloud finding yields nothing.
func Applicable(f model.Finding) []Remediation {
	if f.Category != model.CategoryCloud {
		return nil
	}
	provider := strings.ToLower(f.Meta["provider"])
	service := strings.ToLower(f.Meta["service"] + " " + f.Meta["resourceType"])
	rule := strings.ToLower(f.RuleID)
	var out []Remediation
	for _, r := range Catalog {
		if r.Provider != provider {
			continue
		}
		if !containsAny(service, r.Services) {
			continue
		}
		if !containsAll(rule, r.CheckKeywords) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ByID returns a catalog entry by id.
func ByID(id string) (Remediation, bool) {
	for _, r := range Catalog {
		if r.ID == id {
			return r, true
		}
	}
	return Remediation{}, false
}

// Command is a resolved, ready-to-run argv (no placeholders, all values
// validated). Never contains a shell.
type Command []string

// Plan is a built remediation for a specific finding: the resolved dry-run and
// apply commands plus the reviewed metadata the console shows before approval.
type Plan struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Provider     string    `json:"provider"` // selects the CLI and the credential model
	Description  string    `json:"description"`
	DryRun       []Command `json:"dryRun"`
	Apply        []Command `json:"apply"`
	Reversible   bool      `json:"reversible"`
	ReversalNote string    `json:"reversalNote,omitempty"`
	Permissions  []string  `json:"permissions"`
	Region       string    `json:"region,omitempty"` // the region the commands target, if any
}

// Build resolves a remediation against a finding: it extracts and validates
// every param, substitutes them into the argv templates, and returns the plan.
// An entry that does not apply, or a resource attribute that fails validation,
// is an error — nothing half-built is returned.
func Build(r Remediation, f model.Finding) (Plan, error) {
	vals := map[string]string{}
	var region string
	for _, p := range r.Params {
		raw := strings.TrimSpace(p.Source.value(f))
		if raw == "" {
			return Plan{}, fmt.Errorf("remediation %s: finding is missing its %s", r.ID, p.Source.describe())
		}
		if !p.Pattern.MatchString(raw) {
			return Plan{}, fmt.Errorf("remediation %s: %s %q is not a valid value", r.ID, p.Name, raw)
		}
		vals[p.Name] = raw
		if p.Source == fromRegion {
			region = raw
		}
	}
	dry, err := resolveAll(r.DryRun, vals)
	if err != nil {
		return Plan{}, err
	}
	apply, err := resolveAll(r.Apply, vals)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		ID: r.ID, Title: r.Title, Provider: r.Provider, Description: r.Description,
		DryRun: dry, Apply: apply,
		Reversible: r.Reversible, ReversalNote: r.ReversalNote,
		Permissions: r.Permissions, Region: region,
	}, nil
}

// resolveAll substitutes validated params into every argv template, refusing
// any placeholder left unresolved (a template referencing an undeclared param
// is a catalog bug, caught here rather than shipped as a literal "{x}").
func resolveAll(templates [][]string, vals map[string]string) ([]Command, error) {
	out := make([]Command, 0, len(templates))
	for _, tmpl := range templates {
		cmd := make(Command, 0, len(tmpl))
		for _, tok := range tmpl {
			resolved := tok
			for name, v := range vals {
				resolved = strings.ReplaceAll(resolved, "{"+name+"}", v)
			}
			if i := strings.IndexByte(resolved, '{'); i >= 0 && strings.IndexByte(resolved[i:], '}') > 0 {
				return nil, fmt.Errorf("unresolved placeholder in %q", tok)
			}
			cmd = append(cmd, resolved)
		}
		out = append(out, cmd)
	}
	return out, nil
}

func containsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func containsAll(hay string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(hay, n) {
			return false
		}
	}
	return len(needles) > 0
}
