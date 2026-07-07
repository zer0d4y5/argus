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

	"github.com/leaky-hub/appsec/internal/model"
)

// Remediation is one curated fix. Matching and command building are data-
// driven; the templates are reviewed argv with {param} placeholders.
type Remediation struct {
	ID          string   // stable id, e.g. "aws-s3-block-public-access"
	Title       string   // human summary of what applying does
	Provider    string   // "aws" (the only provider this beat)
	Description string   // one or two sentences for the console

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
	Permissions  []string // IAM actions the write profile must allow
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
)

// Grammars for the resource attributes the templates substitute. Values come
// from prowler scanning the operator's own account, but they are validated
// anyway (defense in depth) so a malformed name can never reach an argv slot.
var (
	s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionPattern   = regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d{1,2}$`)
)

// Catalog is the reviewed set of remediations. Adding one is a vetted change:
// a new entry with its match rules, validated params, reversible templates,
// and required permissions.
var Catalog = []Remediation{
	{
		ID:          "aws-s3-block-public-access",
		Title:       "Block all public access on the bucket",
		Provider:    "aws",
		Description: "Turns on all four S3 Block Public Access settings for the bucket, so ACLs and policies can't expose it.",
		Services:    []string{"s3", "bucket"},
		CheckKeywords: []string{"public"},
		Params: []Param{{Name: "bucket", Source: fromResourceName, Pattern: s3BucketPattern}},
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
		ID:          "aws-s3-default-encryption",
		Title:       "Enable default encryption on the bucket",
		Provider:    "aws",
		Description: "Sets SSE-S3 (AES-256) default encryption so new objects are encrypted at rest.",
		Services:    []string{"s3", "bucket"},
		CheckKeywords: []string{"encryption"},
		Params: []Param{{Name: "bucket", Source: fromResourceName, Pattern: s3BucketPattern}},
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
		ID:          "aws-ec2-ebs-encryption-by-default",
		Title:       "Enable EBS encryption by default in the region",
		Provider:    "aws",
		Description: "Turns on account-level EBS encryption by default for the region, so new volumes are encrypted.",
		Services:    []string{"ec2", "ebs", "volume"},
		CheckKeywords: []string{"ebs", "encryption"},
		Params: []Param{{Name: "region", Source: fromRegion, Pattern: regionPattern}},
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
		raw := ""
		switch p.Source {
		case fromResourceName:
			raw = f.Meta["resourceName"]
		case fromRegion:
			raw = f.Meta["region"]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return Plan{}, fmt.Errorf("remediation %s: finding is missing %s", r.ID, p.Name)
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
		ID: r.ID, Title: r.Title, Description: r.Description,
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
