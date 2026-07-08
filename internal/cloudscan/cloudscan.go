// Package cloudscan runs cloud security posture scans through prowler and
// maps its findings into the unified model (category CLOUD, schema 2.1.0).
//
// It is deliberately NOT a scanner.Adapter: an adapter scans a filesystem
// path handed to every available tool, while a cloud scan targets an
// ACCOUNT through a credential *reference* and must never run implicitly as
// part of a directory scan. The separate package makes the different trust
// shape explicit — cloudscan is the only code in the platform that places a
// cloud profile name into a child environment, and it accepts only names
// validated against the closed list discovered from the local config.
//
// Credential rules (docs/console-ops.md C1–C4): the platform never accepts,
// stores, logs, or transmits credential material. The profile NAME is the
// entire secret-adjacent surface; prowler resolves it against ~/.aws inside
// the child process, and the environment dies with that process.
package cloudscan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
)

// Supported cloud providers. Each references an account without collecting a
// secret: AWS by a named ~/.aws profile (AWS_PROFILE), Azure by a subscription
// id, GCP by a project id. Azure/GCP auth (a service principal in the env for
// Azure, Application Default Credentials for GCP) is supplied by the operator
// in the environment prowler inherits — Argus passes only the account id, in
// argv, never a key.
const (
	ProviderAWS   = "aws"
	ProviderAzure = "azure"
	ProviderGCP   = "gcp"
)

// ToolName is the reporting tool name on every cloud finding.
const ToolName = "prowler"

// KnownProviders returns the providers a cloud scan accepts, sorted.
func KnownProviders() []string { return []string{ProviderAWS, ProviderAzure, ProviderGCP} }

// ValidProvider reports whether name is a supported cloud provider.
func ValidProvider(name string) bool {
	return name == ProviderAWS || name == ProviderAzure || name == ProviderGCP
}

// AccountLabel names the per-provider account reference for UI/errors.
func AccountLabel(provider string) string {
	switch provider {
	case ProviderAzure:
		return "subscription id"
	case ProviderGCP:
		return "project id"
	default:
		return "profile"
	}
}

// Options configure one cloud posture scan.
type Options struct {
	Provider string   // must satisfy ValidProvider
	Profile  string   // AWS named profile — must be in ListAWSProfiles()
	Regions  []string // AWS optional region filter; empty = provider default (all)
	Account  string   // Azure subscription id / GCP project id (the account reference)
}

// Result is a parsed prowler run: the FAIL findings mapped into RawFindings
// plus the posture counts (a posture assessment is fail AND pass counts —
// "3 fails out of 12 checks" and "3 fails out of 600" are different claims).
type Result struct {
	Raw    []model.RawFinding
	Failed int // FAIL records → findings
	Passed int // PASS records → counted, not findings
	Manual int // MANUAL records → counted, not findings (human verification)
	// ToolVersion is the prowler release that produced this run ("Prowler
	// 5.31.0"), captured for the run document's provenance. Empty when the
	// version probe fails; never fatal.
	ToolVersion string
}

// regionPattern bounds region values passed to the prowler argv. Regions are
// exec args (never shell, never env), but a closed grammar keeps the argv
// boring: AWS region names are lowercase letters, digits, and dashes.
var regionPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// azureSubscriptionPattern is a GUID; gcpProjectPattern is Google's project-id
// grammar (6–30 chars, lowercase letter first, letters/digits/hyphens).
var (
	azureSubscriptionPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	gcpProjectPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
)

// accountRef returns the account reference shown in progress lines (profile for
// AWS, subscription/project id for Azure/GCP) — a reference, never a secret.
func accountRef(opts Options) string {
	if opts.Provider == ProviderAWS {
		return opts.Profile
	}
	return opts.Account
}

// Available reports whether the prowler binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("prowler")
	return err == nil
}

// ToolVersion asks the installed prowler for its version, for run-document
// provenance. Best-effort: empty on any failure, bounded, printable-only.
func ToolVersion(ctx context.Context) string {
	vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(vctx, "prowler", "--version").Output()
	if err != nil {
		return ""
	}
	return parseToolVersion(string(out))
}

// parseToolVersion extracts the version line from `prowler --version` output:
// the first non-empty line, stripped of non-printables and any trailing
// parenthetical ("Prowler 5.31.0 (You are running the latest…)"), capped.
func parseToolVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.Index(line, "("); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		var b strings.Builder
		for _, r := range line {
			if r >= 0x20 && r != 0x7f {
				b.WriteRune(r)
			}
			if b.Len() >= 60 {
				break
			}
		}
		return b.String()
	}
	return ""
}

// Validate checks the options against the closed lists: known provider,
// profile discovered in the local AWS config, well-formed regions. It is the
// C2 guard (profile-name injection): a name that is not literally a section
// of ~/.aws/config or ~/.aws/credentials never reaches an environment
// variable, no matter which surface (CLI flag, console form) supplied it.
func Validate(opts Options) error {
	if !ValidProvider(opts.Provider) {
		return fmt.Errorf("unknown cloud provider %q; must be one of %s",
			opts.Provider, strings.Join(KnownProviders(), ", "))
	}
	switch opts.Provider {
	case ProviderAWS:
		profiles, err := ListAWSProfiles()
		if err != nil {
			return fmt.Errorf("discover AWS profiles: %w", err)
		}
		if !contains(profiles, opts.Profile) {
			return fmt.Errorf("unknown AWS profile %q: not present in the local AWS config (known: %s)",
				opts.Profile, strings.Join(profiles, ", "))
		}
		for _, r := range opts.Regions {
			if !regionPattern.MatchString(r) {
				return fmt.Errorf("invalid region %q", r)
			}
		}
	case ProviderAzure:
		if !azureSubscriptionPattern.MatchString(opts.Account) {
			return fmt.Errorf("invalid Azure subscription id %q (want a GUID)", opts.Account)
		}
	case ProviderGCP:
		if !gcpProjectPattern.MatchString(opts.Account) {
			return fmt.Errorf("invalid GCP project id %q", opts.Account)
		}
	}
	return nil
}

// buildArgs assembles prowler's argv for a validated scan. Per-provider: AWS
// takes an optional region filter; Azure a --subscription-ids; GCP a
// --project-ids. All values are already validated against a closed grammar, and
// this is argv (never a shell), so nothing here can inject.
func buildArgs(opts Options, outDir string) []string {
	args := []string{opts.Provider, "-M", "json-ocsf", "--output-directory", outDir, "--output-filename", "scan"}
	switch opts.Provider {
	case ProviderAWS:
		if len(opts.Regions) > 0 {
			args = append(args, "-f")
			args = append(args, opts.Regions...)
		}
	case ProviderAzure:
		args = append(args, "--subscription-ids", opts.Account)
	case ProviderGCP:
		args = append(args, "--project-ids", opts.Account)
	}
	return args
}

// Scan runs prowler against the referenced account and returns the parsed
// result. The context carries the caller's timeout (cloud scans are long;
// config default 1800s). Progress is deliberately coarse: prowler's own
// stderr is never streamed (it echoes account identifiers and ANSI noise) —
// callers get our summary lines only.
func Scan(ctx context.Context, opts Options, progress func(string)) (Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if err := Validate(opts); err != nil {
		return Result{}, err
	}
	if !Available() {
		return Result{}, fmt.Errorf("prowler not found on PATH")
	}

	outDir, err := os.MkdirTemp("", "appsec-cloudscan-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(outDir)

	args := buildArgs(opts, outDir)
	progress(fmt.Sprintf("==> running prowler (CLOUD) against %s %s %q\n", opts.Provider, AccountLabel(opts.Provider), accountRef(opts)))

	cmd := exec.CommandContext(ctx, "prowler", args...)
	// The credential REFERENCE: for AWS a validated profile name resolved by
	// the SDK inside the child; for Azure/GCP the account id is in argv and
	// auth comes from the operator's own env (SP vars / ADC). Either way no key
	// material enters our output, run files, or prompts.
	cmd.Env = childEnv(os.Environ(), opts.Provider, opts.Profile)
	cmd.Stdout = nil // prowler's stdout banner is noise; findings go to the file
	var stderrTail tailBuffer
	cmd.Stderr = &stderrTail

	runErr := cmd.Run()
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("prowler: %w", ctx.Err())
	}

	data, readErr := os.ReadFile(filepath.Join(outDir, "scan.ocsf.json"))
	if readErr != nil {
		// No output file: the run truly failed. Surface a bounded, sanitized
		// tail of stderr — never the raw stream.
		return Result{}, fmt.Errorf("prowler produced no output (%v): %s", runErr, stderrTail.Summary())
	}

	res, err := ParseOCSF(data)
	if err != nil {
		return Result{}, err
	}
	res.ToolVersion = ToolVersion(ctx)
	progress(fmt.Sprintf("prowler: %d raw findings (%d fail / %d pass / %d manual)\n",
		len(res.Raw), res.Failed, res.Passed, res.Manual))
	return res, nil
}

// childEnv builds the prowler child's environment: the parent env plus the
// single credential REFERENCE entry (AWS_PROFILE=<name>). This is the ONLY
// place the platform writes a credential-adjacent value into a child env, and
// it writes a NAME, never key material. Factored out and exported-to-tests
// (via export_test) so the "credential is referenced, never collected"
// invariant (C1/C2) is grep-provable. The provider selects the env var name;
// AWS is the only provider this beat.
func childEnv(base []string, provider, profile string) []string {
	switch provider {
	case ProviderAWS:
		return append(append([]string{}, base...), "AWS_PROFILE="+profile)
	default:
		return append([]string{}, base...)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
