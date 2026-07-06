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

	"github.com/leaky-hub/appsec/internal/model"
)

// ProviderAWS is the one supported provider this beat. Azure and GCP are
// documented next-beat work (docs/console-ops.md): they land only with
// recorded fixtures and uniform flag plumbing, never as stubs.
const ProviderAWS = "aws"

// ToolName is the reporting tool name on every cloud finding.
const ToolName = "prowler"

// KnownProviders returns the providers a cloud scan accepts, sorted.
func KnownProviders() []string { return []string{ProviderAWS} }

// ValidProvider reports whether name is a supported cloud provider.
func ValidProvider(name string) bool { return name == ProviderAWS }

// Options configure one cloud posture scan.
type Options struct {
	Provider string   // must satisfy ValidProvider
	Profile  string   // AWS named profile — must be in ListAWSProfiles()
	Regions  []string // optional region filter; empty = provider default (all)
}

// Result is a parsed prowler run: the FAIL findings mapped into RawFindings
// plus the posture counts (a posture assessment is fail AND pass counts —
// "3 fails out of 12 checks" and "3 fails out of 600" are different claims).
type Result struct {
	Raw    []model.RawFinding
	Failed int // FAIL records → findings
	Passed int // PASS records → counted, not findings
	Manual int // MANUAL records → counted, not findings (human verification)
}

// regionPattern bounds region values passed to the prowler argv. Regions are
// exec args (never shell, never env), but a closed grammar keeps the argv
// boring: AWS region names are lowercase letters, digits, and dashes.
var regionPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Available reports whether the prowler binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("prowler")
	return err == nil
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
	return nil
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

	args := []string{opts.Provider, "-M", "json-ocsf", "--output-directory", outDir, "--output-filename", "scan"}
	if len(opts.Regions) > 0 {
		args = append(args, "-f")
		args = append(args, opts.Regions...)
	}
	progress(fmt.Sprintf("==> running prowler (CLOUD) against %s profile %q\n", opts.Provider, opts.Profile))

	cmd := exec.CommandContext(ctx, "prowler", args...)
	// The credential REFERENCE: a validated profile name, resolved by the
	// AWS SDK inside the child. The value never appears in our output, run
	// files, or prompts; the env entry dies with the child process.
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
