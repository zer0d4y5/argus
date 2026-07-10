// Package dastscan runs dynamic application security testing (DAST) against a
// running web target with nuclei, and maps nuclei's JSONL output into the
// unified findings model (category DAST). It is the running-app analogue of
// internal/cloudscan: a standalone scanner with its own exec boundary and its
// own parse function, invoked by a dedicated command (argus dast) and a
// dedicated pipeline entry (pipeline.RunDAST), NOT registered in
// scanner.All() (whose adapters all receive a filesystem path).
//
// SECURITY:
//   - The target is caller input that becomes outbound HTTP requests. It is
//     validated to an http/https URL with a host before any exec; other
//     schemes (file, gopher, ...) are refused.
//   - nuclei's JSONL carries the full request/response bodies, the base64
//     template, and any data extracted from the live response. Those can hold
//     session tokens, PII, or secrets from the scanned app. parseNuclei NEVER
//     copies them into a finding: RawPayload is rebuilt from a whitelist of
//     identity/metadata fields only, and extracted-results is dropped. A DAST
//     finding is metadata about a weakness, never a copy of the app's
//     response, mirroring the SECRET-findings-are-metadata-only discipline.
//   - nuclei runs with update checks and the interactsh OOB server disabled,
//     so a scan performs no callouts beyond the requests to the target itself.
package dastscan

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
)

// Options configure one DAST run. Only URL is required; the rest tune scope.
type Options struct {
	URL        string   // target, http(s) with a host
	Templates  []string // nuclei -t values (template files/dirs/ids); empty = nuclei default set
	Tags       []string // nuclei -tags filter; empty = no tag filter
	Severities []string // nuclei -severity filter; empty = all
	RateLimit  int      // max requests/sec; 0 = nuclei default
	TimeoutSec int      // whole-scan timeout; 0 = caller's context governs
}

// Result is a completed DAST run.
type Result struct {
	Raw         []model.RawFinding
	ToolVersion string
}

// Available reports whether nuclei is on PATH.
func Available() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

// ValidateURL enforces the target grammar: an absolute http/https URL with a
// host and no embedded credentials. Returned error is safe to show the user.
func ValidateURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid target URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target must be an http:// or https:// URL")
	}
	if u.Host == "" {
		return fmt.Errorf("target URL must include a host")
	}
	if u.User != nil {
		return fmt.Errorf("target URL must not embed credentials")
	}
	return nil
}

// Scan runs nuclei against opts.URL and returns normalized-ready raw findings.
// Findings are written to a private temp file (like the gitleaks adapter) and
// read back, so nuclei's stderr banner never contaminates the JSONL.
func Scan(ctx context.Context, opts Options, progress func(string)) (Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if err := ValidateURL(opts.URL); err != nil {
		return Result{}, err
	}
	if !Available() {
		return Result{}, fmt.Errorf("nuclei not found on PATH: install nuclei to run DAST scans")
	}

	if opts.TimeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.TimeoutSec)*time.Second)
		defer cancel()
	}

	out, err := os.CreateTemp("", "argus-nuclei-*.jsonl")
	if err != nil {
		return Result{}, fmt.Errorf("dast: temp file: %w", err)
	}
	outPath := out.Name()
	out.Close()
	defer os.Remove(outPath)

	args := []string{
		"-target", opts.URL,
		"-jsonl", "-o", outPath,
		"-disable-update-check", // no network callout for a newer nuclei/templates
		"-no-interactsh",        // no OOB callout server; scan touches only the target
		"-no-color", "-silent",
	}
	for _, t := range opts.Templates {
		if t = strings.TrimSpace(t); t != "" {
			args = append(args, "-t", t)
		}
	}
	if len(opts.Tags) > 0 {
		args = append(args, "-tags", strings.Join(opts.Tags, ","))
	}
	if len(opts.Severities) > 0 {
		args = append(args, "-severity", strings.Join(opts.Severities, ","))
	}
	if opts.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(opts.RateLimit))
	}

	progress(fmt.Sprintf("==> running nuclei (DAST) against %s\n", opts.URL))
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	data, readErr := os.ReadFile(outPath)
	if readErr != nil {
		return Result{}, fmt.Errorf("dast: read results: %w", readErr)
	}
	// nuclei exits non-zero for some conditions even with results written; a
	// hard failure with no output is the only real error (mirrors runJSON).
	if runErr != nil && len(bytes.TrimSpace(data)) == 0 {
		if ctx.Err() == context.DeadlineExceeded {
			return Result{}, fmt.Errorf("dast: nuclei timed out")
		}
		return Result{}, fmt.Errorf("dast: nuclei failed with no output (exit error)")
	}

	raw, err := parseNuclei(data)
	if err != nil {
		return Result{}, err
	}
	progress(fmt.Sprintf("nuclei: %d finding(s)\n", len(raw)))
	return Result{Raw: raw, ToolVersion: toolVersion(ctx)}, nil
}

// toolVersion best-effort records the nuclei release for run provenance.
func toolVersion(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "nuclei", "-version").CombinedOutput()
	if err != nil {
		return ""
	}
	// nuclei prints "... Nuclei Engine Version: vX.Y.Z" to stderr.
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "Version:"); i >= 0 {
			return strings.TrimSpace(line[i+len("Version:"):])
		}
	}
	return ""
}
