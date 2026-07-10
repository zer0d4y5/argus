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
	"net"
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
	Fuzzing    bool     // enable nuclei -dast (active fuzzing templates)
	// URLs, when non-empty, is an explicit list of endpoints to scan (nuclei
	// -l) instead of just URL: the endpoints a crawl discovered. URL is still
	// used as the scan's identity/label.
	URLs []string
	// Headers are extra request headers (e.g. "Cookie: SESS=..."), sent on
	// every request so a scan can run authenticated. Values may be live
	// session credentials: they are passed to nuclei but NEVER logged, printed,
	// or written to a finding.
	Headers []string
	// Evidence, when true, captures the redacted request/response for each
	// finding (opt-in: a response body can hold app data).
	Evidence bool
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
	if err := probeTarget(ctx, opts.URL); err != nil {
		return Result{}, err
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

	// A crawl-discovered endpoint list is passed to nuclei via a temp file
	// (-l); a single-URL scan uses -target. The list is scan input, not
	// secret, but the temp file is cleaned up regardless.
	listPath := ""
	if len(opts.URLs) > 0 {
		lp, cleanup, err := writeURLList(opts.URLs)
		if err != nil {
			return Result{}, err
		}
		defer cleanup()
		listPath = lp
	}

	args := buildArgs(opts, outPath, listPath)

	if listPath != "" {
		progress(fmt.Sprintf("==> running nuclei (DAST) against %d discovered endpoint(s)\n", len(opts.URLs)))
	} else {
		progress(fmt.Sprintf("==> running nuclei (DAST) against %s\n", opts.URL))
	}
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

	raw, err := parseNuclei(data, opts.Evidence)
	if err != nil {
		return Result{}, err
	}
	progress(fmt.Sprintf("nuclei: %d finding(s)\n", len(raw)))
	return Result{Raw: raw, ToolVersion: toolVersion(ctx)}, nil
}

// probeTarget checks that something is listening at the target before nuclei
// runs, so a dead URL (wrong port, server not started) fails loudly instead
// of producing a silent zero-finding "clean" run. A plain TCP connect is the
// whole check: it proves a listener without sending a request, and stays
// neutral on TLS trust and HTTP status (both are nuclei's business).
func probeTarget(ctx context.Context, target string) error {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return fmt.Errorf("invalid target URL")
	}
	addr := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		addr = net.JoinHostPort(u.Hostname(), port)
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dast: nothing is listening at %s: check the target URL and port (%v)", addr, err)
	}
	conn.Close()
	return nil
}

// buildArgs assembles the nuclei argv for one scan. Split out from Scan so the
// flag construction (fuzzing, auth headers, filters) is unit-testable without
// invoking the binary. Header VALUES may be live session credentials; they go
// into the argv nuclei needs but are never logged by Argus.
func buildArgs(opts Options, outPath, listPath string) []string {
	args := []string{
		"-jsonl", "-o", outPath,
		"-disable-update-check", // no network callout for a newer nuclei/templates
		"-no-interactsh",        // no OOB callout server; scan touches only the target
		"-no-color", "-silent",
	}
	if listPath != "" {
		args = append(args, "-l", listPath)
	} else {
		args = append(args, "-target", opts.URL)
	}
	if opts.Fuzzing {
		args = append(args, "-dast") // load active fuzzing templates
	}
	for _, h := range opts.Headers {
		if h = strings.TrimSpace(h); h != "" {
			args = append(args, "-H", h)
		}
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
	return args
}

// writeURLList writes the endpoint list to a temp file for nuclei -l and
// returns the path plus a cleanup func.
func writeURLList(urls []string) (string, func(), error) {
	f, err := os.CreateTemp("", "argus-nuclei-urls-*.txt")
	if err != nil {
		return "", func() {}, fmt.Errorf("dast: url list temp file: %w", err)
	}
	if _, err := f.WriteString(strings.Join(urls, "\n") + "\n"); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", func() {}, err
	}
	return f.Name(), func() { os.Remove(f.Name()) }, nil
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
