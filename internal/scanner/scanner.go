// Package scanner defines the Adapter interface and the adapters that wrap
// external scanning tools (semgrep, gitleaks, trivy, checkov).
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// Adapter is the interface every scanner tool must implement to be integrated
// into the pipeline.
type Adapter interface {
	Name() string
	Category() string
	Available() bool
	Scan(ctx context.Context, target string) ([]model.RawFinding, error)
}

// All returns the full adapter set in a stable order, with the semgrep adapter
// configured to run the given curated ruleset packs. Pass nil to use semgrep's
// built-in default (p/ci). Resolve the packs with ResolveSemgrepRulesets.
// The IaC adapters (checkov, trivy-config) run whenever available and not
// excluded by --scanners; `--profile` governs semgrep only.
func All(semgrepRulesets []string, offline bool) []Adapter {
	return []Adapter{&Semgrep{Rulesets: semgrepRulesets, Offline: offline}, &Gitleaks{}, &Trivy{}, &OSV{}, &Checkov{}, &TrivyConfig{}}
}

// toolOnPath checks if an executable exists on the system PATH.
func toolOnPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// SemgrepBinaryEnv is the env var that overrides which semgrep-compatible
// binary Argus invokes. Opengrep (the community fork of semgrep, created after
// Semgrep moved inter-file analysis to the paid tier) is a drop-in: same CLI,
// same rule format, so it needs no code changes beyond the binary name.
const SemgrepBinaryEnv = "ARGUS_SEMGREP_BINARY"

// pickSemgrepBinary decides which semgrep-compatible binary to run: an explicit
// override if it is present, else semgrep, else opengrep if only it is
// installed. Falls back to "semgrep" so error messages name the expected tool.
// Pure (onPath injected) for testing.
func pickSemgrepBinary(override string, onPath func(string) bool) string {
	if override != "" && onPath(override) {
		return override
	}
	if onPath("semgrep") {
		return "semgrep"
	}
	if onPath("opengrep") {
		return "opengrep"
	}
	return "semgrep"
}

// semgrepBinary returns the semgrep-compatible binary to invoke, honoring the
// ARGUS_SEMGREP_BINARY override and auto-detecting Opengrep.
func semgrepBinary() string {
	return pickSemgrepBinary(strings.TrimSpace(os.Getenv(SemgrepBinaryEnv)), toolOnPath)
}

// runJSON executes a command and returns its stdout. Scanners conventionally
// exit non-zero when findings exist, so a non-zero exit is NOT an error as
// long as the tool produced output; it is an error only when there is no
// stdout to parse (start failure, crash, missing binary).
func runJSON(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	if stdout.Len() == 0 && err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s: %s", name, msg)
	}
	return stdout.Bytes(), nil
}
