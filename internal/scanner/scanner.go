// Package scanner defines the Adapter interface and the adapters that wrap
// external scanning tools (semgrep, gitleaks, trivy).
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
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
func All(semgrepRulesets []string) []Adapter {
	return []Adapter{&Semgrep{Rulesets: semgrepRulesets}, &Gitleaks{}, &Trivy{}}
}

// toolOnPath checks if an executable exists on the system PATH.
func toolOnPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
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
