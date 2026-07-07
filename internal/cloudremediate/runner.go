package cloudremediate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Execution of a built plan. The command NEVER comes from the client: the
// server builds a Plan from the catalog and a finding, and the runner executes
// exactly that plan's dry-run or apply commands. The write credential is a
// validated profile NAME resolved by the AWS SDK inside the child process,
// exactly like a cloud scan's read profile — no key material enters Argus.
//
// Defense in depth over the already-vetted, argv-only, grammar-validated
// catalog: the binary must be allowlisted, and no argument may carry a shell
// metacharacter or a destructive verb. A command that fails these never runs.

// Executor runs one argv with the given AWS profile and returns combined
// output. Injected so tests exercise the runner without a live account.
type Executor interface {
	Run(ctx context.Context, argv []string, awsProfile string) (output string, err error)
}

// allowedBinaries are the only CLIs a catalog command may invoke.
var allowedBinaries = map[string]bool{"aws": true}

// forbiddenArg rejects a shell metacharacter (there is no shell, but assert it)
// or a destructive verb anywhere in an argument.
var forbiddenArg = regexp.MustCompile(`[;&|$` + "`" + `><\n\r]|(?i)\b(delete|terminate|remove|destroy|rm|drop|revoke|mkfs)\b`)

// CommandResult is the outcome of running one command in a plan.
type CommandResult struct {
	Command Command `json:"command"`
	Output  string  `json:"output"`
	Err     string  `json:"error,omitempty"`
}

// Runner executes plan commands through an Executor with profile validation.
type Runner struct {
	Exec Executor
	// ValidProfile reports whether a write-profile name is in the local config's
	// closed list. Injected (cloudscan.ListAWSProfiles in production) so this
	// package doesn't depend on cloudscan.
	ValidProfile func(name string) bool
}

// Mode selects which commands of a plan to run.
type Mode int

const (
	DryRun Mode = iota // preview: read current state, never mutate
	Apply              // make the change
)

// Run validates the profile and each command, then executes the plan's dry-run
// or apply commands in order, stopping at the first failure. It returns the
// per-command results. A safety-check failure is an error BEFORE anything runs.
func (r *Runner) Run(ctx context.Context, plan Plan, mode Mode, profile string) ([]CommandResult, error) {
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return nil, fmt.Errorf("a write profile is required")
	}
	if r.ValidProfile != nil && !r.ValidProfile(profile) {
		return nil, fmt.Errorf("unknown AWS profile %q: not present in the local AWS config", profile)
	}
	cmds := plan.DryRun
	if mode == Apply {
		cmds = plan.Apply
	}
	if len(cmds) == 0 {
		return nil, fmt.Errorf("plan %s has no %s commands", plan.ID, modeName(mode))
	}
	// Safety-check EVERY command up front so a partial run can't leave a bad one
	// unchecked mid-sequence.
	for _, c := range cmds {
		if err := checkCommand(c); err != nil {
			return nil, err
		}
	}
	if r.Exec == nil {
		return nil, fmt.Errorf("no executor configured")
	}

	results := make([]CommandResult, 0, len(cmds))
	for _, c := range cmds {
		out, err := r.Exec.Run(ctx, []string(c), profile)
		res := CommandResult{Command: c, Output: out}
		if err != nil {
			res.Err = err.Error()
			results = append(results, res)
			return results, fmt.Errorf("%s command failed: %s", modeName(mode), lastLine(out, err))
		}
		results = append(results, res)
	}
	return results, nil
}

// checkCommand is the pre-execution guard: an allowlisted binary and no
// forbidden argument. Belt-and-suspenders over the catalog's own guarantees.
func checkCommand(c Command) error {
	if len(c) == 0 {
		return fmt.Errorf("empty command")
	}
	if !allowedBinaries[c[0]] {
		return fmt.Errorf("command binary %q is not allowed", c[0])
	}
	for _, arg := range c {
		if forbiddenArg.MatchString(arg) {
			return fmt.Errorf("command argument %q failed the safety check", arg)
		}
	}
	return nil
}

func modeName(m Mode) string {
	if m == Apply {
		return "apply"
	}
	return "dry-run"
}

func lastLine(out string, err error) string {
	s := strings.TrimSpace(out)
	if s == "" {
		return err.Error()
	}
	lines := strings.Split(s, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// execProcess is the production Executor: it runs the argv in a child with the
// write profile referenced via AWS_PROFILE, the SAME credential-reference shape
// cloudscan uses. Output is captured (never streamed — it can echo account
// identifiers). The profile value never appears in Argus's own state.
type execProcess struct {
	timeout time.Duration
}

// NewExecutor returns the production process executor with a per-command
// timeout.
func NewExecutor(timeout time.Duration) Executor {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &execProcess{timeout: timeout}
}

func (e *execProcess) Run(ctx context.Context, argv []string, awsProfile string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("empty command")
	}
	cctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	// The credential REFERENCE: a validated profile NAME, resolved by the AWS
	// SDK inside the child. The value dies with the process.
	cmd.Env = append(append([]string{}, os.Environ()...), "AWS_PROFILE="+awsProfile)
	out, err := cmd.CombinedOutput()
	if cctx.Err() != nil {
		return string(out), fmt.Errorf("command timed out")
	}
	return string(out), err
}
