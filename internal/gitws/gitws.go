// Package gitws manages the server-owned git workspaces behind remote scan
// targets: shallow clone on first scan, fetch+reset refresh after, commit
// SHA reporting.
//
// SECURITY-CRITICAL (docs/console-ops.md S1/§12.1): the clone URL was
// validated at registration (https only, no userinfo), but this package
// does not trust that alone. Every git invocation here uses a FIXED argv
// with a "--" separator (the URL can never become a flag), transports are
// locked down twice (`-c protocol.file.allow=never -c protocol.ext.allow=never`
// on argv AND GIT_ALLOW_PROTOCOL in the environment), credential prompts
// are disabled so a private repo fails fast instead of hanging the worker,
// and clone/refresh runs under a hard time budget plus a post-sync
// workspace size cap.
package gitws

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultTimeout bounds one clone or refresh (docs/console-ops.md §12.1).
	DefaultTimeout = 10 * time.Minute
	// DefaultMaxBytes caps the workspace size after a sync; a repo bigger
	// than this fails the job loudly instead of filling the disk.
	DefaultMaxBytes = 1 << 30 // 1 GiB
	// maxGitStderr bounds how much git stderr rides into an error message.
	maxGitStderr = 400
)

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// Syncer clones/refreshes workspaces. The zero value is NOT usable; call New.
type Syncer struct {
	timeout  time.Duration
	maxBytes int64
	// allowFileProtocol is a TEST-ONLY hook (set via NewInsecureFileForTest)
	// so tests can clone local bare fixtures without network. Production
	// construction can never enable it.
	allowFileProtocol bool
}

// New returns a production Syncer: https-only transport, default budgets.
func New() Syncer {
	return Syncer{timeout: DefaultTimeout, maxBytes: DefaultMaxBytes}
}

// NewInsecureFileForTest returns a Syncer that additionally permits the
// file:// transport. It exists so tests can exercise the full
// clone→scan→refresh path against `git init --bare` fixtures in a tempdir;
// nothing in production code calls it (a grep-able invariant).
func NewInsecureFileForTest() Syncer {
	return Syncer{timeout: DefaultTimeout, maxBytes: DefaultMaxBytes, allowFileProtocol: true}
}

// Sync makes dir an up-to-date shallow working copy of url (optionally
// pinned to branch) and returns the checked-out commit SHA. It clones when
// dir has no repository and fetch+resets when it does — reset, not clean,
// so the workspace's own untracked .appsec/runs history survives refreshes.
func (s Syncer) Sync(ctx context.Context, url, branch, dir string, progress func(line string)) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		progress(fmt.Sprintf("==> refreshing %s\n", url))
		if err := s.refresh(ctx, branch, dir); err != nil {
			return "", err
		}
	} else {
		// A leftover directory without .git is a failed earlier clone;
		// dir is the server-derived workspace path, safe to recreate.
		if err := os.RemoveAll(dir); err != nil {
			return "", fmt.Errorf("git workspace: reset dir: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return "", fmt.Errorf("git workspace: mkdir: %w", err)
		}
		progress(fmt.Sprintf("==> cloning %s\n", url))
		if err := s.clone(ctx, url, branch, dir); err != nil {
			return "", err
		}
	}

	if err := s.checkSize(dir); err != nil {
		return "", err
	}

	commit, err := s.head(ctx, dir)
	if err != nil {
		return "", err
	}
	progress(fmt.Sprintf("==> at commit %s\n", commit))
	return commit, nil
}

// clone runs the initial shallow clone with a fixed argv.
func (s Syncer) clone(ctx context.Context, url, branch, dir string) error {
	args := s.lockdownArgs()
	args = append(args, "clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet")
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, "--", url, dir)
	return s.run(ctx, "", args)
}

// refresh fetches the tracked ref shallowly and hard-resets the working
// tree to it. Untracked files (the workspace's own .appsec) are preserved.
func (s Syncer) refresh(ctx context.Context, branch, dir string) error {
	ref := branch
	if ref == "" {
		ref = "HEAD"
	}
	fetch := s.lockdownArgs()
	fetch = append(fetch, "fetch", "--depth", "1", "--no-tags", "--quiet", "origin", ref)
	if err := s.run(ctx, dir, fetch); err != nil {
		return err
	}
	reset := s.lockdownArgs()
	reset = append(reset, "reset", "--hard", "--quiet", "FETCH_HEAD")
	return s.run(ctx, dir, reset)
}

// head returns the workspace's checked-out commit, validated as a SHA so a
// corrupted repo can never inject text into progress/audit lines.
func (s Syncer) head(ctx context.Context, dir string) (string, error) {
	out, err := s.output(ctx, dir, []string{"rev-parse", "HEAD"})
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(out)
	if !commitRe.MatchString(sha) {
		return "", fmt.Errorf("git workspace: unexpected rev-parse output")
	}
	return sha, nil
}

// lockdownArgs is the transport policy prefix on EVERY git invocation.
func (s Syncer) lockdownArgs() []string {
	fileAllow := "never"
	if s.allowFileProtocol {
		fileAllow = "always"
	}
	return []string{
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=" + fileAllow,
	}
}

// env builds the child environment: the caller's env (ambient credential
// helpers need HOME etc.) plus the protocol allowlist and no-prompt guards.
func (s Syncer) env() []string {
	allow := "https"
	if s.allowFileProtocol {
		allow = "https:file"
	}
	return append(os.Environ(),
		"GIT_ALLOW_PROTOCOL="+allow,
		"GIT_TERMINAL_PROMPT=0",  // fail, never prompt, on missing credentials
		"GIT_ASKPASS=/bin/false", // belt and braces for GUI askpass paths
	)
}

func (s Syncer) run(ctx context.Context, dir string, args []string) error {
	_, err := s.output(ctx, dir, args)
	return err
}

func (s Syncer) output(ctx context.Context, dir string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = s.env()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("git workspace: %s timed out", args[safeArgIndex(args)])
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > maxGitStderr {
			msg = msg[:maxGitStderr] + "…"
		}
		return "", fmt.Errorf("git %s failed: %s", args[safeArgIndex(args)], msg)
	}
	return stdout.String(), nil
}

// safeArgIndex finds the subcommand (first arg after the -c pairs) for
// error labels.
func safeArgIndex(args []string) int {
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" {
			i++ // skip the -c value
			continue
		}
		return i
	}
	return 0
}

// checkSize enforces the post-sync workspace cap.
func (s Syncer) checkSize(dir string) error {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // a racing delete is not a size violation
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		if total > s.maxBytes {
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("git workspace: size check: %w", err)
	}
	if total > s.maxBytes {
		return fmt.Errorf("git workspace exceeds the %d MiB size budget — refusing to scan", s.maxBytes>>20)
	}
	return nil
}
