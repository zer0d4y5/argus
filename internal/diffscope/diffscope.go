// Package diffscope implements incremental (PR-scoped) scanning: given a git
// base ref, it lists the files changed since the merge-base and materializes
// just those files into a temporary mirror directory that preserves relative
// paths. The unmodified scan pipeline then runs against the mirror.
//
// Why a mirror instead of per-scanner flags: every adapter takes exactly one
// positional target, and a finding's Location.File is relative to that
// target. A mirror that preserves relative paths therefore yields the same
// file paths, the same line numbers, and (fingerprints hash tool, rule,
// place, line) the SAME fingerprints a full scan would produce for those
// files. Baselines, dispositions, PR comments, and ignore_paths all compose
// unchanged, and every scanner is scoped by one mechanism.
//
// The honest trade-off, documented rather than hidden: scanners see only the
// changed files, so cross-file context is absent (a semgrep rule needing a
// sibling file, an SCA manifest whose lockfile did not change). That is
// inherent to PR-scoped scanning; the full scan of main remains the source
// of truth and the baseline covers the backlog.
//
// SECURITY: this package execs git. The base ref is caller input, so it is
// validated against a closed grammar and always separated from paths with
// "--"; git runs with prompts disabled and never touches the network (all
// subcommands are local: rev-parse, merge-base, diff, ls-files). Mirrored
// paths come from git output but are still containment-checked against the
// scan root, and only regular files are copied (symlinks are skipped, so a
// hostile link cannot pull /etc/anything into the scanned set).
package diffscope

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// refPattern is the closed grammar for a base ref: branch, tag, remote ref,
// SHA, or relative forms like HEAD~2 / main@{u}. A leading "-" is impossible
// by construction, so a ref can never be read as a git option.
var refPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@^~{}-]{0,250}$`)

// maxChangedFiles bounds a scoped scan. A change set past this is not a
// review-sized diff; the caller falls back to a full scan (which is the
// fail-safe direction: more coverage, never less).
const maxChangedFiles = 5000

// git runs one local git subcommand rooted at dir and returns stdout.
// Prompts are disabled; errors are bounded and never include stderr verbatim
// beyond the first line (enough to say "unknown revision" without dumping).
func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
	)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", args[0], msg)
	}
	return out.String(), nil
}

// ChangedFiles returns the repo-relative paths changed between the
// merge-base of baseRef and HEAD and the current working tree (committed,
// staged, and unstaged edits all count: what a PR scan must look at is what
// is different from the base), plus untracked files. Deleted files are
// excluded (nothing to scan). The list is sorted and deduplicated.
func ChangedFiles(ctx context.Context, root, baseRef string) ([]string, error) {
	if !refPattern.MatchString(baseRef) {
		return nil, fmt.Errorf("diff-base: invalid ref %q", baseRef)
	}
	if _, err := git(ctx, root, "rev-parse", "--is-inside-work-tree"); err != nil {
		return nil, fmt.Errorf("diff-base: %s is not a git work tree (%v)", root, err)
	}

	// The comparison point is the merge-base, so commits on the base branch
	// after the fork never show up as "changes" in this branch. A shallow
	// clone may not contain the merge-base; that surfaces here as a clear
	// error and the caller falls back to a full scan.
	base, err := git(ctx, root, "merge-base", baseRef, "HEAD")
	if err != nil {
		return nil, fmt.Errorf("diff-base: no merge-base with %q (shallow clone? fetch more history): %v", baseRef, err)
	}
	base = strings.TrimSpace(base)

	changed, err := git(ctx, root, "diff", "--name-only", "-z", "--diff-filter=d", base, "--")
	if err != nil {
		return nil, fmt.Errorf("diff-base: %v", err)
	}
	untracked, err := git(ctx, root, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, fmt.Errorf("diff-base: %v", err)
	}

	seen := map[string]struct{}{}
	var files []string
	for _, chunk := range []string{changed, untracked} {
		for _, p := range strings.Split(chunk, "\x00") {
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			files = append(files, p)
		}
	}
	if len(files) > maxChangedFiles {
		return nil, fmt.Errorf("diff-base: %d changed files exceeds the %d cap for a scoped scan", len(files), maxChangedFiles)
	}
	sort.Strings(files)
	return files, nil
}

// Mirror copies the given repo-relative files from root into a fresh
// temporary directory, preserving relative paths. It returns the mirror
// path and a cleanup func (always non-nil). Files that vanished, are not
// regular (symlinks, devices), or fail containment are skipped, not fatal:
// a scoped scan of slightly fewer files is still honest, and the skipped
// names are returned for the caller's progress note.
func Mirror(root string, files []string) (dir string, skipped []string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "argus-diffscope-*")
	if err != nil {
		return "", nil, func() {}, fmt.Errorf("diff-base: temp dir: %w", err)
	}
	cleanup = func() { os.RemoveAll(dir) }

	for _, rel := range files {
		if !contained(rel) {
			skipped = append(skipped, rel)
			continue
		}
		src := filepath.Join(root, filepath.FromSlash(rel))
		fi, lerr := os.Lstat(src)
		if lerr != nil || !fi.Mode().IsRegular() {
			skipped = append(skipped, rel)
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if cerr := copyFile(src, dst); cerr != nil {
			cleanup()
			return "", nil, func() {}, fmt.Errorf("diff-base: mirror %s: %w", rel, cerr)
		}
	}
	return dir, skipped, cleanup, nil
}

// contained rejects any path that could escape the scan root when joined:
// absolute paths, "..", and the repo's own metadata dirs (git never lists
// .git; .appsec holds runs and dispositions and must never be scanned).
func contained(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\x00") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(rel))
	if clean != rel {
		return false
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." || seg == ".git" || seg == ".appsec" {
			return false
		}
	}
	return true
}

// copyFile copies src to dst (0600, parents created 0700): the mirror is a
// private scratch copy of repo content, world-readable never.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
