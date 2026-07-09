# CI integration

Argus in CI is three flags that reinforce each other:

- `--baseline` gates only on findings **new since the baseline**, so a
  repository with a backlog can adopt a hard gate today.
- `--diff-base` scans **only the files a PR changed** (merge-base aware),
  so the PR loop takes seconds, not minutes.
- `--pr-comments` posts that same delta **on the changed lines** of the
  pull request, so developers see it where code review already happens.

All three compose because they share one identity: the finding fingerprint.
A scoped scan produces byte-identical fingerprints to a full scan, and the
gate, the baseline, and the comments all agree on what "new" means.

## The one-file workflow

Copy
[`examples/github-actions/argus-security.yml`](https://github.com/zer0d4y5/argus/blob/main/examples/github-actions/argus-security.yml)
into `.github/workflows/` and commit. What it does:

- **On every push to `main`**: full scan, then `--write-baseline` records
  the backlog's fingerprints into a build cache.
- **On every pull request**: restores the most recent baseline from the
  cache, scans only the changed files against `origin/<base branch>`, fails
  the check only if the PR **adds** a finding at or above the severity gate,
  and posts the new findings as one batched review on the changed lines.

Notes worth knowing before you trust it:

- **First run**: until the first push to `main` caches a baseline, PR scans
  gate on every finding in the changed files (still diff-scoped, so small).
  Merge the workflow to `main` first, or run
  `argus scan . --write-baseline .argus-baseline.json` locally and commit
  the file, then point `--baseline` at the committed copy instead of the
  cache.
- **`fetch-depth: 0`** matters: `--diff-base` needs the merge-base commit.
  On a shallow clone Argus warns and falls back to a full scan (fail-safe:
  more coverage, never less).
- **Forks**: a PR from a fork gets a read-only `GITHUB_TOKEN`. The gate
  still runs and fails the check as usual; the comment post degrades to a
  log warning.
- **Scanner versions are pinned** in the install step. "Install latest" in
  CI breaks nondeterministically; bump the pins deliberately.
- The example installs semgrep and gitleaks (fast, dependency-free). Add
  trivy or checkov the same way to widen coverage; Argus runs whatever is
  on `PATH`.

## What incremental scanning trades away

`--diff-base` shows scanners only the changed files. Findings that need
cross-file context can be missed in the PR loop: an SCA manifest whose
lockfile did not change, a rule that reads a sibling file. That is inherent
to PR-scoped scanning with any tool, and it is why the workflow keeps the
**full** scan on `main` as the source of truth: anything the PR loop misses
surfaces there, and the next baseline refresh records it honestly.

`--write-baseline` refuses to combine with `--diff-base` for the same
reason: a baseline must describe the whole repository, not one diff.

## Gate semantics, unchanged

Nothing in this loop moves the gate itself: the exit code is decided by
`--fail-severity` over the (baseline- and disposition-narrowed) findings,
exactly as in a local run. PR comments are advisory by design; a failed
comment post (network, permissions) is a log warning, never a failed scan.
Details: [PR review comments](pr-comments.md),
[baseline gating](getting-started.md#gate-only-on-new-findings-baseline),
[incremental scanning](getting-started.md#scan-only-what-changed-incremental).
