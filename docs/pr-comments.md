# PR review comments

`argus scan --pr-comments` posts the scan's gated findings as review comments
on a GitHub pull request, on the exact changed lines that introduced them.
Paired with a [baseline](getting-started.md#gate-only-on-new-findings-baseline),
this closes the CI adoption loop: the baseline keeps the pre-existing backlog
out of the gate, and the review comments put exactly what the PR *adds* in
front of the developer, where code review already happens.

```bash
argus scan . --baseline .argus-baseline.json --fail-severity high --pr-comments
```

## What gets posted

One batched review per scan (never a flood of single comments):

- A finding whose file and line are part of the PR diff becomes an **inline
  review comment** on that line: severity, risk score, rule, description, and
  remediation.
- Everything else that is new (cloud posture findings, findings on lines the
  PR does not touch, or findings past the 50-comment inline cap) is listed in
  the **review body** as a table, so nothing is silently dropped.
- The set posted is exactly the set the severity gate judges: new since the
  baseline (when `--baseline` is given) and disposition-filtered. A comment
  and a red check always agree on what the PR added. Without a baseline,
  every gate-relevant finding is posted; the diff scoping still keeps inline
  comments on changed lines only.

Posting is **advisory by design**: the exit code always belongs to the
severity gate. A failed post (missing token, fork PR with a read-only token,
network trouble) is a warning on stderr, never a failed scan. The review is
always `COMMENT`, never `REQUEST_CHANGES`: the gate is the verdict, the
comments are the explanation.

Re-running the scan on a new push does not duplicate anything: every posted
finding carries an invisible marker with its stable fingerprint, and findings
already posted on the PR (inline or in an earlier review body) are skipped.

## Secrets are redacted

A `SECRET` finding's comment carries only the severity, the rule identity,
and rotation guidance. Tool descriptions and remediation strings for secrets
can restate matched credential context, so they are never posted; the
comment's placement already says where the problem is.

## Where the PR context comes from

In GitHub Actions, everything is auto-detected: the repository from
`GITHUB_REPOSITORY`, the pull request number from the `pull_request` event's
ref, the API endpoint from `GITHUB_API_URL` (so GitHub Enterprise Server
works), and the token from `GITHUB_TOKEN`. On a `push` run the flag detects
that there is no PR and does nothing, so a single workflow can carry
`--pr-comments` unconditionally.

Outside Actions, pass the coordinates explicitly:

```bash
export GITHUB_TOKEN=...   # referenced by env var name, never stored or logged
argus scan . --baseline main.json --pr-comments --pr 42
```

The repository falls back to `ticketing.github.repo` in `argus.yml`, and the
token env var name honors `ticketing.github.token_env` (default
`GITHUB_TOKEN`), the same plumbing the [ticketing sync](console-ops.md) uses.

## GitHub Actions example

```yaml
name: security
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write   # required for posting review comments

jobs:
  argus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Scan and comment
        run: |
          argus scan . --baseline .argus-baseline.json \
            --fail-severity high --pr-comments
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Note that pull requests from forks get a read-only `GITHUB_TOKEN`: the gate
still runs and fails the check as usual, and the comment post degrades to a
warning in the log.

## Token hygiene

The token is read from the configured env var at the moment of the API call,
used in the `Authorization` header, and never stored, logged, echoed in error
messages, or written to any report. API error messages carry the HTTP status
code only, never response bodies.
