# Security Policy

Bulwark is a security tool, so we hold its own posture to the standard it
enforces.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" on the Security tab), or email the maintainers.

Please include: affected version/commit, a description, and a minimal
reproduction. We aim to acknowledge within **72 hours** and to ship a fix or a
mitigation plan within **14 days** for confirmed high-severity issues.

## Supported versions

Bulwark is pre-1.0. Security fixes land on `main`; there is no back-port
branch yet. Pin a commit if you need stability.

## Threat model & security-relevant invariants

Bulwark is local-first and processes hostile input (scanned code, tool output,
LLM responses, cloud metadata). The design invariants below are enforced by
tests — a change that breaks one should fail CI, and a report that one does
not hold is a vulnerability:

- **Credentials are referenced, never collected.** Cloud scanning takes a
  profile *name* validated against a closed list; no key material is accepted,
  stored, logged, or placed in a prompt. See `docs/console-ops.md` threat rows
  C1–C4.
- **The LLM never holds authority.** AI triage/explain/posture output never
  moves a severity, a gate, a compliance mapping, or a finding's status; it is
  bounded, sanitized, and never executed. Prompt assembly is a reviewed
  security boundary (`internal/triage`).
- **Secrets never leak downstream.** Detected secret *values* are scrubbed at
  the adapter and never re-read, snippeted, or sent to a cloud LLM without an
  explicit opt-in.
- **The console treats all finding data as hostile.** Strict JSON, `nosniff`,
  a strict CSP with no inline script, loopback bind by default, argon2id
  password hashing, CSRF on every mutation, one server-side authz table.
- **No arbitrary paths or arguments from the browser.** Scans run against
  pre-registered target IDs with closed-enum options; nothing user-supplied
  reaches `exec.Command` or a filesystem join.

The full threat model lives in [`docs/console-ops.md`](docs/console-ops.md).
