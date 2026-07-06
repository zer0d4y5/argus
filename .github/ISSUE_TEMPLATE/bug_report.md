---
name: Bug report
about: Something Bulwark did wrong — a crash, a wrong finding, a broken command
title: ""
labels: bug
---

**Do not report security vulnerabilities here** — see [SECURITY.md](../SECURITY.md).

### What happened

A clear description of the bug.

### To reproduce

The exact command or console action, e.g.:

```
bulwark scan ./repo --profile standard
```

### Expected vs actual

What you expected, and what happened instead.

### Environment

- Bulwark version / commit: (`bulwark --version`)
- OS:
- Scanners on PATH and versions (if relevant): semgrep / gitleaks / trivy / checkov / prowler
- If a scan result looks wrong: the finding's `ruleId`, `category`, and (if safe to share) the relevant snippet or the run JSON.
