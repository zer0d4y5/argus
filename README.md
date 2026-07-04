# appsec

One CLI that runs the best open-source security scanners against your repo,
merges their results into a single deduplicated report, and gates your CI on
severity — SAST, secrets, and dependency (SCA) scanning today; IaC, DAST,
AI triage, and compliance mapping on the [roadmap](docs/roadmap.md).

> **Naming:** `appsec` is the working name. Proposed project name: **Bulwark** —
> a defensive wall built from many stones: independent scanners mortared into
> one structure. Rename is a single `go.mod`/import sweep; the CLI keeps a
> short binary name either way.

```
appsec scan ./repo
  → runs in parallel:  semgrep (SAST) · gitleaks (secrets) · trivy fs (SCA)
  → normalizes everything into one findings model
  → dedups/correlates overlapping findings
  → writes SARIF 2.1.0 / Markdown / JSON
  → exits non-zero when findings hit your severity gate
```

## Quickstart

```bash
# Prereqs: Go 1.22+, plus whichever scanners you want on PATH:
#   pipx install semgrep     (or: pip install semgrep)
#   brew install gitleaks trivy
go build -o appsec ./cmd/appsec

# Scan a repository (markdown report to stdout):
./appsec scan path/to/repo

# SARIF for GitHub code scanning:
./appsec scan . --format sarif -o results.sarif

# Fail CI on high or critical findings:
./appsec scan . --fail-severity high
```

Missing scanners are skipped with a note — the CLI degrades gracefully and
runs whatever the environment provides.

## Configuration — `appsec.yml`

Looked up in the working directory (override with `--config`); flags beat file
values.

```yaml
scanners: []            # subset to run, e.g. [semgrep, gitleaks]; empty = all
fail_severity: high     # critical | high | medium | low | info | none
format: markdown        # sarif | markdown | json
ignore_paths:           # glob patterns; `dir/**` ignores a subtree
  - testdata/**
  - vendor
ignore_rules:           # exact rule IDs to suppress
  - generic-api-key
timeout: 600            # per-scanner timeout, seconds
```

Suppressed findings are counted on stderr — suppression is never silent.

## GitHub Action

`.github/workflows/appsec.yml` runs on every PR: it scans, uploads SARIF to
GitHub code scanning, and fails the build on high+ findings. Copy it into any
repo and adjust the gate.

## Output formats

- **SARIF 2.1.0** — validates against the official schema; ingested by GitHub
  code scanning (severity mapped to `security-severity` so alerts bucket
  correctly; stable fingerprints so alerts track across commits).
- **Markdown** — human-readable summary + findings grouped by severity.
- **JSON** — the full unified findings model (`docs/findings-model.md`),
  including per-tool raw payload passthrough.

## Docs

- [Architecture](docs/architecture.md) — orchestrator design, package layout, design rules
- [Findings model](docs/findings-model.md) — the unified schema (versioned)
- [Roadmap](docs/roadmap.md) — Phases 2–8: AI triage, IaC, compliance, DAST, threat modeling, IAST, platform

## Development

```bash
go build ./... && go test ./...
./appsec scan testdata/fixture   # deliberately vulnerable sample; expect findings
```

Licensed under Apache-2.0.
