# Contributing to Bulwark

Thanks for helping build Bulwark. This project has a strong, specific ethos —
reading it first will save a round-trip on review.

## The ethos (read this before your first PR)

- **Measured, never asserted.** Detection breadth, precision, and recall are
  *proven by tests against labeled fixtures*, not claimed in prose. New
  language/scanner coverage lands only with a labeled plant that proves it;
  honest gaps are documented (`PLANT-GAP`), never hidden. See
  `internal/coverage`.
- **The LLM is enrichment, never a dependency or an authority.** It never
  moves a severity, a gate, a compliance mapping, or a finding's status. Prompt
  assembly and output validation are a security boundary (`internal/triage`) —
  reviewed carefully, never auto-generated.
- **Determinism where it counts.** Severity banding, compliance mapping,
  fingerprints, and correlation are deterministic and table-tested. A change to
  any of them ships with its doc and its test in the same commit.
- **Honesty over polish.** If a scanner catches nothing, say so in the PR. If a
  fix is partial, say so. A silently narrowed result is worse than a stated gap.

Design-in-writing-first: risk tables, the findings model, and threat rows are
written in `docs/` *before* the code, and tests pin both.

## Dev setup

```bash
# Go toolchain (1.22+; CI uses stable) builds the CLI + embedded console.
go build -o bulwark ./cmd/bulwark

# Scanners on PATH enable the integration tests (all optional; tests skip
# gracefully when a tool is absent):
#   semgrep, gitleaks, trivy, checkov, prowler  (+ Ollama for triage evals)

# The web console (React/Vite) lives in ui/. Rebuild it before it ships in
# the binary (the server embeds ui/dist via go:embed). Node 22 LTS:
cd ui && npm install && npm run build   # emits ui/dist, embedded on next go build
```

## Tests

```bash
go test ./...              # full suite
go test -short ./...       # skips network/tool-dependent integration tests
go test -race ./internal/jobs ./internal/server   # concurrency-sensitive pkgs
```

Integration tests that shell out to a scanner or an LLM **skip** when the tool
is unavailable — they never fail for a missing dependency. If you touch the
SARIF writer, re-validate against the 2.1.0 schema (see the ajv note in the
cloud-posture PR / `internal/report`).

## Pull requests

- One coherent change per PR; imperative commit subjects.
- New behavior ships with a test that would fail without it.
- Touching a deterministic contract (severity, compliance, fingerprint,
  correlation, an authz row, a threat row)? Update its doc in the same commit.
- Run `gofmt`, `go vet ./...`, and the relevant tests before pushing.
- Security-relevant changes: see [`SECURITY.md`](SECURITY.md) and the threat
  model in `docs/console-ops.md`.

By contributing you agree your contributions are licensed under the project's
[Apache-2.0 license](LICENSE).
