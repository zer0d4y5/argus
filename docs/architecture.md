# Architecture

The platform is an **orchestrator + AI layer**, not a from-scratch scanning
engine. Best-in-class OSS engines are wrapped behind adapters, their output is
normalized into one unified findings model, and the value is added on top:
correlation/dedup, severity gating, and (in later phases) AI triage, risk
scoring, and compliance mapping.

```
[ scanners ]   semgrep · gitleaks · trivy        (Phase 3+: checkov/kics · zap · nuclei · codeql)
      |            adapters normalize → unified findings model
      v
[ core ]       normalize · correlate/dedup · severity gate     (Phase 2+: AI triage · risk score · compliance map)
      v
[ surfaces ]   CLI · GitHub Action · SARIF / Markdown / JSON   (Phase 8: API server · dashboard)
```

## Package layout

| Package | Role | Ownership note |
|---|---|---|
| `cmd/appsec` | CLI entrypoint (cobra) | |
| `internal/scanner` | `Adapter` interface + semgrep/gitleaks/trivy adapters | adapters shell out; degrade gracefully when a tool is missing |
| `internal/model` | **Unified findings schema**, severity normalization, fingerprints, ignore-filter | security-critical: the contract everything hangs off (see `docs/findings-model.md`) |
| `internal/correlate` | dedup/correlation | security-critical: a wrong merge silently drops a finding |
| `internal/report` | SARIF 2.1.0 / Markdown / JSON writers | SARIF writer is the GitHub code-scanning contract |
| `internal/config` | `appsec.yml` loading + validation | |
| `internal/triage` | AI-triage seam — interface + no-op impl | real implementation is Phase 2 |

## Data flow of `appsec scan <target>`

1. Load `appsec.yml` (flags override file values).
2. Build the adapter list; skip unavailable tools with a stderr NOTE (never a
   hard failure — CI images differ).
3. Run all available adapters **in parallel** (errgroup), each under a
   per-scanner timeout hanging off one cancellable context. A scanner error is
   reported and does not abort the other scanners.
4. `model.Normalize`: RawFinding → Finding (severity normalization,
   fingerprints). The only place this conversion happens.
5. `model.FilterIgnored`: apply `ignore_paths` / `ignore_rules`; suppression
   counts are reported, never silent.
6. `correlate.Correlate`: dedup/merge, deterministic sort.
7. `triage.Triager` seam (no-op in Phase 1).
8. Write the report (`--format sarif|markdown|json`).
9. Severity gate: exit 1 if any finding meets/exceeds `--fail-severity`.

## Design rules

- **Adapters are dumb, the core is smart.** Adapters map native JSON to
  `RawFinding` and nothing else — no severity decisions, no filtering. That
  keeps every judgment call in one reviewable, tested place.
- **Never silently drop a finding.** Unknown severities fail toward `medium`;
  correlation merges only on strong identity; suppressions are counted;
  SARIF emits every finding it is given; a malformed individual result is
  skipped without discarding the rest of the tool's output.
- **Secrets never persist.** The gitleaks adapter strips plaintext secret
  material before anything reaches the model (`--redact` + sanitized payload).
- **The adapter interface is the swap seam.** An adapter could be replaced by
  a custom engine (e.g. an AI-native SAST pass) without touching the core.
- Tool availability is runtime-detected (`Available()`), so one binary works
  in any CI image and does as much as the image allows.
