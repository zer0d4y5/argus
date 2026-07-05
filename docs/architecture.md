# Architecture

The platform is an **orchestrator + AI layer**, not a from-scratch scanning
engine. Best-in-class OSS engines are wrapped behind adapters, their output is
normalized into one unified findings model, and the value is added on top:
correlation/dedup, severity gating, and (in later phases) AI triage, risk
scoring, and compliance mapping.

```
[ scanners ]   semgrep · gitleaks · trivy · checkov · trivy-config    (later: kics · zap · nuclei · codeql)
      |            adapters normalize → unified findings model
      v
[ core ]       normalize · correlate/dedup · AI triage · risk score · compliance map · severity gate
      v
[ surfaces ]   CLI · GitHub Action · SARIF / Markdown / JSON · gap report (`appsec comply`) · web console (`appsec serve`)
```

## Package layout

| Package | Role | Ownership note |
|---|---|---|
| `cmd/appsec` | CLI entrypoint (cobra) | |
| `internal/scanner` | `Adapter` interface + semgrep/gitleaks/trivy/checkov/trivy-config adapters | adapters shell out; degrade gracefully when a tool is missing. The IaC pair (checkov + trivy-config, category `IAC`) runs whenever available — `--profile` governs semgrep only; the trivy-config adapter reuses the trivy binary so IaC needs no new install |
| `internal/model` | **Unified findings schema**, severity normalization, fingerprints, ignore-filter | security-critical: the contract everything hangs off (see `docs/findings-model.md`) |
| `internal/correlate` | dedup/correlation | security-critical: a wrong merge silently drops a finding |
| `internal/report` | SARIF 2.1.0 / Markdown / JSON writers | SARIF writer is the GitHub code-scanning contract |
| `internal/config` | `appsec.yml` loading + validation | |
| `internal/triage` | AI triage: `Triager` interface, no-op impl, LLM impl (Phase 2) | security-critical: prompt assembly is the injection boundary, output validation is the only path model text enters reports; never drops/reorders findings |
| `internal/llm` | provider-agnostic completion clients: Ollama (local, default) + Anthropic, plus a test fake | transport only — providers send prompts verbatim and return raw text; API keys env-only |
| `internal/risk` | 0–10 risk score: deterministic baseline + bounded LLM adjustment | security-critical: the LLM can never set a score, only move it within `docs/risk-scoring.md` bounds |
| `internal/compliance` | framework data (embedded, version-pinned JSON) + mapping engine + gap assessment (`docs/compliance.md`) | security-critical: mapping rows are audit claims — hand-curated, deterministic, no LLM; unmapped is visible, totals reconcile |

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
7. `triage.Triager`: no-op unless `--triage`/`triage.enabled`. The LLM triager
   sends each finding (metadata + a bounded source snippet, hostile-input
   delimited) to the configured provider and records a validated verdict,
   confidence, and rationale. Enrichment only: provider down → note + no-op;
   per-finding failure → `uncertain`; findings are never dropped or reordered.
8. `risk.Apply`: every finding gets a 0–10 risk score — heuristic baseline
   always, plus the bounded verdict adjustment (`docs/risk-scoring.md`).
9. `compliance.Apply`: every finding gets its violated framework controls
   (`complianceControls`, `"<FRAMEWORK>:<control-id>"`) — deterministic,
   hand-curated, always on (`docs/compliance.md`). Enrichment only; a data
   error warns and passes findings through unmapped.
10. Optional `--exclude-fp` (explicit opt-in, counted on stderr): drop
    LLM-marked false positives from the report AND the gate. Default output
    shows everything, verdicts included.
11. Write the report (`--format sarif|markdown|json`).
12. Severity gate: exit 1 if any finding meets/exceeds `--fail-severity`.
    The gate reads `severity` only — never risk scores, verdicts, or
    compliance data (except under the explicit `--exclude-fp`).

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
- **Triage is enrichment, never a dependency.** The scan pipeline completes
  identically with no LLM configured, reachable, or cooperative; triage adds
  fields, and only the explicit `--exclude-fp` opt-in lets a verdict remove a
  finding from output.
- **Scanned code is hostile LLM input.** Finding text and snippets enter
  prompts only between per-request CSPRNG boundary markers with standing
  ignore-instructions; snippet reads are confined to the scan root after
  symlink resolution; model output is parsed as strict JSON with enum/bounds
  validation, free text surviving only as the sanitized, length-capped
  rationale. Triage is strictly per-finding, so a hostile repo cannot steer
  verdicts of other findings.
- **Secrets never reach a cloud LLM.** SECRET findings triage with metadata
  only (no snippet, even locally); non-local providers skip them entirely
  unless the user sets `allow_secret_cloud: true`.
