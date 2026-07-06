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
[ surfaces ]   CLI · GitHub Action · SARIF / Markdown / JSON · gap report (`bulwark comply`) · web console (`bulwark serve`)
```

The scan pipeline itself lives in `internal/pipeline` and has exactly two
callers: the `bulwark scan` CLI command (a thin flag-parsing wrapper) and the
console's serial job queue. Both run the same code path end to end.

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
| `internal/pipeline` | the extracted scan pipeline: adapter selection → parallel scanners → normalize → filter → correlate → triage → risk → compliance | one code path for CLI and console; progress is a pre-formatted-line callback (CLI prints verbatim, console streams into job status) |
| `internal/runstore` | timestamped run files + run-to-run deltas (`.appsec/runs`) | security-critical: delta rules are the one place a finding could vanish from view; JSON shape frozen |
| `internal/server` | web console: read API, authz table + middleware, login/session handlers, ops API, scan executor | security-critical: the authz table in `authz.go` is the entire authorization policy (`docs/console-ops.md`) |
| `internal/server/auth` | argon2id user store, opaque-token sessions + CSRF, login rate limiter | security-critical: hashes/tokens never serialized out; constant-time compares; fail closed |
| `internal/targets` | registered scan-target allowlist (`.appsec/targets.json`): dir + git targets, per-target config block, scope confinement | security-critical: the only bridge from a browser request to a filesystem path or clone URL; git URL policy and scope rules per `docs/console-ops.md` S1/S2/S3 |
| `internal/gitws` | server-owned git workspaces for remote targets: shallow clone/refresh, commit provenance | security-critical: fixed argv + `--` separator, transport locked to https (argv AND env), time/size budgets, no credential prompts |
| `internal/snippet` | bounded code-frame capture into run files (schema 1.4.0) + the shared path-confinement primitive | security-critical: SECRET findings never get snippets; symlink-resolved containment shared with triage — one implementation, not two |
| `internal/jobs` | strictly serial scan queue, bounded pending, in-memory state | one scan at a time protects the runstore and the single-queue Ollama triage |
| `internal/audit` | append-only `.appsec/audit.jsonl` (logins, CRUD, config changes, scan launch/finish/explain) | the durable provenance record — run files carry no launchedBy |

## Data flow of `bulwark scan <target>`

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
- **The console earns exec the hard way.** Scan launching from the browser
  goes through registered target IDs only (no free-text paths), closed-enum
  options, one serial job at a time, and the single authz table — with zero
  users configured the console is exactly the old read-only viewer. The full
  threat model and matrix live in `docs/console-ops.md`.
