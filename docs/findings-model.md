# Unified Findings Model

**Schema version: 1.0.0** (`model.SchemaVersion`)

This is the single most important contract in the platform. Every scanner
adapter maps its native output *into* this model; every downstream stage —
correlation, severity gating, AI triage, compliance mapping, and all report
writers — operates *only* on this model. Adding a scanner never changes the
core; changing the core is a versioned event.

```
tool-native JSON ──(adapter)──> RawFinding ──(Normalize)──> Finding ──(Correlate)──> []Finding
```

## RawFinding (adapter output)

What an adapter emits: native tool data mapped to common field names, with the
tool's **original severity string left verbatim** — normalization happens in
exactly one place (`model.Normalize`), never inside adapters.

| Field | Type | Notes |
|---|---|---|
| `Tool` | string | `semgrep` \| `gitleaks` \| `trivy` (one adapter = one tool) |
| `Category` | string | `SAST` \| `SECRET` \| `SCA` (later: `IAC`, `DAST`) |
| `RuleID` | string | tool's rule/check/vulnerability ID |
| `Title`, `Description` | string | human-readable |
| `RawSeverity` | string | tool-native severity string, verbatim |
| `Confidence` | string | tool-reported confidence, `""` if none |
| `File`, `StartLine`, `EndLine` | string, int, int | path relative to scan root; `0` = N/A |
| `CWEs` | []string | e.g. `["CWE-89"]`, any format the tool emits |
| `CVE` | string | CVE/GHSA identifier for SCA findings |
| `Package` | string | `name@version` for SCA findings |
| `Remediation` | string | fix guidance if the tool provides one |
| `Meta` | map[string]string | extra tool fields worth keeping |
| `RawPayload` | json.RawMessage | the original per-result object, verbatim¹ |

¹ Exception: the gitleaks adapter stores a **sanitized** payload with the
plaintext `Secret` and `Line` fields removed. Secret material must never be
persisted into reports.

## Finding (normalized record)

Produced by `model.Normalize`. JSON field names are camelCase as tagged in
`internal/model/finding.go`.

| Field | Notes |
|---|---|
| `id` | Stable fingerprint (see below) |
| `tool` / `tools` | Primary reporting tool / all tools after correlation |
| `category` | `SAST` \| `SECRET` \| `SCA` \| `IAC` \| `DAST` |
| `ruleId`, `title`, `description` | |
| `severity` | Normalized scale: `critical` > `high` > `medium` > `low` > `info` |
| `rawSeverity` | Tool-native string, preserved for audit |
| `confidence` | Tool-reported, free-form for now |
| `location` | `{file, startLine, endLine, url}` — `url` reserved for DAST |
| `package`, `cve`, `cwes` | SCA / classification identity |
| `remediation` | |
| `meta`, `rawPayload` | Tool passthrough |
| `complianceControls` | **Enrichment slot** — Phase 4 (framework control IDs) |
| `triage` | **Enrichment slot** — Phase 2 (`{verdict, rationale, model}`) |
| `riskScore` | **Enrichment slot** — Phase 2 (0–10 float pointer, nil = unscored) |

## Severity normalization

Defined in `internal/model/severity.go` (`NormalizeSeverity`), explicit per
tool. Design rule: **an unrecognized native severity may never make a finding
disappear or sink to `info`** — unknowns fail toward `medium` so they still
surface and can trip a gate.

| Tool | Native | Normalized |
|---|---|---|
| semgrep | `ERROR` | high |
| semgrep | `WARNING` | medium |
| semgrep | `INFO` | info |
| gitleaks | *(none)* | high — a leaked credential is directly exploitable |
| trivy | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` | same |
| trivy | `UNKNOWN` | medium — un-scored ≠ harmless |
| *any* | unrecognized | medium (raw string preserved in `rawSeverity`) |

## Fingerprint (stable ID)

`model.Fingerprint` = first 32 hex chars of SHA-256 over
`(algver, tool, category, ruleId, file, startLine, package, cve)` with NUL
separators. Properties:

- **Stable across runs** on the same code: no description text, severity, or
  raw payload in the hash (tools reword these between versions).
- **Tool-scoped**: two tools reporting the same issue get different IDs;
  cross-tool identity is *correlation's* job, via correlation keys, so that
  merging logic can evolve without invalidating stored fingerprints.
- The fingerprint algorithm is versioned (`v1` seed) independently of the
  schema version.
- Emitted into SARIF as `partialFingerprints["appsec/fingerprint/v1"]`, which
  GitHub code scanning uses to track alert identity across commits.

Known limitation (v1): line-number drift changes SAST/secret fingerprints.
Acceptable for Phase 1; a context-hash variant can ship as `v2` alongside `v1`.

## Correlation keys (dedup)

Defined in `internal/correlate`. Conservative by design — wrongly merging two
*different* issues silently drops a finding, the worst failure mode this tool
can have. When in doubt, don't merge.

- **SCA**: `category + CVE + package` — the same advisory in the same package
  reported by two SCA tools is one finding.
- **Code findings** (same category only): exact `ruleId + file + startLine`,
  or *cross-tool* fuzzy match = same file + overlapping line range + shared
  CWE. Findings without line info never fuzzy-merge.
- Merges take max severity, union `tools`/`cwes`, keep first non-empty
  description/remediation, and widen the location. Nothing is discarded.

## Versioning rules

- `SchemaVersion` (semver) is embedded in JSON reports.
- Additive optional fields: minor bump. Renamed/removed/retyped fields or
  changed severity semantics: major bump plus a migration note here.
- The fingerprint algorithm versions independently; new algorithms are added
  as new `partialFingerprints` keys, old keys keep emitting during a
  deprecation window.
