# Unified Findings Model

**Schema version: 2.1.0** (`model.SchemaVersion`)

This is the single most important contract in the platform. Every scanner
adapter maps its native output *into* this model; every downstream stage
(correlation, severity gating, AI triage, compliance mapping, and all report
writers) operates *only* on this model. Adding a scanner never changes the
core; changing the core is a versioned event.

```
tool-native JSON ──(adapter)──> RawFinding ──(Normalize)──> Finding ──(Correlate)──> []Finding
```

## RawFinding (adapter output)

What an adapter emits: native tool data mapped to common field names, with the
tool's **original severity string left verbatim**: normalization happens in
exactly one place (`model.Normalize`), never inside adapters.

| Field | Type | Notes |
|---|---|---|
| `Tool` | string | `semgrep` \| `gitleaks` \| `trivy` \| `checkov` \| `trivy-config` (one adapter = one tool) |
| `Category` | string | `SAST` \| `SECRET` \| `SCA` \| `IAC` (later: `DAST`) |
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
| `category` | `SAST` \| `SECRET` \| `SCA` \| `IAC` \| `DAST` \| `CLOUD` (2.1.0, cloud security posture) |
| `ruleId`, `title`, `description` | |
| `severity` | **Banded deterministic risk** (2.0.0): a pure function of the stage-2 deterministic risk score. See the canonical band table in `docs/risk-scoring.md`. Scale: `critical` > `high` > `medium` > `low` > `info`. This is what the severity gate, reporters, SARIF level/security-severity, and all rollups read. LLM-free by construction (banding never sees the stage-3 triage adjustment) |
| `toolSeverity` | **New in 2.0.0.** What `model.NormalizeSeverity` produces from the tool's native severity: the stage-1 risk input and the "tool said: …" audit trail. Always present in ≥2.0.0 documents; absent (JSON-omitted) in older documents, where `severity` itself is tool-normalized. Readers must feature-detect, never assume |
| `rawSeverity` | Tool-native string, verbatim, preserved for audit |
| `confidence` | Tool-reported, free-form for now |
| `location` | `{file, resource, startLine, endLine, url, snippet}`: `url` reserved for DAST; `snippet` optional (1.4.0, see below); `resource` optional (2.1.0): the cloud resource UID/ARN a `CLOUD` finding is about. Cloud posture findings have no file, and `resource` is their place-slot, including in the fingerprint (see below) |
| `package`, `cve`, `cwes` | SCA / classification identity |
| `remediation` | |
| `meta`, `rawPayload` | Tool passthrough |
| `complianceControls` | **Enrichment slot**: populated by Phase 5 compliance mapping on every finding in every run. Sorted, deduplicated `"<FRAMEWORK>:<control-id>"` values (e.g. `ASVS:V5.3.4`, `PCI-DSS:6.2.4`, `CIS-AWS:2.1`); framework IDs and control IDs come from the version-pinned data files in `internal/compliance/data/` (see `docs/compliance.md`). Deterministic and hand-curated: no LLM involvement. Empty/omitted when no framework maps the finding (the gap report shows it as *unmapped*, never hides it). Never feeds the severity gate |
| `triage` | **Enrichment slot**: populated by Phase 2 AI triage: `{verdict, confidence, rationale, model}`. `verdict` ∈ `true-positive` \| `false-positive` \| `uncertain`; `confidence` ∈ [0,1] (validated/clamped at parse time, bounds the risk adjustment); `rationale` is sanitized, length-capped model text; `model` is the provider/model audit tag |
| `riskScore` | **Enrichment slot**: populated by Phase 2 for every finding in every run (0–10, one decimal; see `docs/risk-scoring.md`). `nil` only in pre-Phase-2 documents |
| `riskSignals` | **Enrichment slot** (1.3.0, risk v2): the stage-2 context evidence behind `riskScore`: `[{code, delta, note}]` rows from the reviewed signal tables in `internal/risk` (see `docs/risk-scoring.md`). `code`/`note` are fixed table strings: never model output, never scanned-file content; deltas (with the synthetic cap/ceiling rows) sum to exactly the applied context change. Empty/omitted when no signal fired. Never feeds the severity gate |

Triage semantics are strictly additive: a verdict never changes `severity`,
never feeds the default severity gate, and never removes a finding (the
explicit `--exclude-fp` opt-in filters at report time; the model itself is
untouched).

## location.snippet (1.4.0)

Optional captured code frame around the finding, so a reader can see the
offending code without access to the scanned tree:

```json
"location": {
  "file": "src/db.py", "startLine": 42, "endLine": 42,
  "snippet": { "startLine": 39, "lines": ["def get(uid):", "  q = \"SELECT …\"", "…"] }
}
```

Captured by `internal/snippet` post-pipeline / pre-save (console executor
and CLI `--save`), NOT by `Normalize`: a snippet is presentation context,
not finding identity, and never enters the fingerprint. Rules (spec:
docs/console-ops.md S4/§12.4): **SECRET-category findings never carry a
snippet** (same rule as triage prompts: secret material must not persist
into run files); ≤10 lines and ≤2 KB per finding, ≤1 MiB per run; binary and
minified files skipped; the read is confined to the scan root after symlink
resolution. `snippet.startLine` is the 1-based line number of `lines[0]`;
lines are raw file text (rune-capped per line), hostile data, rendered
escaped-only. Absent slot = "not captured" (old document, secret, capped, or
unreadable); readers must feature-detect, never assume.

## Severity normalization

Defined in `internal/model/severity.go` (`NormalizeSeverity`), explicit per
tool. Since 2.0.0 this table produces **`toolSeverity`**, the stage-1 risk
input and audit context, while the finding's `severity` is banded from the
deterministic risk score (`docs/risk-scoring.md`, "Severity banding").
Design rule unchanged: **an unrecognized native severity may never make a
finding disappear or sink to `info`**; unknowns fail toward `medium` so they
still surface, carry a mid baseline into the risk score, and can trip a gate.

Titles (2.0.0 quality floor): every normalized finding has a non-empty,
deterministic, tool-derived `title`: never LLM text. Semgrep titles are the
first sentence of the rule message; gitleaks titles come from a curated
rule-ID map; any adapter that provides no title falls back to a deterministic
humanization of the rule ID (dash/dot split, sentence case). All titles pass
through one sanitizer in `Normalize` (control characters stripped, whitespace
collapsed, capped at 120 runes) because rule messages are repo-adjacent
hostile data that render in reports and prompts. `description` falls back to
the title when empty; `remediation` stays empty when the tool provides
nothing; inventing remediation text is out of scope by design. Titles and
severity are **not** fingerprint inputs (proven by test), so both can change
without breaking run deltas.

| Tool | Native | Normalized |
|---|---|---|
| semgrep | `ERROR` | high |
| semgrep | `WARNING` | medium |
| semgrep | `INFO` | info |
| gitleaks | *(none)* | high: a leaked credential is directly exploitable |
| trivy | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` | same |
| trivy | `UNKNOWN` | medium: un-scored ≠ harmless |
| trivy-config | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` | same (same engine as trivy, misconfiguration pass) |
| trivy-config | `UNKNOWN` | medium |
| checkov | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` | same: present only in platform-enriched runs |
| checkov | *(none)* | medium: see policy below |
| *any* | unrecognized | medium (raw string preserved in `rawSeverity`) |

**Checkov severity policy (Phase 4).** OSS checkov emits `severity: null` for
nearly every check: severity grading is a paid-platform enrichment. Those
findings normalize to **medium**, by the same reasoning as trivy's `UNKNOWN`:
un-scored is unassessed, not harmless, and must stay visible and able to trip
a medium gate. We deliberately do **not** maintain a curated per-check-ID
severity table here: trivy-config runs alongside checkov on the same files
with graded native severities, so headline misconfigurations (public bucket,
privileged container, secret in ENV) still surface as high/critical through
that engine, and a hand-maintained rule table is compliance-framework work
that belongs to Phase 5. When checkov *does* emit a severity
(platform-enriched runs), it is mapped verbatim. Checkov CIS/benchmark IDs,
when present, are captured verbatim into `meta.benchmarks`, never into
`complianceControls`, which stays reserved for Phase 5.

## Fingerprint (stable ID)

`model.Fingerprint` = first 32 hex chars of SHA-256 over
`(algver, tool, category, ruleId, place, startLine, package, cve)` with NUL
separators, where `place` = `location.file` when non-empty, else
`location.resource` (2.1.0). Properties:

- **Stable across runs** on the same code: no description text, severity, or
  raw payload in the hash (tools reword these between versions).
- **The file slot is a documented overload** (2.1.0): for every finding with
  a file, all pre-cloud findings, the hash input is byte-identical to what
  algorithm v1 always produced, so no existing ID moved (pinned by a golden
  test). A `CLOUD` finding has no file; its resource UID/ARN fills the slot,
  giving the same check on the same resource the same ID across runs; run
  deltas work for cloud runs with zero new machinery. Chosen over minting a
  fingerprint v2 to keep every existing ID stable; the cost is this
  documented overload of one hash position.
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

Defined in `internal/correlate`. Conservative by design: wrongly merging two
*different* issues silently drops a finding, the worst failure mode this tool
can have. When in doubt, don't merge.

- **SCA**: `category + CVE + package`. The same advisory in the same package
  reported by two SCA tools is one finding.
- **Code findings** (same category only): exact `ruleId + file + startLine`,
  or *cross-tool* fuzzy match = same file + overlapping line range + shared
  CWE. Findings without line info never fuzzy-merge.
- **Same-tool SAST noise collapse** (2.1.0 pipeline, locked decision of the
  cloud-posture session): the same tool flagging the same weakness (shared
  CWE) at an overlapping range in one file via *different rule IDs* is one
  finding: the duplicate shape wide semgrep profiles produce. The survivor
  is the finding with the most specific title (longest; smallest rule ID as
  tie-break) and keeps its fingerprint; absorbed rule IDs are recorded in
  `meta.alsoRuleIds` (sorted, comma-joined). SAST only: a second gitleaks
  rule is a different credential claim, and distinct IaC/CLOUD checks on one
  resource are distinct controls. The recall eval asserts plant catch sets
  are identical pre/post-correlate: collapse, never suppression.
- Merges take max severity, union `tools`/`cwes`, keep first non-empty
  description/remediation, and widen the location. Nothing is discarded.

## Versioning rules

- `SchemaVersion` (semver) is embedded in JSON reports.
- **2.1.0** (cloud-posture): added the `CLOUD` category and optional
  `location.resource` (cloud resource UID/ARN). Additive only; 2.0.0
  documents remain valid. The fingerprint algorithm stays `v1`: its file
  slot takes `location.file` when set, else `location.resource` (see
  Fingerprint above); byte-identical for every finding that has a file or
  lacks both, proven by golden test. `CLOUD` findings flow through the same
  severity banding, risk scoring (with their own reviewed stage-2 signal
  table), compliance mapping, and triage seams as every other category: no
  special-cased severity. Readers must treat `location.resource` as the
  place-slot for findings without a file.
- **2.0.0** (deep-scan): **severity semantics changed**: `severity` is now
  the banded deterministic risk score (canonical band table in
  `docs/risk-scoring.md`), no longer the tool-normalized value; the
  tool-normalized value moved to the new `toolSeverity` field. Major bump per
  the rule below. **Migration:** documents ≤1.4.0 remain readable; their
  `severity` is tool-normalized and MAY be displayed as-is; **re-banding old
  documents is forbidden** (their stored risk scores may predate current
  signal tables, and mixing re-banded and original severities in one trend
  line would silently rewrite history). `toolSeverity` is absent in old
  documents; readers feature-detect. Run deltas keep working across the
  boundary because fingerprints never contained severity or title. Also in
  2.0.0: the deterministic title quality floor (above), `meta.gitHistory` /
  `meta.commit` on secrets found only in git history, and run-level coverage
  accounting in saved run documents.
- **1.4.0** (Scan Studio): added optional `location.snippet` (captured code
  frame; format and capture rules documented above). Additive only; 1.3.0
  documents remain valid, and readers must treat a missing snippet as "not
  captured", never as "no code".
- **1.3.0** (Risk v2): added optional `riskSignals` (context-signal evidence
  for the risk score; format documented above). Additive only; 1.2.0
  documents remain valid, and readers must treat a missing slot as "no
  context signal fired", never as "unscored".
- **1.2.0** (Phase 5): `complianceControls` is now populated (it existed,
  always empty, since 1.0.0; writing it is a semantic change, hence the
  minor bump). Value format documented above. Additive only; 1.1.0 documents
  remain valid, and readers must treat a missing/empty slot as "unmapped",
  not "compliant".
- **1.1.0** (Phase 2): added optional `triage.confidence`. Additive only;
  1.0.0 documents remain valid.
- Additive optional fields: minor bump. Renamed/removed/retyped fields or
  changed severity semantics: major bump plus a migration note here.
- The fingerprint algorithm versions independently; new algorithms are added
  as new `partialFingerprints` keys, old keys keep emitting during a
  deprecation window.
