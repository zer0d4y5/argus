# Compliance Mapping & Gap Assessment

Phase 5 turns findings into audit evidence: every finding is mapped to the
security controls it violates across real frameworks, and `bulwark comply`
turns a scan into a per-framework control coverage report a GRC lead can hand
to an auditor.

## Philosophy

Same ethos as the OWASP rollup (`internal/owasp`), generalized:

- **Deterministic, hand-curated, versioned. No LLM anywhere in this path.**
  A wrong mapping is false audit evidence — every mapping row was reviewed
  against the framework text, and the framework version is pinned in the data.
- **Conservative.** A rule maps only where the framework text defensibly
  covers the finding class. Hygiene checks with no corresponding control
  (e.g. "CPU limits should be set", "S3 bucket versioning") stay **unmapped —
  visibly**. Unmapped is a bucket in the report, never a silent drop.
- **Honest about scope.** Static scanning cannot assess most of any framework.
  Every framework file declares an explicit *not assessable by static
  scanning* list, and the report renders it. The report never claims a control
  "passes" — the strongest statement it makes is *no violations detected*.
- **Totals reconcile.** Per framework: `mapped + unmapped + out-of-scope =
  total findings`, and `violated + clean = all assessable controls`. Tested.

## Frameworks (MVP)

| Framework | Version pinned | Scope (finding categories) | Mapping keys |
|---|---|---|---|
| `ASVS` | OWASP ASVS 4.0.3 | SAST, SECRET, SCA | CWE; category for SECRET/SCA |
| `PCI-DSS` | PCI DSS v4.0 | SAST, SECRET, SCA, IAC | CWE; category for SECRET/SCA/IAC |
| `CIS-AWS` | CIS AWS Foundations Benchmark v1.5.0 | IAC, CLOUD | IAC: rule IDs / families → benchmark section. CLOUD: prowler check IDs → requirement (prowler's own mapping, see below) |
| `CIS-DOCKER` | CIS Docker Benchmark v1.6.0 | IAC | rule families → benchmark section |
| `CIS-K8S` | CIS Kubernetes Benchmark v1.8.0 | IAC | rule IDs → benchmark section |

CIS mapping for **IaC findings** is deliberately at **section granularity**
(e.g. `CIS-AWS:2.1` "Simple Storage Service (S3)", not a sub-control
number): checkov/trivy rules and CIS sub-controls do not line up one-to-one
across benchmark versions, and claiming an exact sub-control we did not
verify would be overclaiming. A section-level claim ("this finding violates
the S3 storage section of the benchmark") is the strongest statement the
rule text supports.

CIS mapping for **CLOUD findings** (cloud-posture session) is at
**requirement granularity** (`CIS-AWS:1.20`), because the mapping is not
ours: the check→requirement rules were **materialized verbatim from prowler
5.31's embedded CIS v1.5 framework data** (`cis_1.5_aws.json`, 63
requirements, all check-mapped) — a deterministic passthrough of the
engine's own version-pinned mapping, never invented here. Prowler's CIS
version (1.5) matches our pinned data file (1.5.0) exactly, so no
intersection loss applies; `TestCISPassthroughMatchesProwler` proves on the
recorded fixture that the engine reproduces prowler's own per-finding
mapping. Sections 1 (IAM) and 4 (Monitoring) left `notAssessable`: they
were unassessable for *IaC-only* scanning, and live posture scanning is
exactly what assesses them. Cloud findings scope by provider
(`providerScope: ["aws"]` + `meta.provider`) rather than rule-ID prefix —
an Azure posture finding is *out of scope* for the AWS benchmark, never
"unmapped". On a prowler upgrade, regenerate the materialized rules from
the new embedded framework data and re-run the passthrough test.

## Data format

Framework data lives in `internal/compliance/data/*.json`, embedded at compile
time (`go:embed`) and validated by a strict loader (every rule must reference
declared controls, exactly one match key per rule, no duplicate control IDs).

JSON rather than Go tables, deliberately:

- **Adding a framework is a data-only change** — drop in a new file, no engine
  edits. SOC 2 / NIST 800-53 / ISO 27001 are follow-on data files.
- The files are diffable and reviewable by GRC people, not only Go readers.
- One generic loader validates every framework the same way; a loader test
  proves data integrity for all files at once.

Shape (see any file in `internal/compliance/data/`):

```json
{
  "id": "ASVS",
  "name": "OWASP Application Security Verification Standard",
  "version": "4.0.3",
  "scope": ["SAST", "SECRET", "SCA"],
  "ruleIdScope": [],
  "controls": [
    {"id": "V5.3.4", "title": "Database queries use parameterized queries or are otherwise protected from SQL injection"}
  ],
  "notAssessable": [
    {"id": "V1", "title": "Architecture, Design and Threat Modeling", "reason": "Requires design review, not code scanning."}
  ],
  "rules": [
    {"cwes": ["CWE-89", "CWE-564"], "controls": ["V5.3.4", "V5.3.5"]},
    {"category": "SECRET", "controls": ["V2.10.4", "V6.4.1"]},
    {"ruleIds": ["CKV_AWS_24"], "controls": ["5"]},
    {"rulePrefixes": ["DS-"], "controls": ["4"]}
  ]
}
```

## Mapping semantics

Implemented in `internal/compliance` (engine: `compliance.go`, report
bucketing: `assess.go`):

- A finding is matched against a framework only if its category is in the
  framework's `scope`; otherwise it is **out of scope** for that framework
  (not "unmapped" — an IaC misconfiguration is not an ASVS gap). Platform
  benchmarks additionally declare `ruleIdScope` prefixes: a Kubernetes rule is
  out of scope for the AWS benchmark, not an AWS mapping gap. "Unmapped" always
  means "our curation has no answer for a finding this framework should speak
  to", never "different platform".
- Within a framework, all matching rules contribute controls (union), with
  one precedence rule: if any **exact rule ID** rule matches, **prefix** rules
  are skipped — exact knowledge beats family defaults.
- `cwes` rules match any of the finding's (normalized) CWEs; `category` rules
  match the finding category; `ruleIds`/`rulePrefixes` match the tool rule ID.
- A finding matching no rule in an in-scope framework is **unmapped** for that
  framework: counted, listed in the gap report, never dropped.

The union of a finding's mapped controls across all frameworks is written to
its `complianceControls` slot as `"<FRAMEWORK>:<control-id>"` (e.g.
`ASVS:V5.3.4`, `PCI-DSS:6.2.4`, `CIS-AWS:2.1`), sorted and deduplicated.
This is an always-on, deterministic pipeline stage after risk scoring —
schema **1.2.0** (see `docs/findings-model.md`).

## The gap report — `bulwark comply`

`bulwark comply [path]` produces the per-framework gap assessment:

- fresh scan of `path` by default (same adapters as `bulwark scan`, no triage —
  the report is deterministic), or `--latest` / `--run <id>` to read a saved
  run from `<path>/.appsec/runs`;
- `--format markdown` (default) or `json`; `-o` to write a file.

Per framework, every control lands in exactly one bucket:

- **Violated** — one or more findings mapped to it (with counts and top
  findings as evidence pointers).
- **No violations detected** ("clean") — the scanners *can* produce evidence
  against this control (it is a target of at least one mapping rule) and none
  was found this run. Deliberately not called "compliant": absence of findings
  is not a certification.
- **Not assessable by static scanning** — declared explicitly in the framework
  data with a reason (design/process/physical/runtime controls). The report
  prints this so it never overclaims coverage.

Plus the two finding-side buckets: **unmapped** findings (in scope, no rule
matched) and **out-of-scope** findings, both counted per framework.

A scanner-shaped honesty statement is embedded in the report header: the
report is evidence *from static scanning only* and control coverage is limited
to what the mapped scanners can see.

## Console

The GRC Overview gains a per-framework compliance panel (violated / clean /
not assessable / unmapped), computed report-side by the server from the run's
findings — the same pattern as the OWASP rollup; stored run files are not
rewritten. The finding detail pane lists mapped controls as chips (server
enriches findings from runs saved before schema 1.2.0 at read time).

## Adding a framework

1. Write `internal/compliance/data/<framework>.json`: pin the framework
   version, declare `scope`, list the controls your rules will reference,
   the `notAssessable` entries, and the mapping rules.
2. Review every rule against the framework text — a mapping row is an audit
   claim. Conservative beats complete: leave it unmapped when in doubt.
3. `go test ./internal/compliance` — the loader test validates the file, the
   reconciliation tests guard the bucketing invariants.

No engine change is required; the file is discovered by the embed glob.

## What this is not

- Not a compliance certification of any kind, and not evidence of the
  process/policy/physical controls that dominate every real framework.
- Not a live cloud-posture assessment (CSPM) — it sees IaC files, not accounts.
- No LLM output feeds this path; verdicts and risk scores do not change
  control status. The severity gate is untouched by compliance data.
