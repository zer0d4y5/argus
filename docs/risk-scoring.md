# Risk Scoring (v2, contextual)

Every finding in every run gets a risk score in **[0, 10]** (`riskScore` in the
model, one decimal place). The score is computed in `internal/risk` in three
stages:

1. a **deterministic heuristic baseline**: always computed, no LLM required;
2. a **deterministic per-category context modifier**: bounded, table-driven,
   LLM-free. Named signals (realness, sensitivity, exposure surface) move the
   baseline up or down within a hard cap; unknown context is always neutral;
3. a **bounded LLM adjustment**: applied only when AI triage produced a
   verdict for the finding. The LLM never invents the number; it can only move
   the score within the documented bounds below via its verdict and confidence.

Since schema 2.0.0, `severity` is **derived from the deterministic part of
this score** (stages 1–2) via the canonical bands below; that is the one
sanctioned coupling, and it is one-directional and LLM-free. The stage-3 LLM
adjustment affects `riskScore` only: it never changes `severity`, never feeds
the severity gate, and never suppresses a finding.

```
s1    = clamp( baseline(f), 0, 10 )                          : stage 1
delta = clamp( Σ context signal deltas, −3.0, +3.0 )         : stage 2
s2    = clamp( s1 + delta, 0, 10 )
s2    = min( s2, 9.4 )   if secret-shaped and not verified live
det   = round1( s2 )                : the deterministic score; severity = band(det)
final = round1( min( ceil, clamp( s2 + triage_adj, floor, 10 ) ) )   : stage 3
        where ceil  = 9.4 for secret-shaped findings not verified live, else 10
              floor = 0.5 for false-positive verdicts, else 0
```

`det`, the **deterministic score**, is where stage 2 ends: everything above
the `final` line is LLM-free. It is a first-class intermediate in
`internal/risk` (`risk.Apply` returns it per finding) because severity banding
(below) consumes it; the *stored* `riskScore` stays the full stage-3 `final`.

Every stage-2 signal that fired is exported on the finding as `riskSignals`
(schema 1.3.0, see below), so the score is **evidence, not assertion**: the
console and the JSON report can show exactly why a finding ranks where it does.

## Stage 1: heuristic baseline

```
baseline = clamp( base(severity)
                + confidence_mod(tool_confidence)
                + category_mod(category)
                + cwe_mod(cwes)
                + fix_mod(remediation) , 0, 10 )
```

Since schema 2.0.0 the severity input to `base()` is **`toolSeverity`** (the
tool-normalized severity `model.NormalizeSeverity` produces), never the banded
output `severity`. Feeding the banded severity back into stage 1 would make
scores self-amplify; the circularity is broken by construction, and a test in
`internal/risk` pins it. (Documents older than 2.0.0 have no `toolSeverity`;
if they are ever re-scored, their stored `severity`, which *is*
tool-normalized in those documents, is the stage-1 input.)

| Component | Value | Rationale |
|---|---|---|
| `base(critical)` | 9.0 | anchors to the normalized severity scale |
| `base(high)` | 7.0 | |
| `base(medium)` | 5.0 | |
| `base(low)` | 3.0 | |
| `base(info)` | 1.0 | |
| `confidence_mod(high)` | +0.5 | tool is sure → fewer FP discounts |
| `confidence_mod(medium or empty)` | 0.0 | absence of confidence is not evidence |
| `confidence_mod(low)` | −1.0 | tool itself flags likely-FP |
| `category_mod(SECRET)` | +1.0 | a leaked credential is directly exploitable, no chain needed |
| `category_mod(other)` | 0.0 | |
| `cwe_mod` | +0.5 | if any CWE is in the high-impact class (below), else 0 |
| `fix_mod` | +0.25 | if remediation/fixed-version is known: a public fix means a public advisory, and cheap mitigation raises the cost of *not* acting |

**High-impact CWE class** (direct code-execution / auth-bypass / data-exfil
primitives): CWE-22, 77, 78, 89, 94, 95, 287, 306, 434, 502, 611, 798, 918,
1336. The set is a package-level constant in `internal/risk`; extending it is
a normal reviewed change, not a schema event.

Tool confidence strings are matched case-insensitively (`HIGH`/`high`;
semgrep's `extra.metadata.confidence` style). Unrecognized values count as
medium.

## Stage 2: per-category context modifier

Stage 1 ranks a leaked cloud credential, a vulnerable dependency, and an IaC
misconfiguration with the same handful of knobs. Stage 2 adds the context
signals that actually drive risk *for that category*. Design rules, in order:

- **Deterministic and LLM-free.** Every signal is a named, table-driven rule in
  `internal/risk`, same ethos as `highImpactCWEs`: conservative, reviewed,
  auditable. Extending a table is a normal reviewed change.
- **Unknown = neutral (0).** A finding with no path, no entropy, no metadata
  gets no context delta. Absence of evidence never moves a score.
- **Bounded.** The summed delta is clamped to **±3.0** before it touches the
  score, so no heuristic (or stack of heuristics) can dominate severity: a
  critical finding stays ≥ 6.0-ish territory, an info finding cannot be
  context-inflated past mid-band. When the cap binds, a synthetic
  `context.cap` signal records the clamped-off remainder so the exported
  deltas still sum exactly to the applied change.
- **Validity is never assumed, only carried.** No credential is scored as
  confirmed-live from a path substring or an entropy number. See *the
  `verified` hook* below.

### Category coverage

| Category | Context signals used | Deliberately not (yet) used |
|---|---|---|
| SECRET | realness (entropy, test-path), sensitivity (rule identity), exposure (DS-0031 co-location, prod-path heuristic), `verified` hook | live-credential verification (needs the opt-in verifier, future phase); secret *value* analysis (scrubbed by design, must stay gone) |
| IAC | DS-0031 secret-exposure handling (incl. env-var name table, SECRET co-location, `verified` hook); public-exposure rule table | data-bearing-resource classification (needs a careful resource-type mapping, future reviewed table); cross-resource reachability |
| SAST | test-path deprioritization | reachability/taint: that is Phase 7/8 (IAST), not faked here |
| SCA | none: **trivy's `fs` JSON emits no KEV / EPSS / exploit-maturity fields** (verified against trivy 0.6x output: `CVSS`, `Severity`, `FixedVersion`, dates, references, nothing exploit-related), so SCA stays on the stage-1 baseline rather than inventing a signal | exploit-maturity boost: add when a KEV/EPSS source is wired in as its own reviewed input |
| DAST | none (no DAST adapter yet) | – |
| CLOUD | exposure (prowler check categories: internet-exposed), identity blast radius (reviewed admin-policy check table + privilege-escalation category), data protection (encryption category), detection readiness (logging category), all from prowler check metadata only | resource criticality (needs a data-classification input we don't have); reachability graphs (Attack-path products fake this from topology; we don't); KEV/EPSS-style exploited-in-wild boosts (no source wired) |

### Secret-shaped findings

Two finding shapes carry leaked-credential risk and share the machinery:

- **`SECRET` category** (gitleaks): the scanner *detected a secret value*. The
  value itself is scrubbed at the adapter (`--redact` plus re-scrub) and is
  **never** re-read to assess realness: the only inputs are `ruleId`,
  `meta.entropy`, the file path, and co-located findings.
- **`IAC` rule `DS-0031`** (trivy-config): a Dockerfile `ENV`/`ARG` *name
  pattern* that suggests a secret (e.g. `Possible exposure of secret env
  "AWS_SECRET_ACCESS_KEY" in ENV`). A pattern match is **not** a detected
  credential; trivy rates it CRITICAL regardless, and stage 2's job is to be
  honest about that gap.

#### SECRET signal table

| Code | Delta | Fires when |
|---|---|---|
| `secret.test_path` | **−2.0** | any path token ∈ test tokens (below): the placeholder / not-prod signal |
| `secret.low_entropy` | **−1.0** | `meta.entropy` parses and is < 3.0: structured-but-dummy values (`AKIAAAAAAAAAAAAAAAAA` ≈ 0.9); gitleaks' generic rules already require ≥ 3.5, so this mainly catches named-rule matches on placeholders |
| `secret.high_value_rule` | **+0.75** | `ruleId` ∈ high-value rule table (below) **and** path is not test-like |
| `secret.prod_path` | **+0.5** | any path token ∈ {`prod`, `production`} **and** path is not test-like. This is a **prod-path heuristic**, never "verified production"; the signal note says so |
| `secret.colocated_exposure` | **+0.75** | a `DS-0031` finding exists on the **same file**: a detected secret *plus* an insecure-exposure mechanism is the genuine "baked into a shipped image" case |
| `secret.verified_live` | **+1.5** | `meta.verified == "live"`: also lifts the unverified ceiling (below) |
| `secret.verified_invalid` | **−3.0** | `meta.verified == "invalid"`: a confirmed-dead credential is noise (still visible: rotation hygiene, process leak) |

#### DS-0031 signal table

| Code | Delta | Fires when |
|---|---|---|
| `iac.secret_pattern_unverified` | **−1.5** | always on DS-0031 (unless `verified` is `live` or `invalid`): pulls the flat CRITICAL down into *elevated, unverified* territory, because a name-pattern match is not a confirmed live credential |
| `iac.secret_env_cloud_name` | **+0.5** | the env-var name quoted in `meta.message` ∈ credential-name table (below): `AWS_SECRET_ACCESS_KEY` is sharper evidence than `BUILD_TOKEN` |
| `iac.colocated_secret` | **+0.75** | a `SECRET` finding exists on the **same file**: the pattern has a detected secret value behind it |
| `secret.test_path` | **−2.0** | same test-path rule as above (a Dockerfile in `testdata/` is not shipped) |
| `secret.verified_live` / `secret.verified_invalid` | as above | the `verified` hook is shared across secret-shaped findings |

#### Precedence rules (exhaustive)

1. `meta.verified == "live"` suppresses `iac.secret_pattern_unverified` (the
   question it hedges is answered) and lifts the unverified ceiling.
2. `meta.verified == "invalid"` suppresses **every other** secret-shaped
   signal: the realness/sensitivity heuristics are proxies for exactly the
   question that has now been answered negatively. Only
   `secret.verified_invalid` (−3.0) is emitted.
3. A test-like path suppresses the positive heuristics
   `secret.high_value_rule` and `secret.prod_path` (a fixtures directory named
   `prod` is still fixtures). Negative signals still stack.

#### The `verified` hook (validity: carried, never assumed)

Static scanning **cannot** know whether a credential is live; that requires
authenticating to the provider with a possibly-real production key, a
network action with its own safety review, deliberately **not** built here.
The score carries validity as an explicit three-state input instead:

- `meta.verified` ∈ `live | invalid | unchecked` (absent / anything else =
  `unchecked`, matched case-insensitively). Default is **`unchecked` =
  neutral**: no delta either way.
- Only a **future opt-in verifier or a human** sets it. Nothing in this
  codebase writes `live` today.
- **Unverified ceiling:** a secret-shaped finding that is not `verified: live`
  is capped at **9.4**; elevated-to-critical is reachable on corroborating
  static evidence, but the top of the critical band ([9.5, 10]) is reserved
  for *confirmed-live* credentials. The cap applies at stage 2 and to the
  final score (a triage true-positive cannot vault it either: the LLM never
  sees the secret value, so it cannot confirm liveness). When the ceiling
  binds at stage 2, a synthetic `secret.unverified_ceiling` signal records the
  reduction.
- `verified: live` lifts the ceiling and adds +1.5, so a live high-value
  exposed credential saturates at 10.0.

This is the symmetric honesty the scorer aims for: worst case is not assumed
(DS-0031 alone is no longer an automatic 9+), best case is not assumed either
(a redacted high-entropy cloud key on a prod path climbs to 9.4, not 10), and
the one unobservable signal is a first-class, explicitly-unresolved input.

#### Reviewed tables

**Test-path tokens**: path is lowercased and split into tokens on `/`, `.`,
`_`, `-` and every other non-alphanumeric boundary; a token must match
exactly (so `contest.go` does not match `test`):
`test, tests, testing, testdata, spec, specs, fixture, fixtures, example,
examples, sample, samples, mock, mocks, dummy, demo`.

**Prod-path tokens** (same tokenization): `prod, production`.

**High-value secret rules** (gitleaks rule IDs; cloud credentials, private
keys, DB connection strings, VCS/payment tokens, the "what does it unlock"
tier above `generic-*`):
exact: `private-key, jdbc-connection-string, stripe-access-token, github-pat,
github-oauth, github-app-token, github-refresh-token, gitlab-pat`;
prefix families: `aws-*, gcp-*, azure-*, google-*`.

**Credential env-var names** (DS-0031 `meta.message`, first double-quoted
token): `AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AZURE_CLIENT_SECRET,
GOOGLE_APPLICATION_CREDENTIALS, GCP_SERVICE_ACCOUNT_KEY, GITHUB_TOKEN,
GITLAB_TOKEN, DATABASE_URL, DB_PASSWORD, POSTGRES_PASSWORD, MYSQL_PASSWORD,
MYSQL_ROOT_PASSWORD, MONGODB_URI, REDIS_PASSWORD, STRIPE_SECRET_KEY,
NPM_TOKEN, DOCKER_PASSWORD`.

**Co-location**: file identity is exact match on the normalized
`location.file` (slash-normalized by `model.Normalize`); both directions are
computed from the same run's findings inside `risk.Apply`, which receives the
full correlated slice. If only one scanner ran, co-location simply never
fires: unknown = neutral.

### IAC (beyond DS-0031)

| Code | Delta | Fires when |
|---|---|---|
| `iac.public_exposure` | **+0.75** | `ruleId` (or `meta.avdid`, `AVD-` prefix stripped) ∈ public-exposure table: internet-facing misconfigurations outrank internal hygiene of equal severity |

**Public-exposure rules** (seeded with the AWS S3 public-access family,
world-open ingress, and default-public IPs; extending it is a normal reviewed
change): `AWS-0086, AWS-0087, AWS-0088, AWS-0091, AWS-0092, AWS-0093,
AWS-0094, AWS-0107, AWS-0164`.

General IAC findings do **not** get the test-path discount this session
(example/module Terraform is routinely copied into production verbatim; the
conservative call is neutral). Checkov rule IDs (`CKV_*`) are not yet in the
table; trivy-config covers the same files with graded severities.

### SAST

| Code | Delta | Fires when |
|---|---|---|
| `sast.test_path` | **−1.0** | any path token ∈ test tokens: an injection sink in test code is real code smell but not a reachable production sink |

Everything else stays on the baseline until reachability exists for real
(Phase 7/8 IAST); reachability is **not** faked from heuristics.

### SCA

No context signals this session; see the coverage table: trivy emits no
exploit-maturity data in `trivy fs` JSON output, and inventing an exploit
signal from CVSS vector strings would double-count severity. When a
KEV-catalog or EPSS feed is wired in as an explicit input, a bounded positive
delta slots in here as a reviewed table like the others.

### CLOUD (cloud-posture session, schema 2.1.0)

Cloud posture findings arrive from prowler already graded (Critical → Low),
so stage 2's job is narrow: order findings *within* a severity grade by the
exposure context prowler's own metadata attests to, exactly like
`iac.public_exposure` orders IaC. Signals read **only** the prowler check
identity (`ruleId`), the check's category tags (`meta.categories`, written
by the adapter from prowler's own check metadata), and nothing else: never
resource contents, never account topology, never model output. All deltas
are positive (posture failures are never *discounted* by heuristics: there
is no cloud analogue of a test directory) and modest (prowler's grading
carries the base signal; these nudge, they don't dominate). Unknown =
neutral: a record with no category tags gets no delta. The ±3.0 cap is
unchanged.

| Code | Delta | Fires when |
|---|---|---|
| `cloud.public_exposure` | **+0.75** | check categories contain `internet-exposed`: an internet-facing misconfiguration outranks internal hygiene of equal grade (same weight and rationale as `iac.public_exposure`) |
| `cloud.iam_wildcard` | **+0.75** | `ruleId` ∈ the reviewed admin-policy table (below), or categories contain `privilege-escalation`: `*:*` grants and escalation paths are account-wide blast radius |
| `cloud.unencrypted_at_rest` | **+0.25** | categories contain `encryption`: data-at-rest gaps order above same-grade operational hygiene |
| `cloud.logging_disabled` | **+0.25** | categories contain `logging`: missing audit/access logging degrades detection and forensics; kept positive-and-small deliberately (a logging gap is not itself an exposure, but it makes every other finding harder to catch) |

**Admin-policy checks** (prowler 5.31 check IDs, verified against the
installed registry; extending is a normal reviewed change):
`iam_aws_attached_policy_no_administrative_privileges`,
`iam_customer_attached_policy_no_administrative_privileges`,
`iam_customer_unattached_policy_no_administrative_privileges`,
`iam_inline_policy_no_administrative_privileges`,
`iam_inline_policy_allows_privilege_escalation`,
`iam_policy_allows_privilege_escalation`,
`iam_group_administrator_access_policy`,
`iam_role_administratoraccess_policy`,
`iam_user_administrator_access_policy`.

Signals stack (a public, unencrypted bucket fires two rows) and the summed
delta obeys the global cap. Severity banding then applies unchanged;
**CLOUD findings get no special-cased severity anywhere**: prowler's grade
is `toolSeverity` (stage-1 input), stage 2 adds the rows above, and the
band table converts the deterministic score exactly as it does for every
other category.

## Stage 3: bounded LLM adjustment

AI triage yields `verdict ∈ {true-positive, false-positive, uncertain}` and
`confidence ∈ [0, 1]` (validated and clamped at parse time, see
`internal/triage`). The adjustment is a pure function of those two values:

| Verdict | Adjustment | Bound |
|---|---|---|
| `true-positive` | `+1.0 × confidence` | capped at 10.0 (9.4 for unverified secret-shaped findings) |
| `false-positive` | `−4.0 × confidence` | floored at **0.5** |
| `uncertain` | 0 | – |

Design constraints, in order of importance:

- **A false-positive verdict can deprioritize but never erase.** The 0.5 floor
  keeps the finding visible and above "no risk"; an LLM verdict is advice, not
  proof. Removing FP-marked findings from output is a separate, explicit,
  opt-in step (`--exclude-fp`): never the score's job.
- **The adjustment is bounded and monotone in confidence**, so a prompt-injected
  or hallucinating model can move a score by at most −4.0/+1.0; it cannot set
  an arbitrary value, it cannot touch stage 1 or stage 2, and it cannot touch
  any *other* finding (triage is strictly per-finding).
- The downward bound is larger than the upward one on purpose: the main value
  of triage is FP suppression; severity already carries the upside.

## Severity banding (schema 2.0.0)

Since schema 2.0.0, a finding's `severity` is a **pure function of the
deterministic score** `det` (stages 1–2 above, one decimal), not of any
single tool's opinion, and explicitly **not** of the stage-3 LLM adjustment.
"High" therefore means the same thing on every finding from every tool: the
platform's own deterministic, evidence-backed risk estimate landed in the high
band.

| Deterministic score `det` | Severity |
|---|---|
| 9.0 – 10.0 | `critical` |
| 7.0 – 8.9 | `high` |
| 4.0 – 6.9 | `medium` |
| 0.1 – 3.9 | `low` |
| 0.0 | `info` |

The bands are user-specified canon (they are not re-derived from data) and
they deliberately match the Overview histogram cutoffs (≥9.0 / ≥7.0 / ≥4.0),
so the histogram and the finding badges agree **by construction**. Scores are
one-decimal, so the boundaries are exact; the implementation
(`model.SeverityForScore`) bands on the integer decisecond value to keep
float representation out of the decision.

**`info` is reachable, but only as exactly 0.0.** The stage-1 floor is not
above zero: an `info`-severity finding whose tool reports `low` confidence
baselines at `1.0 − 1.0 = 0.0`, and stage 2's clamp floor is 0. An
`info`-severity SAST finding in test code (`1.0 − 1.0 = 0.0` via
`sast.test_path`) gets there too. Anything that rounds to 0.1 or above is
`low`.

Design rules, in order of importance:

- **Banding consumes `det`, never `final`.** A triage verdict moves
  `riskScore` within its documented bounds; it can never move a finding
  across the severity gate. A test pins that flipping a verdict changes
  `riskScore` but never `severity`. This keeps the platform ethos intact: no
  LLM output ever touches severity, the gate, or another finding.
- **`toolSeverity` is input and audit trail.** What `NormalizeSeverity`
  produced survives on the finding (alongside `rawSeverity`, the tool's
  verbatim string), feeds stage 1, and renders in the console as
  "tool said: …" context. The banded `severity` is output only.
- **The severity gate reads banded severity.** `--fail-severity high` means
  "any finding whose deterministic risk lands ≥ 7.0". That is the point of
  the change: the gate reflects context (test-path, exposure, corroboration),
  not tool opinion. The gate's inputs remain 100% deterministic.
- **Old documents are never re-banded.** A ≤1.4.0 run's stored `severity` is
  tool-normalized and is displayed as-is; its stored risk scores may predate
  current signal tables, so re-banding it would silently rewrite history. See
  the 2.0.0 migration note in `docs/findings-model.md`.

Worked contrast (from the examples below): the gitleaks secret in
`testdata/fixtures/creds.env` (#5, det 5.0) was `high` under tool-normalized
severity; banded it is `medium`: the test-path and low-entropy signals are
now allowed to mean something. The DS-0031 next to a real detected secret
(#4, det 9.0) rises from tool `critical`→9.25-baseline territory to a banded
`critical` *with evidence attached*, while the bare `ARG BUILD_TOKEN` pattern
(#1, det 7.8) settles at `high`.

## `riskSignals` (schema 1.3.0)

Stage 2's evidence trail is exported on each finding:

```json
"riskSignals": [
  {"code": "secret.high_value_rule", "delta": 0.75, "note": "named high-value provider rule (cloud credential, key material, or DB DSN)"},
  {"code": "secret.colocated_exposure", "delta": 0.75, "note": "DS-0031 secret-exposure pattern on the same file"},
  {"code": "secret.unverified_ceiling", "delta": -0.1, "note": "unverified secrets cap at 9.4; only meta.verified=live lifts the ceiling"}
]
```

- Additive, optional (`omitempty`); absent when no stage-2 signal fired.
  Schema bump 1.0 → **1.3.0** is documented in `docs/findings-model.md`.
- `baseline + Σ deltas` equals the stage-2 output exactly: the synthetic
  `context.cap` and `secret.unverified_ceiling` rows keep the sum honest when
  a bound binds. (The final [0,10] clamp and the stage-3 adjustment are
  documented above and shown separately in the console.)
- Notes are fixed strings from the signal tables: never model output, never
  scanned-file content. The prod-path note says **"prod-path heuristic"**,
  never "verified production".

## Worked examples

Baselines: a gitleaks SECRET is high severity, no CWE, no confidence, no
remediation → `7.0 + 1.0 = 8.0`. A trivy-config DS-0031 is critical with a
resolution → `9.0 + 0.25 = 9.25`.

| # | Finding | Stage 1 | Stage 2 | Stage 3 | Final |
|---|---|---|---|---|---|
| 1 | DS-0031 alone, `ARG BUILD_TOKEN` | 9.25 | −1.5 (unverified pattern) | – | **7.8** |
| 2 | DS-0031 alone, `ENV AWS_SECRET_ACCESS_KEY` | 9.25 | −1.5 + 0.5 (cloud name) | – | **8.3** |
| 3 | gitleaks `aws-access-token`, entropy 5.2, `deploy/Dockerfile`, DS-0031 on same file | 8.0 | +0.75 (high-value) +0.75 (co-located) → 9.5 → ceiling −0.1 | – | **9.4** |
| 4 | the DS-0031 next to #3 (`AWS_SECRET_ACCESS_KEY`) | 9.25 | −1.5 + 0.5 + 0.75 (co-located secret) | – | **9.0** |
| 5 | same secret as #3 but in `testdata/fixtures/creds.env`, entropy 2.1 | 8.0 | −2.0 (test path) −1.0 (low entropy); high-value suppressed | – | **5.0** |
| 6 | #3 with `meta.verified = live` | 8.0 | +0.75 +0.75 +1.5, ceiling lifted → 11.0 → clamp | – | **10.0** |
| 7 | #3 with `meta.verified = invalid` | 8.0 | −3.0 only (all heuristics suppressed) | – | **5.0** |
| 8 | semgrep SQLi (high, CWE-89), `src/api/users.py` | 7.5 | 0 (no signal) | TP @ 0.9 | **8.4** |
| 9 | same SQLi rule in `tests/api_test.py` | 7.5 | −1.0 (test path) | – | **6.5** |
| 10 | trivy CVE (critical, fix available) | 9.25 | 0 (SCA on baseline) | – | **9.3** |
| 11 | trivy-config `AWS-0107` world-open ingress (high, resolution) | 7.25 | +0.75 (public exposure) | – | **8.0** |
| 12 | semgrep `shell=True` on a constant (medium) | 5.0 | 0 | FP @ 1.0 | **1.0** |
| 13 | gitleaks secret, no path/entropy metadata at all | 8.0 | 0 (unknown = neutral) | – | **8.0** |
| 14 | prowler `iam_aws_attached_policy_no_administrative_privileges` (critical, remediation) | 9.25 | +0.75 (iam wildcard) | – | **10.0** |
| 15 | prowler `ec2_instance_public_ip` (high, remediation, `internet-exposed`) | 7.25 | +0.75 (public exposure) | – | **8.0** |
| 16 | prowler `s3_bucket_kms_encryption` (medium, remediation, `encryption`) | 5.25 | +0.25 (unencrypted at rest) | – | **5.5** |
| 17 | prowler logging check (low, remediation, `logging`) | 3.25 | +0.25 (logging disabled) | – | **3.5** |

Banding note: severity comes from the **Stage 2** column's result (the
deterministic score), not the Final column. So #8 is `high` (det 7.5) even
though triage lifted its final score to 8.4, and #12 stays `medium` (det 5.0)
even though a confident FP verdict dropped its final score to 1.0; verdicts
move `riskScore`, never `severity`.

The flagship contrast the v2 stage exists for: **#3 (9.4) > #4 (9.0) > #1/#2
(7.8/8.3) > #5 (5.0)**. A corroborated real-looking secret in a shipped image
outranks the bare exposure pattern, which still sits elevated; the same secret
in fixtures sinks to the bottom of the high band; and nothing reaches
[9.5, 10] without `verified: live` (#6).

## Where the score surfaces

- **JSON**: `riskScore` + `riskSignals` on each finding.
- **Markdown**: `Risk` column in the findings tables.
- **SARIF**: `properties.riskScore` on each result. It deliberately does NOT
  replace `properties.security-severity`, which stays severity-derived;
  GitHub's bucketing must not move on LLM output. `riskSignals` is not
  emitted to SARIF this session (writer untouched).
- **Console**: the finding detail pane lists the fired signals as chips with
  their deltas: the "why" behind the rank.

## Triage response schema (contract with `internal/triage`)

The LLM must answer with exactly one JSON object:

```json
{"verdict": "true-positive" | "false-positive" | "uncertain",
 "confidence": 0.0-1.0,
 "rationale": "one or two sentences"}
```

Validation (in `internal/triage`, security-critical, never delegated):
verdict must match the enum exactly; confidence is clamped to [0,1]
(missing → 0.5); rationale is free text but truncated to 500 runes with
control characters stripped; it is the ONLY place model free-text reaches a
report. Anything else (malformed JSON, unknown verdict, refusals, prose)
degrades that one finding to `uncertain` with zero score adjustment.

## Change control

The formula is a written contract: this document and `internal/risk` must not
drift, and the worked-example numbers above are pinned verbatim in
`internal/risk` table tests. Changing a signal table or a bound is a normal
reviewed change (PR touching doc + code + tests together); adding a new
*field* (like `riskSignals`) is an additive schema minor bump; changing the
formula is never a schema event on its own.
