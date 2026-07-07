# Coverage: the eagle-eye matrix

> **Generated, not authored.** This file is produced by
> `internal/coverage` from a live scan of the labeled fixtures under
> `testdata/polyglot/`. Regenerate with `make coverage` (or
> `APPSEC_UPDATE_COVERAGE=1 go test ./internal/coverage`). If a cell here
> disagrees with a scan, the scan is right and this file is stale.

Detection is proven, not claimed: a network-dependent test
(`TestPolyglotCoverage`) asserts every ✅ canary below is caught under the
`standard` profile, and fails CI if breadth regresses.

## Scan profiles

`--profile fast|standard|max` (config: `profile:`). Ruleset lists are the
detection policy; they live in one reviewed file (`internal/scanner/profiles.go`)
and are overridable per repo via `semgrep_rulesets:`.

| Profile | semgrep packs | Intended use | Relative cost |
|---|---|---|---|
| `fast` | `p/ci` | tight PR gates, low noise | fastest |
| `standard` | `p/security-audit`, `p/owasp-top-ten`, `p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`, `p/csharp`, `p/ruby`, `p/php`, `p/kotlin`, `p/rust`, `p/scala`, `argus/curated` | default: broad multi-language audit | ~1 pack-set, moderate |
| `max` | `p/security-audit`, `p/owasp-top-ten`, `p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`, `p/csharp`, `p/ruby`, `p/php`, `p/kotlin`, `p/rust`, `p/scala`, `argus/curated`, `p/default`, `p/secrets`, `p/gosec`, `p/nodejsscan`, `p/react`, `p/command-injection`, `p/sql-injection`, `p/xss`, `p/jwt`, `p/insecure-transport`, `p/bandit`, `p/findsecbugs`, `p/security-code-scan`, `p/mobsfscan`, `p/phpcs-security-audit` | deep audit; recall over noise (triage handles FPs) | highest (adds p/default) |

## Language × weakness coverage

✅ caught under `standard` · ◐ caught only under `max` · · not caught by any profile

| Language | SQL Injection | Command Injection | Code Injection | XSS | Deserialization | Weak Crypto |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Python | ◐ | ✅ | · | · | · | ✅ |
| JavaScript | ✅ | ✅ | ✅ | ✅ | · | · |
| TypeScript | · | ✅ | · | · | · | ◐ |
| Go | ✅ | ✅ | · | · | · | ✅ |
| Java | ✅ | ◐ | · | · | ✅ | · |
| C# | ✅ | ◐ | · | · | · | · |
| Ruby | ✅ | · | ✅ | ✅ | ✅ | · |
| PHP | ✅ | ✅ | ✅ | ✅ | · | · |
| Kotlin | ✅ | ◐ | · | · | · | ✅ |
| Rust | · | · | · | · | · | · |
| Scala | ✅ | · | · | · | · | · |
| C | · | · | · | · | · | · |
| Swift | ✅ | ✅ | · | · | · | ✅ |

## Canaries (regression guard)

Each is asserted detected under `standard` by `TestPolyglotCoverage`:

- **Python**: OS command injection (CWE-78); Weak hash (MD5) (CWE-327); Path traversal (unsanitized join; argus/curated) (CWE-22)
- **JavaScript**: OS command injection (CWE-78); Cross-site scripting (CWE-79); Code injection (eval) (CWE-95); SQL injection (tainted query string; argus/curated) (CWE-89)
- **TypeScript**: OS command injection (CWE-78)
- **Go**: SQL injection (CWE-89); Weak hash (MD5) (CWE-328); OS command injection (shell string; argus/curated) (CWE-78)
- **Java**: SQL injection (CWE-89); Insecure deserialization (CWE-502)
- **C#**: SQL injection (CWE-89)
- **Ruby**: SQL injection (CWE-89); Cross-site scripting (CWE-79); Code injection (CWE-94); Insecure deserialization (CWE-502)
- **PHP**: OS command injection (CWE-78); Cross-site scripting (CWE-79); SQL injection (CWE-89); Code injection (CWE-94)
- **Kotlin**: Weak hash (MD5) (CWE-328); SQL injection (concatenated statement; argus/curated) (CWE-89)
- **Rust**: Reliance on untrusted input in a security decision (CWE-807); Use of inherently dangerous function (unsafe) (CWE-242)
- **Scala**: SQL injection (tainted interpolation) (CWE-89)
- **C**: Use of dangerous function (gets) (CWE-676)
- **Swift**: SQL injection (interpolated statement; argus/curated) (CWE-89); OS command injection (shell string; argus/curated) (CWE-78); Weak hash (MD5; argus/curated) (CWE-328); TLS validation disabled (argus/curated) (CWE-295); Hardcoded credential (argus/curated) (CWE-798)

## Known gaps (honest accounting)

None among the labeled classes: every weakness class shown is caught by at least one profile.

## Per-scanner review

- **semgrep (SAST)**: the breadth engine. `standard` runs a security-audit +
  OWASP-Top-Ten base plus a per-language pack for Python, JS, TS, Go, Java, C#,
  Ruby, PHP, Kotlin, **Rust** (`p/rust`), and **Scala** (`p/scala`), plus the
  **argus/curated** local ruleset (below). `max` adds `p/default`, `p/secrets`,
  `p/gosec`, and framework/category packs, which is what lifts Kotlin command
  injection, Python string-format SQLi, and TS weak-crypto into coverage
  (see ◐ cells).
- **argus/curated (local rules, detection-depth session).** The platform's own
  vetted rules (`internal/scanner/rules/curated.yaml`, embedded in the binary,
  never fetched) close gaps every registry pack provably missed: Python path
  traversal (CWE-22), Go shell command injection (CWE-78), JavaScript SQLi
  through a query string (CWE-89), Kotlin concatenated-statement SQLi (CWE-89)
  and predictable PRNG (CWE-330), PHP extract() (CWE-621) and rand() tokens
  (CWE-330), and all five Swift plants (SQLi, shell cmdi, MD5, disabled TLS
  validation, hardcoded credential). Every rule holds the same earn-your-slot
  bar as a pack, per rule, via TestProfileRecall, and each class has a
  safe-code PLANT-FP counterpart that must stay unflagged.
- **New languages, honest accounting.** **Rust** and **Scala** landed with
  dedicated packs (`p/rust`: untrusted-input CWE-807, unsafe-usage CWE-242;
  `p/scala`: tainted-sql-string CWE-89). **C** landed through
  `p/security-audit`'s own C rules (`insecure-use-gets-fn`, CWE-676); a
  dedicated `p/c` added nothing over it on the plants, so it was NOT added.
  **Swift** landed via argus/curated after `p/swift` caught none of its
  plants. **Elixir** did NOT land and cannot on the OSS engine: parsing
  Elixir is a Pro-only plugin (every elixir rule errors with MissingPlugin),
  so neither registry packs nor local rules can cover it; its fixture stays
  `PLANT-GAP` documentation and `.ex`/`.exs` stay "unsupported source" in
  skip accounting. Nothing is claimed that a scan did not prove.
- **gitleaks (SECRET)**: default ruleset (100+ credential patterns) is
  sufficient; secret material is redacted before it ever reaches a report or an
  LLM. No per-language tuning needed: secrets are language-agnostic.
  **Git history mode** (schema 2.0.0): when the scan target is a git
  repository, a second pass scans the commit history, so a credential that
  was committed and later deleted, but never rotated, still surfaces,
  labeled `meta.gitHistory` with the introducing commit. Shallow console
  workspaces (depth-1 clones) cover a single commit of history and say so
  (`meta.gitShallow`). Cost: roughly one extra gitleaks pass per scan.
- **trivy (SCA)**: vulnerability scanning of dependency manifests and lockfiles
  across ecosystems; `--profile` does not change SCA behavior (semgrep-only).
  Trivy's built-in misconfiguration scanner is the Phase 4 IaC teaser.

## Recall is proven, not asserted

Every planted vulnerability in `testdata/polyglot` carries an in-fixture
label `PLANT(<id>, min-profile=<fast|standard|max>, <CWE>)` naming the
minimum profile that must catch it. `TestProfileRecall` scans the fixtures
under every profile and asserts (a) each plant is caught by its minimum
profile and every superset, and (b) the caught-plant sets form the
inclusion chain fast ⊆ standard ⊆ max on plant IDs. A new pack lands in a
profile only with a plant proving it detects something the existing packs
miss; packs that add nothing are rejected (p/flask, p/django, p/brakeman
were evaluated and rejected on exactly that bar). Plants no profile catches
are labeled `PLANT-GAP` in the fixtures and listed under Known gaps.

## Skip accounting (what a scan did NOT look at)

Every saved run carries a `coverage` block (schema 2.0.0): files bucketed
as SAST-covered, IaC/config, secrets-only text, **unsupported source**
(recognizable code in a language no profile analyzes), **binary**, and
**oversize** (> 5 MB), plus git-repo/shallow facts, with sample paths.
The console renders it on the run detail. "No findings" in a tree full
of unscanned binaries is a different claim than "no findings" in a fully
analyzable tree; the accounting keeps the difference visible.

## Why breadth is safe here

Wide rulesets raise false-positive volume; that is the intended tradeoff. The
Phase 2 AI triage layer is the answer: every finding gets a local-LLM verdict and
a 0–10 risk score, so `standard`/`max` breadth stays actionable instead of
drowning the reviewer. Breadth + triage is the pairing the demo shows.

## Noise metric (correlation collapse, measured)

Wide profiles flag one weakness through several overlapping rules; the
same-tool collapse in `internal/correlate` merges those into one finding
(same tool + same file + overlapping range + shared CWE + different rule
IDs), unioning the evidence and recording absorbed rule IDs in
`meta.alsoRuleIds`. Collapse is NOT suppression: `TestProfileRecall`
asserts the plant catch set is identical before and after correlation at
every profile. Counts below are from the live scan that generated this file.

| Profile | Findings pre-correlate | Post-correlate | Duplicates collapsed | Findings per plant (post) | Safe-code false flags |
|---|---:|---:|---:|---:|---:|
| `standard` | 65 | 60 | 5 | 0.9 | 0/29 |
| `max` | 129 | 93 | 36 | 1.4 | 2/29 |

**Safe-code false flags** is the precision metric (locked decision 2): the
number of labeled `PLANT-FP` safe-code plants (parameterized SQL, constant
shell args, strong hashes, vendor example keys in tests) a profile wrongly
flagged for the class they resemble. It is MEASURED, not asserted, and not
suppressed: a deterministic rule never drops a finding for looking like an
FP; triage (the LLM oracle) and `--exclude-fp` are the only removal paths.


## Infrastructure-as-Code coverage

IaC misconfiguration scanning (category `IAC`) runs **checkov** and
**trivy-config** (the trivy misconfiguration pass, no extra binary) against
Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, and Helm charts.
IaC engines run whenever available; `--profile` governs semgrep only. Planted
misconfigurations under `testdata/iac/` are asserted detected by
`TestIaCCoverage`; the table below is generated from that live scan.

| Fixture | Planted misconfiguration | Canary rules | Detected by |
|---|---|---|---|
| Terraform (`terraform/main.tf`) | Public S3 bucket ACL | `CKV_AWS_20`, `AWS-0092` | checkov + trivy-config |
| Terraform (`terraform/main.tf`) | Security group open to 0.0.0.0/0 (SSH) | `CKV_AWS_24`, `AWS-0107` | checkov + trivy-config |
| Terraform (`terraform/main.tf`) | Unencrypted EBS volume | `CKV_AWS_3`, `AWS-0026` | checkov + trivy-config |
| Kubernetes (`k8s/deployment.yaml`) | Privileged container | `CKV_K8S_16`, `KSV-0017` | checkov + trivy-config |
| Kubernetes (`k8s/deployment.yaml`) | hostPath volume mounted | `KSV-0023`, `KSV-0121` | trivy-config |
| Kubernetes (`k8s/deployment.yaml`) | No resource limits | `CKV_K8S_13`, `CKV_K8S_11`, `KSV-0018`, `KSV-0011` | checkov + trivy-config |
| Dockerfile (`docker/Dockerfile`) | Mutable :latest base image | `CKV_DOCKER_7`, `DS-0001` | checkov + trivy-config |
| Dockerfile (`docker/Dockerfile`) | Container runs as root (no USER) | `CKV_DOCKER_3`, `DS-0002` | checkov + trivy-config |
| Dockerfile (`docker/Dockerfile`) | Secret in ENV | `DS-0031` | trivy-config |

Every IaC finding rolls up to **A05 Security Misconfiguration** in the OWASP
view and gets the same triage + 0–10 risk score as app-code findings.
Severity policy for the IaC engines is documented in `docs/findings-model.md`.
