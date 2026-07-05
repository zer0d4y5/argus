# Coverage — the eagle-eye matrix

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
| `standard` | `p/security-audit`, `p/owasp-top-ten`, `p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`, `p/csharp`, `p/ruby`, `p/php`, `p/kotlin` | default — broad multi-language audit | ~1 pack-set, moderate |
| `max` | `p/security-audit`, `p/owasp-top-ten`, `p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`, `p/csharp`, `p/ruby`, `p/php`, `p/kotlin`, `p/default`, `p/secrets`, `p/gosec`, `p/nodejsscan`, `p/react`, `p/command-injection`, `p/sql-injection`, `p/xss`, `p/jwt`, `p/insecure-transport`, `p/bandit`, `p/findsecbugs`, `p/security-code-scan`, `p/mobsfscan`, `p/phpcs-security-audit` | deep audit; recall over noise (triage handles FPs) | highest (adds p/default) |

## Language × weakness coverage

✅ caught under `standard` · ◐ caught only under `max` · · not caught by any profile

| Language | SQL Injection | Command Injection | Code Injection | XSS | Deserialization | Weak Crypto |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Python | ◐ | ✅ | · | · | · | ✅ |
| JavaScript | · | ✅ | ✅ | ✅ | · | · |
| TypeScript | · | ✅ | · | · | · | ◐ |
| Go | ✅ | · | · | · | · | ✅ |
| Java | ✅ | ◐ | · | · | ✅ | · |
| C# | ✅ | ◐ | · | · | · | · |
| Ruby | ✅ | · | ✅ | ✅ | ✅ | · |
| PHP | ✅ | ✅ | ✅ | ✅ | · | · |
| Kotlin | · | ◐ | · | · | · | ✅ |

## Canaries (regression guard)

Each is asserted detected under `standard` by `TestPolyglotCoverage`:

- **Python** — OS command injection (CWE-78); Weak hash (MD5) (CWE-327)
- **JavaScript** — OS command injection (CWE-78); Cross-site scripting (CWE-79); Code injection (eval) (CWE-95)
- **TypeScript** — OS command injection (CWE-78)
- **Go** — SQL injection (CWE-89); Weak hash (MD5) (CWE-328)
- **Java** — SQL injection (CWE-89); Insecure deserialization (CWE-502)
- **C#** — SQL injection (CWE-89)
- **Ruby** — SQL injection (CWE-89); Cross-site scripting (CWE-79); Code injection (CWE-94); Insecure deserialization (CWE-502)
- **PHP** — OS command injection (CWE-78); Cross-site scripting (CWE-79); SQL injection (CWE-89); Code injection (CWE-94)
- **Kotlin** — Weak hash (MD5) (CWE-328)

## Known gaps (honest accounting)

None among the labeled classes — every weakness class shown is caught by at least one profile.

## Per-scanner review

- **semgrep (SAST)** — the breadth engine. `standard` runs a security-audit +
  OWASP-Top-Ten base plus a per-language pack for Python, JS, TS, Go, Java, C#,
  Ruby, PHP, and Kotlin. `max` adds `p/default`, `p/secrets`, `p/gosec`, and
  framework/category packs, which is what lifts Kotlin command injection,
  Python string-format SQLi, and TS weak-crypto into coverage (see ◐ cells).
- **gitleaks (SECRET)** — default ruleset (100+ credential patterns) is
  sufficient; secret material is redacted before it ever reaches a report or an
  LLM. No per-language tuning needed — secrets are language-agnostic.
  **Git history mode** (schema 2.0.0): when the scan target is a git
  repository, a second pass scans the commit history, so a credential that
  was committed and later deleted — but never rotated — still surfaces,
  labeled `meta.gitHistory` with the introducing commit. Shallow console
  workspaces (depth-1 clones) cover a single commit of history and say so
  (`meta.gitShallow`). Cost: roughly one extra gitleaks pass per scan.
- **trivy (SCA)** — vulnerability scanning of dependency manifests and lockfiles
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
**oversize** (> 5 MB), plus git-repo/shallow facts — with sample paths.
The console renders it on the run detail. "No findings" in a tree full
of unscanned binaries is a different claim than "no findings" in a fully
analyzable tree; the accounting keeps the difference visible.

## Why breadth is safe here

Wide rulesets raise false-positive volume — that is the intended tradeoff. The
Phase 2 AI triage layer is the answer: every finding gets a local-LLM verdict and
a 0–10 risk score, so `standard`/`max` breadth stays actionable instead of
drowning the reviewer. Breadth + triage is the pairing the demo shows.

## Infrastructure-as-Code coverage

IaC misconfiguration scanning (category `IAC`) runs **checkov** and
**trivy-config** (the trivy misconfiguration pass — no extra binary) against
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
