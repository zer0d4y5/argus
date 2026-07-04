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
| `max` | `p/security-audit`, `p/owasp-top-ten`, `p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`, `p/csharp`, `p/ruby`, `p/php`, `p/kotlin`, `p/default`, `p/secrets`, `p/gosec`, `p/nodejsscan`, `p/react`, `p/command-injection`, `p/sql-injection`, `p/xss`, `p/jwt`, `p/insecure-transport` | deep audit; recall over noise (triage handles FPs) | highest (adds p/default) |

## Language × weakness coverage

✅ caught under `standard` · ◐ caught only under `max` · · not caught by any profile

| Language | SQL Injection | Command Injection | Code Injection | XSS | Deserialization | Weak Crypto |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Python | ◐ | ✅ | · | · | · | ✅ |
| JavaScript | · | ✅ | ✅ | ✅ | · | · |
| TypeScript | · | ✅ | · | · | · | ◐ |
| Go | ✅ | · | · | · | · | ✅ |
| Java | ✅ | · | · | · | ✅ | · |
| C# | ✅ | · | · | · | · | · |
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
- **trivy (SCA)** — vulnerability scanning of dependency manifests and lockfiles
  across ecosystems; `--profile` does not change SCA behavior (semgrep-only).
  Trivy's built-in misconfiguration scanner is the Phase 4 IaC teaser.

## Why breadth is safe here

Wide rulesets raise false-positive volume — that is the intended tradeoff. The
Phase 2 AI triage layer is the answer: every finding gets a local-LLM verdict and
a 0–10 risk score, so `standard`/`max` breadth stays actionable instead of
drowning the reviewer. Breadth + triage is the pairing the demo shows.
