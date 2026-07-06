<h1 align="center">
  <img src="docs/screenshots/logo.svg" alt="" width="42" height="42" valign="middle" />
  Bulwark
</h1>

<p align="center"><strong>AppSec + cloud posture, one wall.</strong></p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue" />
  <img alt="Go" src="https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white" />
  <img alt="Schema" src="https://img.shields.io/badge/findings--model-2.1.0-6e56cf" />
  <img alt="Local-first" src="https://img.shields.io/badge/local--first-no%20cloud%20required-16a34a" />
</p>

**One security tool for the whole surface — code AND the cloud it runs in.**
Bulwark runs the best open-source scanners against your repositories and your
cloud accounts, merges everything into one deduplicated, risk-scored,
compliance-mapped findings model, AI-triages each finding on your own machine,
gates CI on severity, and serves a three-persona web console over your run
history — all from one Go binary. A defensive wall built from many stones:
independent scanners mortared into one structure.

**Everything, one model.** SAST across **eleven languages** (Python,
JavaScript, TypeScript, Go, Java, C#, Ruby, PHP, Kotlin, Rust, Scala; C via
security-audit), secrets, dependencies (SCA), **IaC misconfiguration**
(Terraform, CloudFormation, Kubernetes, Dockerfile, Helm), and **cloud
security posture** (prowler — AWS today) all flow through the same banded
severity, risk signals, and compliance mapping. DAST is on the
[roadmap](docs/roadmap.md).

**Findings become audit evidence.** Every finding is mapped — deterministically,
no LLM — to the framework controls it violates (**OWASP ASVS 4.0**,
**PCI DSS 4.0**, and **CIS** AWS/Docker/Kubernetes benchmarks), and
`bulwark comply` turns any scan into a per-framework gap report a GRC lead can
hand to an auditor: controls violated with evidence, controls with no
violations detected, and an explicit "not assessable by static scanning"
bucket so the report never overclaims ([docs/compliance.md](docs/compliance.md)).

```
bulwark scan ./repo --profile standard --triage --save
  → runs in parallel:  semgrep (SAST) · gitleaks (secrets) · trivy (SCA) · checkov + trivy-config (IaC)
  → normalizes everything into one findings model
  → dedups/correlates overlapping findings
  → AI triage (local Ollama): LLM verdicts true/false-positive per finding
  → risk-scores every finding 0–10 (heuristic baseline ± bounded LLM adjustment)
  → maps every finding to ASVS / PCI DSS / CIS controls (deterministic, no LLM)
  → writes SARIF 2.1.0 / Markdown / JSON, saves the run for the console
  → exits non-zero when findings hit your severity gate

bulwark comply  → per-framework compliance gap report: violated / clean / not assessable
bulwark serve   → local web console: Overview (GRC) · Findings (AppSec) · Runs (SecOps)
                 + with users configured: login, scan launching, admin, audit
bulwark user    → console users: add | list | passwd | remove (bootstrap the first admin)
bulwark target  → registered scan targets the console may launch against
```

## The console

`bulwark serve` reads the runs you save and renders three persona views. Finding
data (titles, paths, LLM rationales) is treated as hostile and rendered inert —
escaping only, no HTML injection, strict CSP, binds `127.0.0.1`.

Out of the box the console is a read-only viewer with no login. Create users
(`bulwark user add <name> --role admin`) and it becomes an **operational
console**: login + roles (viewer/operator/admin), scan launching against
registered targets (`bulwark target add`) through a strictly serial job queue,
user management, and an append-only audit log. Threat model and design:
[docs/console-ops.md](docs/console-ops.md).

| Overview — GRC / exec | Findings — AppSec | Runs — SecOps |
|---|---|---|
| ![Overview](docs/screenshots/overview.png) | ![Findings](docs/screenshots/findings.png) | ![Runs](docs/screenshots/runs.png) |

Risk posture, severity/OWASP rollups, per-framework compliance posture, and a
cross-run trend for leadership; a filterable explorer with per-finding triage
rationale and violated-control chips for engineers; new-vs-resolved deltas and
gate outcomes for operations.

## Quickstart (90 seconds)

```bash
# Prereqs: Go 1.22+, plus whichever scanners you want on PATH:
#   pipx install semgrep     (or: pip install semgrep)
#   brew install gitleaks trivy   # trivy covers SCA *and* IaC misconfigs
#   pipx install checkov          # optional: the broad IaC engine
go build -o bulwark ./cmd/bulwark        # embeds the console; no Node needed to run

# Scan with the default `standard` multi-language profile, triage locally,
# and save the run for the console:
./bulwark scan . --triage --save

# Open the console over your saved runs:
./bulwark serve                          # http://127.0.0.1:8080

# Other common invocations:
./bulwark scan . --profile fast          # tight, low-noise PR gate (semgrep p/ci)
./bulwark scan . --profile max           # deepest recall; triage handles the FP volume
./bulwark scan . --format sarif -o results.sarif   # GitHub code scanning
./bulwark scan . --fail-severity high    # fail CI on high or critical
./bulwark scan . --triage --exclude-fp   # drop LLM-marked false positives (explicit)
./bulwark comply .                       # compliance gap report (fresh scan, Markdown)
./bulwark comply . --latest -f json      # assess the last saved run instead
```

## Cloud security posture (prowler)

Point the platform at an AWS account and get a posture assessment through the
**same** pipeline as code — unified findings (category `CLOUD`), banded
severity, deterministic risk signals, and CIS-AWS compliance mapping, skimmable
in the console.

```bash
# Prereq: prowler on PATH (`pipx install prowler`) and a read-only profile.
./bulwark cloud-scan --provider aws --profile security-audit
./bulwark cloud-scan --provider aws --profile security-audit --regions us-east-1,us-west-2 --save
```

**Credentials are referenced, never collected.** `--profile` names a profile
from your local cloud config (`~/.aws`); the platform passes only that NAME to
prowler as `AWS_PROFILE` and never sees, stores, or logs a key. Least-privilege
setup — create a read-only security-audit principal and point `--profile` at it:

```bash
# AWS: attach the two AWS-managed read-only policies to a dedicated principal.
aws iam create-user --user-name bulwark-audit
aws iam attach-user-policy --user-name bulwark-audit \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-user-policy --user-name bulwark-audit \
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
# Put its keys in a named profile in ~/.aws/credentials, e.g. [security-audit],
# then reference that NAME. The platform runs with exactly what that profile
# can do — least privilege is your control, honesty about it is ours.
```

Azure (`Reader`) and GCP (`Viewer`) are the same shape and are the documented
next beat. In the console, an admin registers a cloud target by picking a
discovered profile name (never a key); cloud runs appear in the aggregated Runs
tab with a resource-aware finding drawer and an optional on-demand,
never-persisted **AI posture summary**.

Missing scanners are skipped with a note — the CLI degrades gracefully and
runs whatever the environment provides. The same applies to triage: no LLM
reachable means the scan simply runs without verdicts.

## Scan profiles & coverage

`--profile fast|standard|max` (config: `profile:`) selects the curated semgrep
ruleset. `standard` is the default — a security-audit + OWASP base plus a
per-language pack for all nine languages. Coverage is **proven, not claimed**: a
labeled fixture per language (`testdata/polyglot/`) and a network-dependent test
assert every canary is detected under `standard`, and
[docs/coverage.md](docs/coverage.md) is a generated language × weakness matrix.
Breadth raises false-positive volume on purpose — local AI triage is the answer.

The same bar applies to IaC: labeled misconfigured Terraform / Kubernetes /
Dockerfile fixtures (`testdata/iac/`) with a coverage test asserting every
planted misconfiguration is detected. IaC engines run whenever they are on
PATH (`--profile` tunes semgrep only); every IaC finding lands in the same
model — triaged, risk-scored, gated, and rolled up to OWASP A05 — and wears a
category badge in the console.

## Compliance mapping & gap assessment

Every scan maps every finding to the security controls it violates —
hand-curated, version-pinned data (`internal/compliance/data/`), zero LLM
involvement, unmapped-is-visible, totals reconcile. `bulwark comply` renders the
per-framework gap assessment (Markdown or JSON): **violated** controls with
evidence pointers, **no violations detected** (deliberately not "compliant"),
and an explicit **not assessable by static scanning** bucket. Adding a
framework (SOC 2, NIST 800-53, ISO 27001 are next) is a data-only change —
philosophy, honest-scope statement, and a how-to in
[docs/compliance.md](docs/compliance.md).

## AI triage & risk scoring

Every finding always gets a deterministic **risk score** (0–10; formula in
[docs/risk-scoring.md](docs/risk-scoring.md)), and since schema 2.0.0 its
**severity is banded from the deterministic part of that score** (canonical
bands in the same doc) — so "high" means the same thing on every finding from
every tool, context signals included, LLM excluded. The tool's own opinion is
preserved as `toolSeverity`. With `--triage` (or
`triage.enabled: true`), an LLM additionally reviews each finding with a
bounded source snippet and records a verdict — `true-positive`,
`false-positive`, or `uncertain` — plus a rationale, which reporters surface
alongside the score. Verdicts are additive metadata: severity and the CI gate
never move on LLM output, and `--exclude-fp` is the only (explicit, counted)
way a verdict removes a finding from the report and gate.

Providers: **Ollama** (default, local) and **Anthropic** (set
`ANTHROPIC_API_KEY`; keys are env-only, never config). Scanned code is treated
as hostile input: snippets enter prompts only inside per-request random
boundary markers, model output is schema-validated, and SECRET findings never
leave the machine unless `allow_secret_cloud: true` is set.

## Configuration — `appsec.yml`

Looked up in the working directory (override with `--config`); flags beat file
values.

```yaml
scanners: []            # subset to run, e.g. [semgrep, gitleaks]; empty = all
profile: standard       # fast | standard | max — the curated semgrep ruleset
semgrep_rulesets: []    # optional: override the profile with your own pack list
fail_severity: high     # critical | high | medium | low | info | none
format: markdown        # sarif | markdown | json
ignore_paths:           # glob patterns; `dir/**` ignores a subtree
  - testdata/**
  - vendor
ignore_rules:           # exact rule IDs to suppress
  - generic-api-key
timeout: 600            # per-scanner timeout, seconds
triage:                 # AI triage (Phase 2) — off unless enabled here or via --triage
  enabled: false
  provider: ollama      # ollama | anthropic (API key via ANTHROPIC_API_KEY env)
  model: qwen3.6:35b-a3b
  endpoint: http://localhost:11434
  timeout: 90           # per-LLM-request seconds
  concurrency: 4
  max_findings: 200     # triage the N most severe findings; 0 = all
  exclude_fp: false     # opt-in: drop LLM-marked false positives from report + gate
  allow_secret_cloud: false  # opt-in: allow SECRET findings to non-local providers
```

Suppressed findings are counted on stderr — suppression is never silent.

## GitHub Action

`.github/workflows/appsec.yml` runs on every PR: it scans, uploads SARIF to
GitHub code scanning, and fails the build on high+ findings. Copy it into any
repo and adjust the gate.

## Output formats

- **SARIF 2.1.0** — validates against the official schema; ingested by GitHub
  code scanning (severity mapped to `security-severity` so alerts bucket
  correctly; stable fingerprints so alerts track across commits).
- **Markdown** — human-readable summary + findings grouped by severity.
- **JSON** — the full unified findings model (`docs/findings-model.md`),
  including per-tool raw payload passthrough.

## Docs

- [Pitch](docs/pitch.md) — the one-page why: problem, wedge, differentiators
- [Coverage](docs/coverage.md) — generated language × weakness matrix + profiles
- [Architecture](docs/architecture.md) — orchestrator design, package layout, design rules
- [Findings model](docs/findings-model.md) — the unified schema (versioned)
- [Risk scoring](docs/risk-scoring.md) — the 0–10 formula and the bounded LLM adjustment
- [Compliance](docs/compliance.md) — frameworks, mapping philosophy, adding a framework
- [Roadmap](docs/roadmap.md) — Phases 6–9: DAST, threat modeling, IAST, platform

## Development

```bash
go build ./... && go test ./...     # `go build` alone works — the UI bundle is committed
make ui                              # rebuild the React console into ui/dist (Node 22)
make coverage                        # regenerate docs/coverage.md from a live scan
./demo/demo.sh                       # the full 10-minute investor story, end to end
./bulwark scan testdata/fixture       # deliberately vulnerable sample; expect findings
```

Licensed under Apache-2.0.
