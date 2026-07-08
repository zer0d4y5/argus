# Getting started

This walks through a first scan, reading the results, the compliance report, and
the console. It assumes you have `argus` on your `PATH` (see [Install](install.md)).

## Your first scan

Point Argus at a repository. The `standard` profile is a good default: a
security-audit plus OWASP base with a per-language pack.

```bash
argus scan ./your-repo --profile standard
```

Argus runs the scanners you have on `PATH` in parallel, normalizes their output
into one findings model, dedups overlapping findings, risk-scores each 0 to 10,
maps each to the compliance controls it violates, and prints a summary. It exits
non-zero if any finding hits your severity gate, so it drops straight into CI.

Common variations:

```bash
argus scan . --profile fast              # tight, low-noise PR gate
argus scan . --profile max               # deepest recall; triage handles the FP volume
argus scan . --fail-severity high        # fail CI on high or critical
argus scan . --format sarif -o out.sarif # for GitHub code scanning
```

## Gate only on new findings (baseline)

A repository with a backlog of known issues should still be able to fail CI on
anything *newly* introduced without drowning in pre-existing noise. Record a
baseline once, then gate against it:

```bash
argus scan . --write-baseline .argus-baseline.json   # capture today's findings, no gate
argus scan . --baseline .argus-baseline.json --fail-severity high
```

The second command reports every finding but only lets **new** ones (those whose
stable fingerprint is not in the baseline) fail the gate; known findings are
counted and shown (`N new, M known`) but never block the build. The baseline is
a plain JSON list of fingerprints, safe to commit. It composes with dispositions
and `--strict-gate`, and pairs naturally with a PR workflow: baseline `main`,
gate the PR on what it adds.

## Add local AI triage

Breadth raises false-positive volume on purpose. The answer is an LLM verdict on
each finding, and Argus runs it locally by default so nothing leaves your
machine.

```bash
argus scan . --triage                    # verdict + rationale per finding
argus scan . --triage --exclude-fp       # also drop LLM-marked false positives (explicit)
```

Verdicts are additive metadata. Severity and the CI gate never move on the LLM's
opinion; `--exclude-fp` is the one explicit, counted way a verdict removes a
finding.

## Save a run and open the console

Save a run, then serve the console over your history:

```bash
argus scan . --triage --save
argus serve                              # http://127.0.0.1:8080
```

The console binds to `127.0.0.1` and treats all finding data as hostile (escaped,
never injected). Out of the box it is a read-only viewer with no login. Add users
to turn it into an operational console with roles, scan launching, and an audit
log:

```bash
argus user add alice --role admin
```

See [Console and pillars](console-ops.md) for the full authz model, ticketing,
and threat modeling.

## Compliance report

Any scan can be reframed as an auditor-shaped gap report:

```bash
argus comply .                           # Markdown gap report from a fresh scan
argus comply . --latest -f json          # assess the last saved run instead
```

It lists controls violated with evidence, controls with no violations detected,
and an explicit "not assessable by static scanning" bucket, so it never
overclaims. More in [Compliance](compliance.md).

## Cloud posture

Point Argus at a cloud account and get a posture assessment through the same
pipeline as code: unified findings, banded severity, and compliance mapping.

```bash
argus cloud-scan --provider aws --profile security-audit
argus cloud-scan --provider aws --profile security-audit --regions us-east-1 --save
```

Credentials are referenced, never collected. `--profile` names a profile from
your local cloud config; Argus passes only that name to prowler and never sees,
stores, or logs a key. Azure (by subscription id) and GCP (by project id) work
the same way, with auth supplied by the environment prowler inherits.

From the console, an admin can also **apply a curated, reversible fix** for a
posture finding, dry-run first, across all three providers. Every command comes
from a vetted catalog and is grammar-checked against the finding; the model
never authors a command that runs.

## Extend the detection

Argus ships curated detection, but you are not stuck with it.

- **Enable a rule pack.** In the console's Admin → Detection rules tab, browse a
  catalog of vetted semgrep packs grouped by language, framework, cloud stack,
  and weakness class, and enable the ones for your stack with one click. Packs
  already in your profile are marked, so you can tell what is new.

- **Bring your own semgrep rules.** Point `semgrep_rulesets:` in `appsec.yml` at
  a registry pack or a local rule file or directory. A leading `"+"` entry adds
  your rules to the profile packs; without it they replace them. In the console
  an admin can edit the list and validate it, and a malformed rule is a clear
  error before it ever reaches a scan.

- **Let the local model draft one.** In the console, describe a detection in
  plain language and a local LLM drafts a semgrep rule. You validate it, test it
  against a pasted example (green if it matches, red if it does not), edit it
  freely, and save it as a custom rule. A deterministic safety check rejects
  catastrophic-backtracking and match-everything rules, and nothing is saved or
  runs until you confirm.

See [Console and pillars](console-ops.md) for the full rule-authoring workflow.

## Configuration

Argus reads `appsec.yml` from the working directory (override with `--config`);
command-line flags beat file values. A minimal example:

```yaml
profile: standard          # fast | standard | max
fail_severity: high        # critical | high | medium | low | info | none
triage:
  enabled: true
  provider: ollama         # ollama (local) | anthropic (opt-in, key via env)
```

### Opengrep instead of Semgrep

The SAST engine is Semgrep by default. If you prefer [Opengrep](https://github.com/opengrep/opengrep),
the community fork created after Semgrep moved inter-file analysis to its paid
tier, it is a drop-in: same CLI, same rule format. Install it and Argus uses it
automatically when Semgrep is absent, or set `ARGUS_SEMGREP_BINARY=opengrep` to
prefer it. Findings are still attributed to "semgrep" in the model.

### Air-gapped scanning

Argus is local-first, but the `standard` and `max` profiles resolve semgrep
*registry* packs over the network on first use. For a truly air-gapped run, cache
them once while online, then scan offline:

```bash
argus rules sync --profile standard        # fetch the profile's packs into a local cache
argus scan . --offline --profile standard  # use the cache + embedded rules; never touch the network
```

`--offline` (or `offline: true` in `argus.yml`) makes a scan use only local rule
sources: the curated rules embedded in the binary, the packs `argus rules sync`
cached, and any local BYO rules. Registry packs missing from the cache are
skipped with a warning rather than fetched, and semgrep's own update ping is
disabled. Even with an empty cache a scan still runs the embedded curated rules,
so it is air-gapped from the very first run. The cache directory
(`offline.cache_dir`, default `<user-cache>/argus/rules`) can be copied to a
disconnected host.

## In CI

The repo ships a GitHub Actions workflow that scans on every pull request,
uploads SARIF to code scanning, and fails on high-or-critical findings. Copy it
into any repo and adjust the gate.

## Where to next

- [Console and pillars](console-ops.md): roles, audit, tickets, threat models
- [Risk scoring](risk-scoring.md): the 0 to 10 formula and the bounded LLM adjustment
- [Findings model](findings-model.md): the unified schema
- [Coverage](coverage.md): the language and weakness matrix
- [Architecture](architecture.md): how the pieces fit together
