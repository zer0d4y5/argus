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
