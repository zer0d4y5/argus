---
hide:
  - navigation
---

# Argus

**The all-seeing watch over your code and the cloud it runs in.**

Argus runs open-source scanners against your repositories and your cloud
accounts, merges everything into one deduplicated, risk-scored,
compliance-mapped findings model, triages each finding with an LLM on your own
machine, gates CI on severity, and serves a web console over your run history.
All from a single Go binary.

[Install :material-download:](install.md){ .md-button .md-button--primary }
[Getting started :material-rocket-launch:](getting-started.md){ .md-button }
[Source on GitHub :fontawesome-brands-github:](https://github.com/leaky-hub/argus){ .md-button }

<p align="center"><img src="diagrams/pipeline.svg" alt="Argus pipeline: scanners and cloud feed one findings model, enriched deterministically, then gating CI, exporting reports, and feeding the console" style="max-width:100%"></p>

## Why Argus exists

A good application-security program has mostly been a privilege of teams that
could afford one. The scanners that matter sit behind enterprise sales calls and
per-seat pricing; the ones that don't usually want your source uploaded to
someone else's cloud before they'll tell you what's wrong with it. If you're a
student, a two-person shop, or a team that can't send its code offsite, you've
been priced or policied out of the thing everyone calls table stakes.

That never sat right. Security is the baseline, not an upsell, and the people
with the least budget are often the ones getting breached. So Argus runs on a
stubborn premise: the core is free, and it works entirely on your machine. Your
code, your findings, and the local model that triages them stay put; nothing
phones home, nothing gets uploaded, and you start without an account. The pieces
a bigger org needs later (SSO, roles, an audit trail) are layers you switch on,
never a paywall in front of the scanner.

Free and private aren't the compromise. They're the whole idea.

## What it does

<div class="grid cards" markdown>

- :material-magnify-scan: **Everything, one model**

    SAST across eleven languages, secrets, dependencies (SCA), IaC
    misconfiguration, and cloud posture (AWS, Azure, GCP) all flow through the
    same banded severity, risk signals, and compliance mapping.

- :material-shield-lock: **Local-first AI triage**

    An LLM reviews each finding and records a verdict plus a rationale, on a
    local Ollama model by default. Nothing leaves the machine; it works
    air-gapped. Anthropic is an opt-in.

- :material-clipboard-check: **Findings become audit evidence**

    Every finding maps, deterministically, to the ASVS / PCI DSS / CIS controls
    it violates. `argus comply` turns any scan into a per-framework gap report.

- :material-view-dashboard: **A console the whole team reads**

    Risk posture and trend for leadership, a filterable explorer with per-finding
    triage rationale for engineers, tickets and STRIDE threat models over your
    architecture.

</div>

## In one command

```bash
argus scan ./repo --profile standard --triage --save
argus serve    # http://127.0.0.1:8080
```

The first line scans, normalizes and dedups, triages locally, risk-scores every
finding 0 to 10, maps each to compliance controls, writes SARIF / Markdown /
JSON, and exits non-zero if anything hits your severity gate. The second opens
the console over your saved runs.

Ready? [Install Argus](install.md) or walk through a [first scan](getting-started.md).
