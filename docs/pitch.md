# appsec (working name: **Bulwark**) — one page

**The whole codebase's security in one binary: broad detection, local-first AI
triage, and a console the whole team can read.**

## The problem

Security teams don't lack scanners — they drown in them. A typical org runs a
separate SAST tool, secret scanner, and dependency scanner, each with its own
config, output format, severity scale, and dashboard. The results don't
correlate, every tool floods the same reviewer with false positives, and the
one artifact leadership actually wants — "are we getting better or worse?" —
doesn't exist. Meanwhile the AI-native entrants solve the noise problem by
shipping your source code to their cloud, which is a non-starter for exactly the
regulated, security-conscious buyers who need it most.

## The wedge

`appsec` is an **orchestrator + local AI layer**, not another engine. It wraps
best-in-class OSS scanners (semgrep, gitleaks, trivy) behind one adapter
interface, normalizes everything into a single findings model, and adds the
value on top: dedup/correlation, a severity gate, **AI triage that runs on your
own hardware**, 0–10 risk scoring, and a web console. One `go build`, one
binary, drops into any CI image and any laptop.

## Why we win (the four differentiators)

1. **Breadth, proven not claimed.** SAST across nine languages out of the box,
   plus secrets and SCA, under curated `fast|standard|max` profiles. A labeled
   polyglot fixture set and a CI test assert the coverage; the matrix is
   generated from a live scan (`docs/coverage.md`), so the breadth claim is
   auditable, not marketing.
2. **Local-first AI triage — the privacy story.** The false-positive problem is
   real, and the answer is an LLM verdict + rationale on every finding. Ours
   defaults to a **local Ollama model**: nothing leaves the machine, secrets
   never reach a cloud, and the whole thing works air-gapped. Anthropic is an
   opt-in for teams that want it. This is the exact capability the cloud-only
   entrants can't offer the buyers who care most.
3. **One binary, zero lock-in.** No agent, no SaaS dependency, no per-seat
   dashboard to log into. The console is embedded and served locally. The
   adapter seam means any engine (including a future AI-native SAST pass) swaps
   in without touching the core.
4. **Apache-2.0, open by default.** Adoption starts bottom-up with the engineers
   who'll champion it, not top-down through procurement. Open source is the
   distribution strategy.

## The demo (10 minutes, all true)

Scan a nine-language vulnerable repo → breadth surfaces 30+ findings → local AI
triage confirms the real ones and **kills the false positives with a written
rationale**, on-device → open the console → walk leadership through risk
posture and trend, hand engineers a filterable explorer, show ops the
new-vs-resolved delta between runs. Breadth + local triage + one console, live.

## Who pays, and for what (later)

Open-source core stays free and is the funnel. Revenue is the **team layer**
the OSS tool deliberately omits: hosted history and multi-repo rollups,
SSO/RBAC and audit, policy-as-code gates across pipelines, ticketing and
notification integrations, and compliance-framework reporting (the roadmap's
Phase 4–5 compliance mapping productized). Land with the free scanner the
engineers already run; expand to the platform the CISO signs for.

## Status

Phases 1–3 shipped: the scan pipeline, local AI triage + risk scoring, and now
multi-language coverage + the console. Roadmap: IaC/cloud posture, compliance
mapping, DAST, threat modeling, IAST, and the commercial platform layer.
