# Roadmap

Long-term goal: the best OSS AppSec tool in existence — one utility covering
the whole SSDLC (SAST, SCA, secrets, IaC/cloud posture, DAST, IAST, threat
modeling, compliance assessment, offensive checks) that drops cleanly into any
cloud and any CI/CD pipeline, shifting security as far left as possible while
still catching runtime issues.

- **Phase 1 (shipped):** SAST + secrets + SCA vertical slice — CLI + GitHub
  Action, unified findings model, SARIF/Markdown/JSON output, dedup/correlation,
  severity gate. ✅ = the acceptance criteria in the Phase 1 handoff; see
  `docs/architecture.md` and `docs/findings-model.md`.
- **Phase 2 — AI triage & risk scoring (core shipped):** LLM-backed
  false-positive triage (provider-agnostic: local Ollama default + Anthropic
  opt-in), prompt-injection-hardened per-finding review with bounded source
  snippets, and 0–10 risk scoring (deterministic baseline + bounded LLM
  adjustment, `docs/risk-scoring.md`). ✅ met on the labeled eval set
  (`testdata/triage-eval/`, `go test -run TestTriageEval`): FP-detection
  precision 1.00 / recall 1.00, zero true positives suppressed, every finding
  scored in every run. **Remaining stretch:** natural-language remediation
  and auto-generated fix suggestions/patches; severity re-ranking with
  reachability context lands with IAST (Phase 7).
- **Phase 3 — Eagle-eye coverage & web console (shipped, this cycle):**
  curated `fast|standard|max` scan profiles running per-language semgrep packs
  across nine languages; a labeled polyglot fixture set with a coverage test
  and a generated language × weakness matrix (`docs/coverage.md`); file-based
  run history (`scan --save`); and the first web console (`argus serve`) with
  Overview, Findings, and Runs tabs, served from the single embedded binary,
  rendering hostile finding data inert.
  ✅ = every labeled plant detected under `standard`; the console shows a real
  cross-run trend, filterable findings with triage rationale, and new-vs-
  resolved deltas; an XSS fixture renders as text; `go build` alone produces
  the whole working binary. **Note:** the OWASP Top 10 rollup is computed
  report/UI-side from CWEs; the `complianceControls` model slot stays reserved
  for Phase 5.
- **Phase 4 — IaC & cloud posture (shipped, this cycle):** two IaC engines
  behind the same dumb-adapter seam — **checkov** (Terraform, CloudFormation,
  Kubernetes, Dockerfile, Helm, ARM, Bicep, Serverless) and **trivy-config**
  (trivy's misconfiguration pass: IaC coverage with zero new binaries) — both
  emitting `IAC` findings that dedup, triage, risk-score, and gate like
  everything else. Severity policy for both engines is documented in
  `docs/findings-model.md` (OSS checkov emits no severities → medium, never
  info); checkov CIS/benchmark IDs are captured into `meta`. IaC findings roll
  up to **A05 Security Misconfiguration** in the OWASP view and render
  first-class in the console (category badges + Overview breakdown).
  ✅ = every planted misconfiguration in the labeled `testdata/iac/` fixtures
  (public S3 ACL, open security group, unencrypted EBS, privileged container,
  hostPath mount, missing limits, `:latest` base, root container, secret in
  ENV) detected via `TestIaCCoverage`, with both engines proven per format;
  the generated `docs/coverage.md` gained an IaC section. Also fixed in this
  cycle: the Phase 2 snippet-path bug (snippet reads now resolve
  scanner-reported CWD-relative/absolute paths correctly while staying
  confined to the scan root). **Remaining for a later beat:** KICS as an
  optional third engine; live cloud-account posture scanning (AWS/GCP/Azure
  APIs) — file-based IaC only for now.
- **Phase 5 — Compliance mapping & assessment (shipped, this cycle):** a
  deterministic, hand-curated, version-pinned mapping engine
  (`internal/compliance`, no LLM in the path) that maps every finding to the
  framework controls it violates — **OWASP ASVS 4.0.3** (CWE + category
  rules), **PCI DSS 4.0** (CWE + category rules, IaC → secure-configuration),
  and CIS-derived IaC coverage at section granularity (**CIS AWS Foundations
  v1.5.0, CIS Docker v1.6.0, CIS Kubernetes v1.8.0** via rule-ID families).
  The always-on pipeline stage writes `complianceControls`
  (`"<FRAMEWORK>:<control-id>"`, schema **1.2.0**); `argus comply` produces
  the auditor-shaped gap report (Markdown + JSON) with violated /
  no-violations-detected / not-assessable buckets that never overclaim
  (unmapped findings are listed, never dropped; totals reconcile, tested);
  the GRC Overview gained a per-framework compliance panel and finding
  details show control chips. Frameworks are data-only additions
  (`internal/compliance/data/*.json`) — see `docs/compliance.md`.
  ✅ = a findings run yields a per-framework control coverage report; every
  planted fixture vuln class lands under the right ASVS/PCI controls.
  **Remaining for a later beat:** SOC 2 / NIST 800-53 / ISO 27001 data files;
  evidence-collection workflow.
- **Phase 6 — DAST:** integrate OWASP ZAP and/or Nuclei for authenticated
  dynamic scanning of a running target; wire results into the same model
  (the `location.url` slot exists). ✅ = DAST run against a deliberately-vuln
  app (e.g. Juice Shop) produces correlated findings.
- **Phase 7 — Threat modeling (shipped):** architecture-aware STRIDE threat
  models. A curated, version-pinned STRIDE library enumerates threats per
  component tech deterministically; `internal/iacdetect` bootstraps a baseline
  from repo IaC (Terraform, CloudFormation, Kubernetes, Bicep, ARM, Pulumi,
  Helm); a local LLM optionally suggests components and threats a human
  confirms as `assisted`; threats link to real findings, controls, and
  mitigations; a full-width canvas editor maps the architecture — add and
  arrange components, assets, external entities, and zone-typed trust
  boundaries (DMZ/VPC/subnet/…), resize boundaries, and draw data flows. ✅ = a
  model generated from IaC with enumerated STRIDE, linked to
  findings, exported to CSV/JSON. Paired with **ticketing** — a work layer over
  findings with a timeline, severity rollup, aging, and opt-in GitHub Issues
  sync. Both live in `internal/store` (embedded SQLite) and never move the gate.
- **Phase 8 — IAST & runtime:** instrumentation/agent hooks for runtime
  vulnerability detection; correlate runtime evidence back to SAST findings
  (reachability truth).
- **Phase 9 — Server/platform:** hosted API server, multi-repo dashboards,
  shared historical trends, triage workflow, SSO/RBAC, ticketing integrations,
  and policy-as-code gates across pipelines — the commercial team layer.
- **Cross-cutting:** offensive/pentest checks (Nuclei templates,
  exploitability probes), SBOM generation (syft/CycloneDX), and first-class
  support for GitLab CI, Jenkins, CircleCI, Azure DevOps, and pre-commit hooks
  alongside the GitHub Action.
