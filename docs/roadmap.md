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
- **Phase 2 — AI triage & risk scoring:** LLM-backed false-positive triage,
  severity re-ranking with exploitability/reachability context,
  natural-language remediation, auto-generated fix suggestions/patches.
  Provider-agnostic interface (the `internal/triage` seam is already wired).
  ✅ = triage measurably cuts false positives on a labeled fixture set and
  every finding gets a risk score.
- **Phase 3 — IaC & cloud posture:** add Checkov/KICS (Terraform/CFN/K8s/
  Dockerfile) and cloud-config assessment (CIS benchmarks, cloud best-practice
  standards). ✅ = clean scans of sample Terraform + a K8s manifest, mapped
  into the model.
- **Phase 4 — Compliance mapping & assessment:** map findings/controls to
  frameworks (OWASP ASVS/Top 10, NIST 800-53, CIS, SOC 2, PCI-DSS, ISO 27001)
  and produce gap-assessment reports (the `complianceControls` slot exists in
  the model). ✅ = a findings run yields a per-framework control coverage
  report.
- **Phase 5 — DAST:** integrate OWASP ZAP and/or Nuclei for authenticated
  dynamic scanning of a running target; wire results into the same model
  (the `location.url` slot exists). ✅ = DAST run against a deliberately-vuln
  app (e.g. Juice Shop) produces correlated findings.
- **Phase 6 — Threat modeling:** code/architecture-aware threat model
  generation (data-flow + STRIDE), ideally AI-assisted from repo + IaC,
  producing a reviewable model and linked findings.
- **Phase 7 — IAST & runtime:** instrumentation/agent hooks for runtime
  vulnerability detection; correlate runtime evidence back to SAST findings
  (reachability truth).
- **Phase 8 — Server/platform:** optional API server, dashboard, historical
  trends, triage workflow, ticketing integrations, and policy-as-code gates
  across pipelines.
- **Cross-cutting:** offensive/pentest checks (Nuclei templates,
  exploitability probes), SBOM generation (syft/CycloneDX), and first-class
  support for GitLab CI, Jenkins, CircleCI, Azure DevOps, and pre-commit hooks
  alongside the GitHub Action.
