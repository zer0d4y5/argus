// API client + types. Field names mirror the Go JSON contract in
// internal/server/api.go exactly. Every string here (title, description, path,
// rationale) originates from scanned code or an LLM and is HOSTILE — it is only
// ever rendered as React text (auto-escaped), never as HTML.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Location {
  file?: string;
  resource?: string; // cloud findings (schema 2.1.0): resource UID/ARN, no file
  startLine?: number;
  endLine?: number;
  url?: string;
  snippet?: Snippet;
}

// locationLabel is the one place the UI decides how to name a finding's
// place: file:line for code, the resource UID/ARN for cloud findings (which
// have no file), a dash when neither exists. Feature-detect, never assume.
export function locationLabel(loc: Location): string {
  if (loc.file) {
    return loc.startLine ? `${loc.file}:${loc.startLine}` : loc.file;
  }
  if (loc.resource) return loc.resource;
  return "—";
}

export interface Triage {
  verdict: "true-positive" | "false-positive" | "uncertain";
  confidence?: number;
  rationale?: string;
  model?: string;
}

// Stage-2 context evidence behind riskScore (schema 1.3.0, risk v2).
// code/note are fixed strings from the reviewed signal tables in Go.
export interface RiskSignal {
  code: string;
  delta: number;
  note?: string;
}

export interface Finding {
  id: string;
  tool: string;
  tools?: string[];
  category: string;
  ruleId: string;
  title: string;
  displayName?: string; // clean weakness name from the CWE map; falls back to title
  description?: string;
  severity: Severity;
  toolSeverity?: Severity; // what the tool's own scale normalized to; severity is banded deterministic risk (2.0.0)
  rawSeverity?: string;
  confidence?: string;
  location: Location;
  package?: string;
  cwes?: string[];
  cve?: string;
  remediation?: string;
  meta?: Record<string, string>;
  complianceControls?: string[];
  triage?: Triage;
  riskScore?: number;
  riskSignals?: RiskSignal[];
  evidence?: Evidence;
  proof?: Proof;
}

// Evidence is the redacted request/response behind a DAST finding (opt-in).
export interface Evidence {
  request?: string;
  response?: string;
  fuzzParam?: string;
  fuzzPos?: string;
}

// Proof is the reproduction proof-of-concept for a confirmed dynamic finding
// (schema 2.3.0): the request, a copy-paste curl, the observed proof, and a
// plain-English reason. impact is present only when a bounded confirmation ran.
export interface Proof {
  request?: string;
  response?: string;
  curl?: string;
  observed?: string;
  rationale?: string;
  impact?: ImpactProof;
}

export interface ImpactProof {
  kind: string;
  command?: string;
  summary: string;
  detail?: string;
}

// ConfirmImpactResponse is the result of a live bounded-confirmation probe run
// from the console (admin, interlocked). Not persisted to the run.
export interface ConfirmImpactResponse {
  confirmed: boolean;
  impact?: ImpactProof;
  message?: string;
}

export interface OwaspCategory {
  id: string;
  title: string;
}
export interface OwaspBucket {
  category: OwaspCategory;
  count: number;
}

export interface FrameworkSummary {
  id: string;
  version: string;
  violatedControls: number;
  cleanControls: number;
  notAssessable: number;
  unmappedFindings: number;
}

export interface GateInfo {
  threshold: string;
  failed: boolean;
  // Findings excluded from the gate by disposition (accepted-risk /
  // false-positive) — still in the report, just no longer failing CI.
  suppressed?: number;
}
export interface VerdictCounts {
  truePositive: number;
  falsePositive: number;
  uncertain: number;
  untriaged: number;
}
export interface RiskBands {
  info: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

// Skip accounting (schema 2.0.0): what the scan did NOT look at.
export interface CoverageAccounting {
  filesTotal: number;
  bytesTotal: number;
  sastCovered: number;
  iacConfig: number;
  secretsOnly: number;
  unsupportedSource: number;
  binary: number;
  oversize: number;
  unreadable: number;
  oversizeLimitBytes: number;
  gitRepo: boolean;
  gitShallow: boolean;
  unsupportedSample?: string[];
  binarySample?: string[];
  oversizeSample?: string[];
}

export interface DeltaCounts {
  new: number;
  resolved: number;
  unchanged: number;
  total: number;
}

export interface TrendPoint {
  id: string;
  createdAt: string;
  total: number;
  bySeverity: Record<string, number>;
  riskAvg: number;
}

// Curated secure-coding guidance for a weakness class (see internal/mitigation).
export interface MitigationSnippet {
  language: string;
  library?: string;
  vulnerable: string;
  secure: string;
  note?: string;
}
export interface MitigationReference {
  title: string;
  url: string;
}
export interface Mitigation {
  weakness: string;
  title: string;
  cwes: string[];
  principle: string;
  snippets: MitigationSnippet[];
  references: MitigationReference[];
  matchedLanguage?: string;
}

export interface SummaryResponse {
  runCount: number;
  latestId: string;
  createdAt: string;
  total: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  owasp: OwaspBucket[];
  compliance: FrameworkSummary[];
  riskBands: RiskBands;
  gate: GateInfo;
  verdicts: VerdictCounts;
  trend: TrendPoint[];
  // Latest run's finding-workflow rollup by status (+ "regression").
  dispositions?: Record<string, number>;
}

export interface RunListItem {
  id: string;
  createdAt: string;
  total: number;
  bySeverity: Record<string, number>;
  gate: GateInfo;
  delta: DeltaCounts;
  verdicts: VerdictCounts;
}
export interface RunsResponse {
  runs: RunListItem[];
}

// A finding's durable human disposition (workflow status), keyed by
// fingerprint so it follows the finding across re-scans. Absence = "open".
export type DispositionStatus = "in-progress" | "accepted-risk" | "false-positive" | "fixed";
export interface Disposition {
  findingId: string;
  status: DispositionStatus;
  note?: string;
  actor: string;
  updatedAt: string;
}

// --- Ticketing ---
export type TicketStatus = "open" | "in-progress" | "blocked" | "done";
export type TicketPriority = "low" | "medium" | "high" | "urgent";
export interface TicketRollup {
  total: number;
  resolved: number;
  max?: Severity;
  bySeverity: Record<string, number>;
}
export interface Ticket {
  id: string;
  title: string;
  description: string;
  status: TicketStatus;
  priority: TicketPriority;
  assignee?: string;
  targetId?: string;
  dueDate?: string;
  externalUrl?: string;
  createdAt: string;
  createdBy?: string;
  updatedAt: string;
}
export interface TicketView extends Ticket {
  linkCount: number;
  rollup: TicketRollup;
}
export interface TicketLink { findingId: string; targetId?: string; }
export interface TicketComment { id: string; kind: string; author?: string; body: string; createdAt: string; }
export interface TicketDetail extends Ticket {
  links: TicketLink[];
  comments: TicketComment[];
  rollup: TicketRollup;
}

// --- Threat modeling ---
export type StrideCategory = "spoofing" | "tampering" | "repudiation" | "info-disclosure" | "denial-of-service" | "elevation";
export type ThreatStatus = "open" | "mitigated" | "accepted" | "transferred";
export interface ThreatModel {
  id: string;
  targetId?: string;
  name: string;
  description?: string;
  createdAt: string;
  createdBy?: string;
  updatedAt: string;
}
export interface ThreatComponent { id: string; modelId: string; kind: string; name: string; tech?: string; notes?: string; source: string; x: number; y: number; w: number; h: number; }
export interface Threat {
  id: string;
  modelId: string;
  componentId?: string;
  category: StrideCategory;
  title: string;
  description?: string;
  status: ThreatStatus;
  source: "curated" | "assisted" | "manual";
  mitigation?: string;
  createdAt: string;
}
export interface ThreatLink { kind: "finding" | "control" | "mitigation"; ref: string; targetId?: string; }
export interface ThreatFlow { id: string; modelId: string; fromId: string; toId: string; label?: string; }
export interface ThreatModelDetail extends ThreatModel {
  components: ThreatComponent[];
  threats: Threat[];
  links: Record<string, ThreatLink[]>;
  flows: ThreatFlow[];
}
export interface LibraryComponent { tech: string; title: string; }

export interface RunDetail {
  id: string;
  createdAt: string;
  total: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  owasp: OwaspBucket[];
  compliance: FrameworkSummary[];
  gate: GateInfo;
  verdicts: VerdictCounts;
  delta: DeltaCounts;
  newIds: string[];
  resolvedIds: string[];
  // The run the new/resolved delta was computed against: the previous run by
  // default, or the run chosen as a baseline. Empty for the first run.
  baselineId: string;
  findings: Finding[];
  coverage?: CoverageAccounting;
  // Per-finding workflow dispositions for findings present in this run,
  // keyed by finding id. Absent/omitted findings are "open".
  dispositions?: Record<string, Disposition>;
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`${path}: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export const api = {
  summary: (targetId?: string) => {
    const base = "api/summary";
    if (targetId) {
      return getJSON<SummaryResponse>(`${base}?target=${encodeURIComponent(targetId)}`);
    }
    return getJSON<SummaryResponse>(base);
  },
  runs: (targetId?: string) => {
    const base = "api/runs";
    if (targetId) {
      return getJSON<RunsResponse>(`${base}?target=${encodeURIComponent(targetId)}`);
    }
    return getJSON<RunsResponse>(base);
  },
  run: (id: string, targetId?: string, baselineId?: string) => {
    const base = `api/runs/${encodeURIComponent(id)}`;
    const params = new URLSearchParams();
    if (targetId) params.set("target", targetId);
    if (baselineId) params.set("baseline", baselineId);
    const qs = params.toString();
    // Old zero-finding runs can carry findings: null; the views index into
    // the array unguarded, so normalize at the one fetch seam.
    return getJSON<RunDetail>(qs ? `${base}?${qs}` : base).then((d) => ({
      ...d,
      findings: d.findings ?? [],
    }));
  },
  // The download URL for a run export (SARIF or JSON). Server sets
  // Content-Disposition; the browser downloads. GET (viewer) — no CSRF.
  exportUrl: (id: string, format: "sarif" | "json" | "html", targetId?: string) => {
    const q = new URLSearchParams({ format });
    if (targetId) q.set("target", targetId);
    return `api/runs/${encodeURIComponent(id)}/export?${q.toString()}`;
  },
  // Curated secure-coding guidance for a finding's CWEs. Resolves to null when
  // the library has nothing for them (a 404), so callers can hide the panel.
  mitigation: async (cwes: string[], lang?: string): Promise<Mitigation | null> => {
    const q = new URLSearchParams();
    cwes.forEach((c) => q.append("cwe", c));
    if (lang) q.set("lang", lang);
    try {
      return await getJSON<Mitigation>(`api/mitigations?${q.toString()}`);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }
  },
};

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

// --- Console-ops (auth, targets, scan jobs, audit) ---
// Field names mirror internal/server DTOs exactly; opsApi sends the
// session CSRF token on every non-GET request.

// --- New TypeScript types (exact JSON contract from the Go server) ---

export interface UserInfo { id: string; username: string; role: string; createdAt: string; }
// A curated cloud remediation applicable to a finding. Commands are argv
// arrays (never a shell string), resolved server-side from the catalog.
export interface CloudRemediation {
  id: string;
  title: string;
  provider: string; // "aws" | "azure" | "gcp": selects the credential UI
  description: string;
  dryRun: string[][];
  apply: string[][];
  reversible: boolean;
  reversalNote?: string;
  permissions: string[];
  region?: string;
}
export interface CloudRemediateResult {
  results: { command: string[]; output: string; error?: string }[];
  applied: boolean;
  reScanHint: string;
}

// Console-managed integration + scanning settings. Secrets are never here —
// only env-var names, plus a read-only flag on whether each var is set.
export interface TriageSettings {
  enabled: boolean;
  provider: string; // ollama | anthropic
  model: string;
  endpoint: string;
  maxFindings: number;
  excludeFp: boolean;
}
export interface SettingsView {
  githubRepo: string;
  githubTokenEnv: string;
  githubTokenSet: boolean;
  triage: TriageSettings;
  anthropicKeySet: boolean;
  scanProfile: string;
  failSeverity: string;
  semgrepRulesets: string[];
  semgrepRulesetsAdditive: boolean;
  remediationEnabled: boolean;
}
export interface SettingsInput {
  githubRepo?: string;
  githubTokenEnv?: string;
  triage?: TriageSettings;
  scanProfile?: string;
  failSeverity?: string;
  semgrepRulesets?: string[];
  semgrepRulesetsAdditive?: boolean;
  remediationEnabled?: boolean;
}

// One custom-ruleset entry's validation verdict from the check-rules endpoint.
export interface RulesetStatus {
  entry: string;
  kind?: string; // "pack" | "local"
  ok: boolean;
  message?: string;
}

// AI-assisted rule authoring.
export interface RuleSafetyIssue {
  rule?: string;
  message: string;
  blocking: boolean;
}
export interface RuleDraft {
  rule: string; // the drafted/edited rule YAML
  issues: RuleSafetyIssue[];
  ready: boolean; // parsed + no blocking safety issue
  model: string; // provider/model that produced it (for the AI-generated label)
}
export interface RuleTestMatch {
  check: string;
  startLine: number;
  endLine: number;
}
export interface RuleTestResult {
  issues: RuleSafetyIssue[];
  safe: boolean;
  valid: boolean;
  validationError: string;
  matched: boolean;
  matches: RuleTestMatch[];
}
export interface SavedRule {
  name: string;
  path: string;
  active: boolean;
}

// A rule-pack catalog entry (a curated semgrep registry pack).
export interface CatalogPack {
  id: string;
  label: string;
  category: string; // "language" | "framework" | "cloud" | "class"
  description: string;
  active: boolean; // currently in the custom rulesets
  inProfile: boolean; // already run by the standard/max profile
}

export interface MeResponse { authRequired: boolean; authenticated: boolean; user?: UserInfo; csrfToken?: string; githubRepo?: string; ssoEnabled?: boolean; }

// SSO (OIDC) admin configuration. The client secret is never here — the UI
// configures the env-var NAME (clientSecretEnv) and reads back whether that
// var is currently set on the server (secretPresent).
export interface OIDCConfigInput {
  issuer: string;
  clientId: string;
  clientSecretEnv?: string;
  redirectUrl: string;
  allowedDomains?: string[];
  defaultRole?: string;
  groupClaim?: string;
  roleMap?: Record<string, string>;
  disable?: boolean;
}
export interface OIDCConfigView extends OIDCConfigInput {
  source: "store" | "config" | "none";
  enabled: boolean;
  secretEnvName: string;
  secretPresent: boolean;
}
export interface LoginResponse { user: UserInfo; csrfToken: string; }

export interface Snippet { startLine: number; lines: string[] }

export interface TargetConfig {
  timeoutSec?: number;
  triage?: boolean | null;
  ignorePaths?: string[];
  ignoreRules?: string[];
  dast?: DastConfig;
}

// DastConfig mirrors the `argus dast` options for a DAST target. Credentials
// are never stored: usernameEnv/passwordEnv name environment variables read on
// the server at scan time.
export interface DastConfig {
  fuzzing?: boolean;
  crawl?: boolean;
  evidence?: boolean;
  dalfox?: boolean;
  sqlmap?: boolean;
  cmdi?: boolean;
  ssrf?: boolean;
  ssti?: boolean;
  fileUpload?: boolean;
  graphql?: boolean;
  recon?: boolean;
  fingerprint?: boolean;
  apiRecon?: boolean;
  crawlDepth?: number;
  crawlPages?: number;
  templates?: string[];
  tags?: string[];
  severities?: string[];
  rateLimit?: number;
  idor?: boolean;
  auth?: DastAuthConfig;
  auth2?: DastAuthConfig;
}
export interface DastAuthConfig {
  loginUrl?: string;
  usernameEnv?: string;
  passwordEnv?: string;
  tryDefaults?: boolean;
}

export interface Target {
  id: string; name: string;
  type?: "dir" | "git" | "cloud" | "dast" | "image";
  path?: string;
  url?: string; branch?: string;
  // Cloud targets (schema 2.1.0): a provider + a profile NAME (never a key)
  // and an optional region filter.
  provider?: string; profileName?: string; regions?: string[];
  // DAST targets reuse url (a running http/https target). Image targets
  // (schema 2.2.0) carry a container image reference. Neither stores a
  // credential.
  ref?: string;
  scanners?: string[]; profile?: string;
  config?: TargetConfig;
  createdAt: string;
}

export interface TargetsResponse { targets: Target[]; }

// Cloud profile discovery: the closed list of profile NAMES the console host
// has locally, per provider. Names only — never key material.
export interface CloudProviderProfiles { provider: string; profiles: string[]; }
export interface CloudProfilesResponse { providers: CloudProviderProfiles[]; }

export interface JobOptions { scanners?: string[]; profile?: string; triage?: boolean | null; scope?: string; frameworks?: string[] }

export type JobStatus = "queued" | "running" | "done" | "failed";

export interface Job {
  id: string; targetId: string; targetName: string; launchedBy: string;
  options: JobOptions; status: JobStatus; queuedAt: string;
  startedAt?: string; finishedAt?: string; progress: string[];
  runId?: string; error?: string; commit?: string;
}

export interface JobsResponse { jobs: Job[]; }

export interface AuditEntry { time: string; event: string; actor?: string; details?: Record<string, string>; }
export interface AuditResponse { entries: AuditEntry[]; }

// --- ApiError class ---

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// --- Module-level CSRF state ---

let csrfToken: string | null = null;

export function setCsrfToken(t: string | null): void {
  csrfToken = t;
}

// --- send helper ---

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (!res.ok) {
    let errorMessage = `${path}: ${res.status} ${res.statusText}`;
    try {
      const errBody = await res.json();
      if (errBody && typeof errBody === "object" && "error" in errBody && typeof errBody.error === "string") {
        errorMessage = errBody.error;
      }
    } catch {
      // Ignore parse errors, use default message
    }
    throw new ApiError(res.status, errorMessage);
  }

  // Every success body in the contract is JSON; a non-JSON success is empty.
  const contentType = res.headers.get("content-type");
  if (!contentType || !contentType.includes("application/json")) {
    return undefined as unknown as T;
  }
  return (await res.json()) as T;
}

// --- Constants ---

export const KNOWN_SCANNERS = ["semgrep", "gitleaks", "trivy", "osv-scanner", "checkov", "trivy-config"];
export const PROFILES = ["fast", "standard", "max"];

// --- opsApi implementation ---

export interface FrameworkInfo { id: string; name: string; version: string; scanners: string[] }
export interface FrameworksResponse { frameworks: FrameworkInfo[] }

export interface ExplainResponse { explanation: string; remediation?: string; model: string; cached: boolean }

// AI-assisted remediation (on-demand, never persisted). Artifacts are scripts
// the USER runs — the platform never executes them. safetyIssues, when
// present, mean the deterministic linter withheld/defanged something.
export interface RemediationArtifact { language: string; title: string; content: string }
export interface RemediationResponse {
  summary: string;
  kind: "cli-script" | "code-patch" | "dependency-upgrade" | "secret-rotation" | "manual";
  steps?: string[];
  artifacts?: RemediationArtifact[];
  warnings?: string[];
  verification?: string;
  model: string;
  safetyIssues?: string[];
}

// Advisory severity validation (verdict + impact/likelihood + a
// deterministically-scored CVSS 3.1 vector). Never changes stored severity.
export interface ValidationResponse {
  verdict: "true-positive" | "false-positive" | "uncertain";
  impact: string;
  likelihood: string;
  cvssVector: string;
  cvssScore: number;
  cvssSeverity: string; // None/Low/Medium/High/Critical/unrated
  rationale: string;
  model: string;
}

export const opsApi = {
  me: (): Promise<MeResponse> => send<MeResponse>("GET", "api/auth/me"),
  
  login: (username: string, password: string): Promise<LoginResponse> => 
    send<LoginResponse>("POST", "api/auth/login", { username, password }),
  
  logout: (): Promise<void> => 
    send<void>("POST", "api/auth/logout"),
  
  users: (): Promise<{ users: UserInfo[] }> => 
    send<{ users: UserInfo[] }>("GET", "api/users"),
  
  createUser: (username: string, password: string, role: string): Promise<UserInfo> => 
    send<UserInfo>("POST", "api/users", { username, password, role }),
  
  updateUserRole: (id: string, role: string): Promise<UserInfo> => 
    send<UserInfo>("PATCH", `api/users/${encodeURIComponent(id)}`, { role }),
  
  updateUserPassword: (id: string, password: string): Promise<UserInfo> => 
    send<UserInfo>("PATCH", `api/users/${encodeURIComponent(id)}`, { password }),
  
  deleteUser: (id: string): Promise<void> => 
    send<void>("DELETE", `api/users/${encodeURIComponent(id)}`),
  
  targets: (): Promise<TargetsResponse> => 
    send<TargetsResponse>("GET", "api/targets"),
  
  createTarget: (t: { name: string; type?: "dast" | "image"; path?: string; url?: string; branch?: string; ref?: string; provider?: string; profileName?: string; account?: string; regions?: string[]; scanners?: string[]; profile?: string }): Promise<Target> =>
    send<Target>("POST", "api/targets", t),

  cloudProfiles: (): Promise<CloudProfilesResponse> =>
    send<CloudProfilesResponse>("GET", "api/cloud/profiles"),

  // generateSbom returns the raw SBOM document text (CycloneDX/SPDX), not
  // JSON, so it does its own fetch with the CSRF header rather than send<T>.
  // The caller triggers a browser download of the returned text.
  generateSbom: async (targetId: string, format: "cyclonedx" | "spdx-json" | "spdx"): Promise<string> => {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
    const res = await fetch("api/sbom", {
      method: "POST",
      headers,
      body: JSON.stringify({ targetId: targetId || undefined, format }),
    });
    if (!res.ok) {
      let msg = `api/sbom: ${res.status} ${res.statusText}`;
      try {
        const b = await res.json();
        if (b && typeof b === "object" && "error" in b && typeof b.error === "string") msg = b.error;
      } catch { /* keep default */ }
      throw new ApiError(res.status, msg);
    }
    return await res.text();
  },

  postureSummary: (targetId: string, runId: string): Promise<{ summary: string; model: string }> =>
    send<{ summary: string; model: string }>("POST", "api/cloud/posture-summary", { targetId, runId }),

  cloudRemediations: (req: { targetId?: string; runId: string; findingId: string }): Promise<{ remediations: CloudRemediation[]; enabled: boolean }> =>
    send<{ remediations: CloudRemediation[]; enabled: boolean }>("POST", "api/cloud/remediations", req),
  cloudRemediate: (req: { targetId?: string; runId: string; findingId: string; remediationId: string; mode: "dryrun" | "apply"; profile?: string }): Promise<CloudRemediateResult> =>
    send<CloudRemediateResult>("POST", "api/cloud/remediate", req),

  deleteTarget: (id: string): Promise<void> =>
    send<void>("DELETE", `api/targets/${encodeURIComponent(id)}`),

  deleteRun: (id: string, targetId?: string): Promise<void> => {
    const q = targetId ? `?target=${encodeURIComponent(targetId)}` : "";
    return send<void>("DELETE", `api/runs/${encodeURIComponent(id)}${q}`);
  },
  
  updateTarget: (id: string, patch: { name?: string; scanners?: string[]; profile?: string; config?: TargetConfig }): Promise<Target> => 
    send<Target>("PATCH", `api/targets/${encodeURIComponent(id)}`, patch),
  
  jobs: (): Promise<JobsResponse> => 
    send<JobsResponse>("GET", "api/scans"),
  
  job: (id: string): Promise<Job> => 
    send<Job>(`GET`, `api/scans/${encodeURIComponent(id)}`),
  
  launchScan: (targetId: string, options: JobOptions): Promise<Job> => 
    send<Job>("POST", "api/scans", { targetId, options }),
  
  audit: (n = 200): Promise<AuditResponse> =>
    send<AuditResponse>(`GET`, `api/audit?n=${n}`),

  getSettings: (): Promise<SettingsView> =>
    send<SettingsView>("GET", "api/admin/settings"),
  saveSettings: (req: SettingsInput): Promise<SettingsView> =>
    send<SettingsView>("PUT", "api/admin/settings", req),
  validateRulesets: (semgrepRulesets: string[]): Promise<{ results: RulesetStatus[] }> =>
    send<{ results: RulesetStatus[] }>("POST", "api/admin/settings/validate-rulesets", { semgrepRulesets }),

  draftRule: (req: { description: string; language: string; existingRule?: string; instruction?: string }): Promise<RuleDraft> =>
    send<RuleDraft>("POST", "api/admin/rules/draft", req),
  testRule: (req: { rule: string; snippet?: string; language?: string }): Promise<RuleTestResult> =>
    send<RuleTestResult>("POST", "api/admin/rules/test", req),
  listRules: (): Promise<{ rules: SavedRule[] }> =>
    send<{ rules: SavedRule[] }>("GET", "api/admin/rules"),
  saveRule: (req: { name: string; rule: string; activate?: boolean }): Promise<{ name: string; path: string; activated: boolean }> =>
    send<{ name: string; path: string; activated: boolean }>("POST", "api/admin/rules", req),
  deleteRule: (name: string): Promise<{ deleted: string }> =>
    send<{ deleted: string }>("DELETE", `api/admin/rules/${encodeURIComponent(name)}`),
  ruleCatalog: (): Promise<{ categories: string[]; packs: CatalogPack[] }> =>
    send<{ categories: string[]; packs: CatalogPack[] }>("GET", "api/admin/rule-catalog"),
  toggleRuleset: (entry: string, enabled: boolean): Promise<{ entry: string; enabled: boolean }> =>
    send<{ entry: string; enabled: boolean }>("POST", "api/admin/rulesets/toggle", { entry, enabled }),

  getOIDCConfig: (): Promise<OIDCConfigView> =>
    send<OIDCConfigView>("GET", "api/admin/oidc"),
  saveOIDCConfig: (req: OIDCConfigInput): Promise<OIDCConfigView> =>
    send<OIDCConfigView>("PUT", "api/admin/oidc", req),
  disableOIDCConfig: (): Promise<OIDCConfigView> =>
    send<OIDCConfigView>("PUT", "api/admin/oidc", { disable: true }),

  frameworks: (): Promise<FrameworksResponse> =>
    send<FrameworksResponse>("GET", "api/frameworks"),

  explain: (req: { targetId?: string; runId: string; findingId: string }): Promise<ExplainResponse> =>
    send<ExplainResponse>("POST", "api/explain", req),

  remediate: (req: { targetId?: string; runId: string; findingId: string }): Promise<RemediationResponse> =>
    send<RemediationResponse>("POST", "api/remediate", req),

  validate: (req: { targetId?: string; runId: string; findingId: string }): Promise<ValidationResponse> =>
    send<ValidationResponse>("POST", "api/validate", req),

  confirmImpact: (req: { targetId: string; runId: string; findingId: string }): Promise<ConfirmImpactResponse> =>
    send<ConfirmImpactResponse>("POST", "api/confirm-impact", { ...req, confirm: true }),

  setDisposition: (req: { targetId?: string; findingId: string; status: DispositionStatus; note?: string }): Promise<Disposition> =>
    send<Disposition>("POST", "api/dispositions", req),

  clearDisposition: (findingId: string, targetId?: string): Promise<void> => {
    const q = targetId ? `?target=${encodeURIComponent(targetId)}` : "";
    return send<void>("DELETE", `api/dispositions/${encodeURIComponent(findingId)}${q}`);
  },

  // Apply one status to many findings (or clear them, status omitted) in a
  // single locked write. Returns how many were updated.
  bulkDisposition: (req: { targetId?: string; findingIds: string[]; status?: DispositionStatus; note?: string }): Promise<{ updated: number }> =>
    send<{ updated: number }>("POST", "api/dispositions/bulk", req),

  // --- Ticketing ---
  tickets: (filter?: { status?: string; assignee?: string; priority?: string }): Promise<{ tickets: TicketView[] }> => {
    const q = new URLSearchParams();
    if (filter?.status) q.set("status", filter.status);
    if (filter?.assignee) q.set("assignee", filter.assignee);
    if (filter?.priority) q.set("priority", filter.priority);
    const qs = q.toString();
    return send<{ tickets: TicketView[] }>("GET", `api/tickets${qs ? `?${qs}` : ""}`);
  },
  workSummary: (): Promise<{ tickets: Record<string, number>; threats: Record<string, number> }> =>
    send<{ tickets: Record<string, number>; threats: Record<string, number> }>("GET", "api/work-summary"),
  userNames: (): Promise<{ names: string[] }> =>
    send<{ names: string[] }>("GET", "api/users/names"),
  ticket: (id: string): Promise<TicketDetail> =>
    send<TicketDetail>("GET", `api/tickets/${encodeURIComponent(id)}`),
  createTicket: (req: { title: string; description?: string; priority?: string; assignee?: string; targetId?: string; findingIds?: string[] }): Promise<Ticket> =>
    send<Ticket>("POST", "api/tickets", req),
  updateTicket: (id: string, patch: Partial<{ title: string; description: string; status: TicketStatus; priority: TicketPriority; assignee: string; dueDate: string }>): Promise<Ticket> =>
    send<Ticket>("PATCH", `api/tickets/${encodeURIComponent(id)}`, patch),
  deleteTicket: (id: string): Promise<void> =>
    send<void>("DELETE", `api/tickets/${encodeURIComponent(id)}`),
  ticketComment: (id: string, body: string): Promise<TicketComment> =>
    send<TicketComment>("POST", `api/tickets/${encodeURIComponent(id)}/comments`, { body }),
  ticketLink: (id: string, findingId: string, targetId?: string, remove?: boolean): Promise<{ links: TicketLink[] }> =>
    send<{ links: TicketLink[] }>("POST", `api/tickets/${encodeURIComponent(id)}/links`, { findingId, targetId, remove }),
  ticketGitHub: (id: string, issueUrl?: string): Promise<{ externalUrl: string; externalId: string }> =>
    send<{ externalUrl: string; externalId: string }>("POST", `api/tickets/${encodeURIComponent(id)}/github`, issueUrl ? { issueUrl } : {}),
  ticketCloseFixed: (id: string): Promise<{ markedFixed: number; skipped: number; kept: number }> =>
    send<{ markedFixed: number; skipped: number; kept: number }>("POST", `api/tickets/${encodeURIComponent(id)}/close-fixed`, {}),

  // --- Threat modeling ---
  threatLibrary: (): Promise<{ components: LibraryComponent[] }> =>
    send<{ components: LibraryComponent[] }>("GET", "api/threat-library"),
  threatModels: (target?: string): Promise<{ models: ThreatModel[] }> =>
    send<{ models: ThreatModel[] }>("GET", `api/threat-models${target ? `?target=${encodeURIComponent(target)}` : ""}`),
  threatModel: (id: string): Promise<ThreatModelDetail> =>
    send<ThreatModelDetail>("GET", `api/threat-models/${encodeURIComponent(id)}`),
  createThreatModel: (req: { name: string; targetId?: string; description?: string }): Promise<ThreatModel> =>
    send<ThreatModel>("POST", "api/threat-models", req),
  deleteThreatModel: (id: string): Promise<void> =>
    send<void>("DELETE", `api/threat-models/${encodeURIComponent(id)}`),
  addThreatComponent: (modelId: string, req: { name: string; tech?: string; kind?: string; notes?: string; source?: string; x?: number; y?: number }): Promise<ThreatComponent> =>
    send<ThreatComponent>("POST", `api/threat-models/${encodeURIComponent(modelId)}/components`, req),
  removeThreatComponent: (modelId: string, componentId: string): Promise<{ ok: boolean }> =>
    send<{ ok: boolean }>("POST", `api/threat-models/${encodeURIComponent(modelId)}/components`, { remove: true, componentId }),
  updateThreatComponent: (modelId: string, componentId: string, req: { name: string; tech?: string; kind?: string; notes?: string }): Promise<ThreatComponent> =>
    send<ThreatComponent>("POST", `api/threat-models/${encodeURIComponent(modelId)}/components`, { componentId, ...req }),
  removeThreat: (modelId: string, threatId: string): Promise<{ ok: boolean }> =>
    send<{ ok: boolean }>("POST", `api/threat-models/${encodeURIComponent(modelId)}/threats`, { remove: true, threatId }),
  suggestComponents: (modelId: string): Promise<{ suggestions: ComponentSuggestion[]; model: string }> =>
    send<{ suggestions: ComponentSuggestion[]; model: string }>("POST", `api/threat-models/${encodeURIComponent(modelId)}/suggest-components`, {}),
  enumerateComponent: (modelId: string, componentId: string): Promise<{ added: number }> =>
    send<{ added: number }>("POST", `api/threat-models/${encodeURIComponent(modelId)}/enumerate`, { componentId }),
  setThreatStatus: (modelId: string, threatId: string, status: ThreatStatus): Promise<void> =>
    send<void>("POST", `api/threat-models/${encodeURIComponent(modelId)}/threat-status`, { threatId, status }),
  linkThreat: (modelId: string, req: { threatId: string; kind: string; ref: string; targetId?: string; remove?: boolean }): Promise<void> =>
    send<void>("POST", `api/threat-models/${encodeURIComponent(modelId)}/links`, req),
  threatModelFromTarget: (targetId: string, name?: string): Promise<{ modelId: string; components: number; threats: number }> =>
    send<{ modelId: string; components: number; threats: number }>("POST", "api/threat-models/from-target", { targetId, name }),
  suggestThreats: (modelId: string): Promise<{ suggestions: ThreatSuggestion[]; model: string }> =>
    send<{ suggestions: ThreatSuggestion[]; model: string }>("POST", `api/threat-models/${encodeURIComponent(modelId)}/suggest`, {}),
  saveThreatPositions: (modelId: string, positions: { componentId: string; x: number; y: number; w?: number; h?: number }[]): Promise<{ saved: number }> =>
    send<{ saved: number }>("POST", `api/threat-models/${encodeURIComponent(modelId)}/positions`, { positions }),
  addThreatFlow: (modelId: string, req: { fromId: string; toId: string; label?: string }): Promise<ThreatFlow> =>
    send<ThreatFlow>("POST", `api/threat-models/${encodeURIComponent(modelId)}/flows`, req),
  removeThreatFlow: (modelId: string, flowId: string): Promise<{ ok: boolean }> =>
    send<{ ok: boolean }>("POST", `api/threat-models/${encodeURIComponent(modelId)}/flows`, { remove: true, flowId }),
  addThreat: (modelId: string, req: { category: StrideCategory; title: string; description?: string; componentId?: string; mitigation?: string; source?: string }): Promise<Threat> =>
    send<Threat>("POST", `api/threat-models/${encodeURIComponent(modelId)}/threats`, req),
};
export interface ThreatSuggestion { category: StrideCategory; title: string; description?: string; component?: string; }
export interface ComponentSuggestion { name: string; tech?: string; kind: string; rationale?: string; }
