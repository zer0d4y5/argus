// API client + types. Field names mirror the Go JSON contract in
// internal/server/api.go exactly. Every string here (title, description, path,
// rationale) originates from scanned code or an LLM and is HOSTILE — it is only
// ever rendered as React text (auto-escaped), never as HTML.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Location {
  file?: string;
  startLine?: number;
  endLine?: number;
  url?: string;
}

export interface Triage {
  verdict: "true-positive" | "false-positive" | "uncertain";
  confidence?: number;
  rationale?: string;
  model?: string;
}

export interface Finding {
  id: string;
  tool: string;
  tools?: string[];
  category: string;
  ruleId: string;
  title: string;
  description?: string;
  severity: Severity;
  rawSeverity?: string;
  confidence?: string;
  location: Location;
  package?: string;
  cwes?: string[];
  cve?: string;
  remediation?: string;
  complianceControls?: string[];
  triage?: Triage;
  riskScore?: number;
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
}
export interface VerdictCounts {
  truePositive: number;
  falsePositive: number;
  uncertain: number;
  untriaged: number;
}
export interface RiskBands {
  low: number;
  medium: number;
  high: number;
  critical: number;
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
  findings: Finding[];
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`${path}: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export const api = {
  summary: () => getJSON<SummaryResponse>("api/summary"),
  runs: () => getJSON<RunsResponse>("api/runs"),
  run: (id: string) => getJSON<RunDetail>(`api/runs/${encodeURIComponent(id)}`),
};

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
