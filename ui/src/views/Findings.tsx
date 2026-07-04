import { useMemo, useState } from "react";
import { Finding, RunDetail, Severity, SEVERITIES } from "../api";
import { Panel, SeverityBadge, EmptyState } from "../components";
import { VERDICT_CHIP, VERDICT_LABEL, riskColor } from "../theme";

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function Findings({ detail }: { detail: RunDetail }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string>("all");
  const [cat, setCat] = useState<string>("all");
  const [tool, setTool] = useState<string>("all");
  const [verdict, setVerdict] = useState<string>("all");
  const [minRisk, setMinRisk] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const newSet = useMemo(() => new Set(detail.newIds), [detail.newIds]);
  const tools = useMemo(
    () => Array.from(new Set(detail.findings.flatMap((f) => f.tools ?? [f.tool]))).sort(),
    [detail.findings],
  );
  const cats = useMemo(
    () => Array.from(new Set(detail.findings.map((f) => f.category))).sort(),
    [detail.findings],
  );

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return detail.findings
      .filter((f) => sev === "all" || f.severity === sev)
      .filter((f) => cat === "all" || f.category === cat)
      .filter((f) => tool === "all" || (f.tools ?? [f.tool]).includes(tool))
      .filter((f) => verdict === "all" || (verdict === "untriaged" ? !f.triage : f.triage?.verdict === verdict))
      .filter((f) => (f.riskScore ?? 0) >= minRisk)
      .filter(
        (f) =>
          needle === "" ||
          f.title.toLowerCase().includes(needle) ||
          (f.description ?? "").toLowerCase().includes(needle) ||
          (f.location.file ?? "").toLowerCase().includes(needle) ||
          f.ruleId.toLowerCase().includes(needle) ||
          (f.cwes ?? []).some((c) => c.toLowerCase().includes(needle)),
      )
      .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0) || SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  }, [detail.findings, q, sev, cat, tool, verdict, minRisk]);

  const selected = filtered.find((f) => f.id === selectedId) ?? filtered[0] ?? null;

  if (detail.findings.length === 0) {
    return <EmptyState title="No findings in this run" hint="This run recorded a clean scan. Nice." />;
  }

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
      {/* Filter rail + list */}
      <div className="lg:col-span-3">
        <Panel
          title={`Findings (${filtered.length}/${detail.findings.length})`}
          right={
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search title, path, CWE…"
              className="w-48 rounded-md border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
            />
          }
        >
          <div className="mb-3 flex flex-wrap gap-2 text-sm">
            <Select value={sev} onChange={setSev} label="Severity" options={["all", ...SEVERITIES]} />
            <Select value={cat} onChange={setCat} label="Category" options={["all", ...cats]} />
            <Select value={tool} onChange={setTool} label="Tool" options={["all", ...tools]} />
            <Select
              value={verdict}
              onChange={setVerdict}
              label="Verdict"
              options={["all", "true-positive", "false-positive", "uncertain", "untriaged"]}
            />
            <label className="inline-flex items-center gap-1 text-xs text-gray-500">
              Min risk {minRisk.toFixed(0)}
              <input
                type="range"
                min={0}
                max={10}
                step={1}
                value={minRisk}
                onChange={(e) => setMinRisk(Number(e.target.value))}
                className="w-24"
              />
            </label>
          </div>

          <div className="scroll-thin max-h-[62vh] overflow-y-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-white text-xs uppercase text-gray-500 dark:bg-gray-900">
                <tr>
                  <th className="py-2 pr-2">Risk</th>
                  <th className="py-2 pr-2">Sev</th>
                  <th className="py-2 pr-2">Title</th>
                  <th className="py-2 pr-2">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedId(f.id)}
                    className={`cursor-pointer border-t border-gray-100 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50 ${
                      selected?.id === f.id ? "bg-blue-50 dark:bg-blue-950/40" : ""
                    }`}
                  >
                    <td className="py-1.5 pr-2">
                      <RiskPill score={f.riskScore} />
                    </td>
                    <td className="py-1.5 pr-2">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-1.5 pr-2">
                      <div className="flex items-center gap-2">
                        {newSet.has(f.id) && (
                          <span className="rounded bg-emerald-100 px-1 text-[10px] font-bold text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-300">
                            NEW
                          </span>
                        )}
                        <span className="line-clamp-1 font-mono text-xs">{f.title}</span>
                      </div>
                      <div className="truncate text-[11px] text-gray-400">{f.location.file}</div>
                    </td>
                    <td className="py-1.5 pr-2">
                      {f.triage ? (
                        <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${VERDICT_CHIP[f.triage.verdict]}`}>
                          {VERDICT_LABEL[f.triage.verdict]}
                        </span>
                      ) : (
                        <span className="text-[11px] text-gray-400">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <p className="py-8 text-center text-sm text-gray-500">No findings match these filters.</p>
            )}
          </div>
        </Panel>
      </div>

      {/* Detail pane */}
      <div className="lg:col-span-2">
        {selected ? <Detail f={selected} isNew={newSet.has(selected.id)} /> : null}
      </div>
    </div>
  );
}

function Detail({ f, isNew }: { f: Finding; isNew: boolean }) {
  return (
    <Panel title="Finding detail">
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          <RiskPill score={f.riskScore} />
          {isNew && (
            <span className="rounded bg-emerald-100 px-1.5 text-[10px] font-bold text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-300">
              NEW
            </span>
          )}
          <span className="text-xs text-gray-400">{(f.tools ?? [f.tool]).join(", ")}</span>
        </div>

        {/* All values below are hostile data rendered as escaped text only. */}
        <h3 className="break-words font-mono text-sm font-semibold">{f.title}</h3>
        {f.description && <p className="whitespace-pre-wrap break-words text-gray-600 dark:text-gray-300">{f.description}</p>}

        <Row label="Location">
          <code className="break-all text-xs">
            {f.location.file}
            {f.location.startLine ? `:${f.location.startLine}` : ""}
          </code>
        </Row>
        <Row label="Rule">
          <code className="break-all text-xs">{f.ruleId}</code>
        </Row>
        {f.cwes && f.cwes.length > 0 && (
          <Row label="CWE">
            <span className="flex flex-wrap gap-1">
              {f.cwes.map((c) => (
                <span key={c} className="rounded bg-gray-100 px-1.5 py-0.5 text-xs dark:bg-gray-800">
                  {c}
                </span>
              ))}
            </span>
          </Row>
        )}
        {f.package && <Row label="Package"><code className="text-xs">{f.package}</code></Row>}
        {f.cve && <Row label="CVE"><code className="text-xs">{f.cve}</code></Row>}

        {f.triage && (
          <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-800/50">
            <div className="mb-1 flex items-center gap-2">
              <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${VERDICT_CHIP[f.triage.verdict]}`}>
                {VERDICT_LABEL[f.triage.verdict]}
              </span>
              {typeof f.triage.confidence === "number" && (
                <span className="text-xs text-gray-500">confidence {(f.triage.confidence * 100).toFixed(0)}%</span>
              )}
              {f.triage.model && <span className="ml-auto text-[10px] text-gray-400">{f.triage.model}</span>}
            </div>
            {f.triage.rationale && (
              <p className="whitespace-pre-wrap break-words text-xs text-gray-600 dark:text-gray-300">
                {f.triage.rationale}
              </p>
            )}
          </div>
        )}

        {f.remediation && (
          <Row label="Remediation">
            <p className="whitespace-pre-wrap break-words text-xs text-gray-600 dark:text-gray-300">{f.remediation}</p>
          </Row>
        )}
      </div>
    </Panel>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[80px_1fr] gap-2">
      <span className="text-xs font-medium uppercase text-gray-400">{label}</span>
      <div>{children}</div>
    </div>
  );
}

function RiskPill({ score }: { score?: number }) {
  if (score === undefined || score === null) return <span className="text-xs text-gray-400">—</span>;
  return (
    <span
      className="inline-block rounded px-1.5 py-0.5 text-xs font-bold tabular-nums text-white"
      style={{ background: riskColor(score) }}
    >
      {score.toFixed(1)}
    </span>
  );
}

function Select({
  value,
  onChange,
  label,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  options: string[];
}) {
  return (
    <label className="inline-flex items-center gap-1 text-xs text-gray-500">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-gray-300 bg-white px-1.5 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
      >
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}
