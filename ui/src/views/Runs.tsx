import { useMemo, useState } from "react";
import { RunsResponse } from "../api";
import { Panel, GateBadge, EmptyState } from "../components";
import { SEV_COLOR, fmtTime } from "../theme";

// The served repo's own runs have no origin; this label stands in for them
// in the target filter and the Target column.
const SERVED_REPO = "(served repo)";

export function Runs({
  runs,
  selectedId,
  onSelect,
}: {
  runs: RunsResponse;
  selectedId: string | null;
  onSelect: (id: string, targetId?: string) => void;
}) {
  const [targetFilter, setTargetFilter] = useState("all");

  // Distinct origins present in the aggregated list, served repo first.
  const origins = useMemo(() => {
    const seen = new Map<string, string>();
    runs.runs.forEach((r) => {
      if (r.target) seen.set(r.target.id, r.target.name);
    });
    return Array.from(seen, ([id, name]) => ({ id, name }));
  }, [runs.runs]);

  const hasServedRuns = runs.runs.some((r) => !r.target);
  const filtered =
    targetFilter === "all"
      ? runs.runs
      : runs.runs.filter((r) => (targetFilter === "" ? !r.target : r.target?.id === targetFilter));

  if (runs.runs.length === 0) {
    return <EmptyState title="No runs" hint="Record runs with `appsec scan --save` or launch one from Operate." />;
  }

  return (
    <Panel
      title={`Run history (${filtered.length}${targetFilter === "all" ? "" : `/${runs.runs.length}`})`}
      right={
        (origins.length > 0 || !hasServedRuns) && (
          <label className="flex items-center gap-1 text-xs text-gray-500">
            Target
            <select
              value={targetFilter}
              onChange={(e) => setTargetFilter(e.target.value)}
              className="rounded-md border border-gray-300 bg-white px-1.5 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
            >
              <option value="all">all</option>
              {hasServedRuns && <option value="">{SERVED_REPO}</option>}
              {origins.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
          </label>
        )
      }
    >
      <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead className="text-xs uppercase text-gray-500">
            <tr>
              <th className="py-2 pr-3">Run</th>
              <th className="py-2 pr-3">Target</th>
              <th className="py-2 pr-3">Gate</th>
              <th className="py-2 pr-3">Findings</th>
              <th className="py-2 pr-3">Severity mix</th>
              <th className="py-2 pr-3">Δ vs previous</th>
              <th className="py-2 pr-3">Triage</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr
                key={`${r.target?.id ?? ""}|${r.id}`}
                onClick={() => onSelect(r.id, r.target?.id)}
                className={`cursor-pointer border-t border-gray-100 align-top hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50 ${
                  selectedId === r.id ? "bg-blue-50 dark:bg-blue-950/40" : ""
                }`}
              >
                <td className="py-2.5 pr-3">
                  <div className="font-medium">{fmtTime(r.createdAt)}</div>
                  <div className="font-mono text-[10px] text-gray-400">{r.id}</div>
                </td>
                <td className="py-2.5 pr-3">
                  {r.target ? (
                    <span className="rounded bg-gray-100 px-1.5 py-0.5 text-xs dark:bg-gray-800">{r.target.name}</span>
                  ) : (
                    <span className="text-xs text-gray-400">{SERVED_REPO}</span>
                  )}
                </td>
                <td className="py-2.5 pr-3">
                  <GateBadge gate={r.gate} />
                </td>
                <td className="py-2.5 pr-3 text-2xl font-bold tabular-nums">{r.total}</td>
                <td className="py-2.5 pr-3">
                  <SeverityBar bySeverity={r.bySeverity} total={r.total} />
                </td>
                <td className="py-2.5 pr-3">
                  <div className="flex gap-2 text-xs">
                    <span className="text-emerald-600 dark:text-emerald-400">+{r.delta.new} new</span>
                    <span className="text-gray-500">−{r.delta.resolved} resolved</span>
                  </div>
                  <div className="text-[11px] text-gray-400">{r.delta.unchanged} unchanged</div>
                </td>
                <td className="py-2.5 pr-3 text-xs">
                  <span className="text-red-600 dark:text-red-400">{r.verdicts.truePositive} TP</span>{" · "}
                  <span className="text-green-600 dark:text-green-400">{r.verdicts.falsePositive} FP</span>{" · "}
                  <span className="text-yellow-600 dark:text-yellow-400">{r.verdicts.uncertain} ?</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
        New vs resolved is computed by stable fingerprint between consecutive runs of the same target. Click a run to load it in Findings.
      </p>
    </Panel>
  );
}

function SeverityBar({ bySeverity, total }: { bySeverity: Record<string, number>; total: number }) {
  const order = ["critical", "high", "medium", "low", "info"] as const;
  if (total === 0) return <span className="text-xs text-gray-400">clean</span>;
  return (
    <div className="flex h-3 w-40 overflow-hidden rounded-full">
      {order.map((s) => {
        const v = bySeverity[s] || 0;
        if (v === 0) return null;
        return (
          <div
            key={s}
            title={`${s}: ${v}`}
            style={{ width: `${(v / total) * 100}%`, background: SEV_COLOR[s] }}
          />
        );
      })}
    </div>
  );
}
