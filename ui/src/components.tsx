import { ReactNode } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { Severity, GateInfo } from "./api";
import { SEV_CHIP, SEV_COLOR, CATEGORY_CHIP, CATEGORY_LABEL, CATEGORY_COLOR } from "./theme";

export function Panel({
  title,
  children,
  right,
  className = "",
}: {
  title?: string;
  children: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900 ${className}`}
    >
      {(title || right) && (
        <div className="mb-3 flex items-center justify-between">
          {title && (
            <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
              {title}
            </h2>
          )}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function StatCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-800 dark:bg-gray-900">
      <div className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
        {label}
      </div>
      <div className="mt-1 text-3xl font-bold tabular-nums" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {sub && <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">{sub}</div>}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-semibold ${SEV_CHIP[severity]}`}>
      {severity}
    </span>
  );
}

// CategoryBadge labels a finding category (SAST/SECRET/SCA/IAC/DAST). The
// category string comes from the model's fixed constants, but unknown values
// still render (neutral chip, raw text) rather than disappearing. `compact`
// shows the raw category code instead of the long label.
export function CategoryBadge({ category, compact = false }: { category: string; compact?: boolean }) {
  const chipClass = CATEGORY_CHIP[category] || "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300";
  const label = compact ? category : CATEGORY_LABEL[category] || category;
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-semibold ${chipClass}`}>
      {label}
    </span>
  );
}

// CategoryBreakdown renders per-category counts as labeled proportion bars.
// Known categories come first in canonical order; unknown categories present
// in the data are appended, never hidden.
export function CategoryBreakdown({ byCategory }: { byCategory: Record<string, number> }) {
  const order = ["SAST", "SECRET", "SCA", "IAC", "DAST"];
  const extras = Object.keys(byCategory).filter((c) => !order.includes(c)).sort();
  const entries = [...order, ...extras]
    .map((cat) => ({ cat, count: byCategory[cat] || 0 }))
    .filter((e) => e.count > 0);

  if (entries.length === 0) {
    return <p className="py-6 text-center text-sm text-gray-500">No categorized findings.</p>;
  }

  const maxCount = Math.max(...entries.map((e) => e.count));
  const fallbackColor = "#6b7280";

  return (
    <div className="space-y-3">
      {entries.map(({ cat, count }) => (
        <div key={cat} className="flex items-center gap-3 text-sm">
          <span
            className="h-2.5 w-2.5 shrink-0 rounded-full"
            style={{ backgroundColor: CATEGORY_COLOR[cat] || fallbackColor }}
          />
          <span className="w-36 truncate font-medium text-gray-700 dark:text-gray-300">
            {CATEGORY_LABEL[cat] || cat}
          </span>
          <div className="relative h-4 flex-1 overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800">
            <div
              className="absolute left-0 top-0 h-full rounded-full"
              style={{
                width: `${(count / maxCount) * 100}%`,
                backgroundColor: CATEGORY_COLOR[cat] || fallbackColor,
              }}
            />
          </div>
          <span className="w-12 text-right tabular-nums text-gray-600 dark:text-gray-400">{count}</span>
        </div>
      ))}
    </div>
  );
}

export function GateBadge({ gate }: { gate: GateInfo }) {
  return gate.failed ? (
    <span className="inline-flex items-center gap-1 rounded-full bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-800 dark:bg-red-900/40 dark:text-red-300">
      ● FAIL <span className="opacity-70">≥ {gate.threshold}</span>
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full bg-green-100 px-2 py-0.5 text-xs font-semibold text-green-800 dark:bg-green-900/40 dark:text-green-300">
      ● PASS <span className="opacity-70">≥ {gate.threshold}</span>
    </span>
  );
}

// SeverityDonut renders a severity distribution as a donut. Empty data shows a
// neutral ring so the panel never collapses.
export function SeverityDonut({ bySeverity }: { bySeverity: Record<string, number> }) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const data = order
    .map((s) => ({ name: s, value: bySeverity[s] || 0, color: SEV_COLOR[s] }))
    .filter((d) => d.value > 0);
  const total = data.reduce((a, d) => a + d.value, 0);

  return (
    <div className="relative h-56">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={total > 0 ? data : [{ name: "none", value: 1, color: "#e5e7eb" }]}
            dataKey="value"
            nameKey="name"
            innerRadius={58}
            outerRadius={84}
            paddingAngle={total > 0 ? 2 : 0}
            stroke="none"
          >
            {(total > 0 ? data : [{ color: "#e5e7eb" }]).map((d, i) => (
              <Cell key={i} fill={d.color} />
            ))}
          </Pie>
          {total > 0 && <Tooltip formatter={(v: number, n: string) => [v, n]} />}
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold tabular-nums">{total}</span>
        <span className="text-xs text-gray-500 dark:text-gray-400">findings</span>
      </div>
    </div>
  );
}

export function Loading({ what }: { what: string }) {
  return <div className="p-8 text-center text-gray-500 dark:text-gray-400">Loading {what}…</div>;
}

export function ErrorNote({ error }: { error: string }) {
  return (
    <div className="m-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
      {error}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="m-6 rounded-xl border border-dashed border-gray-300 p-10 text-center dark:border-gray-700">
      <div className="text-lg font-semibold">{title}</div>
      <p className="mx-auto mt-2 max-w-md text-sm text-gray-500 dark:text-gray-400">{hint}</p>
    </div>
  );
}
