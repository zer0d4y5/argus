import { ReactNode } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { Severity, GateInfo } from "./api";
import { SEV_CHIP, SEV_COLOR, CATEGORY_CHIP, CATEGORY_LABEL, CATEGORY_COLOR } from "./theme";

// Logo is the Argus mark: the all-seeing eye (Argus Panoptes, the hundred-eyed
// watchman) set in a hexagonal security badge. Inline SVG (no asset fetch,
// CSP-safe), sized by the `size` prop. The favicon in index.html is the same
// mark — keep the two in sync. Fixed brand colors (indigo iris ramp) so it
// reads identically on light and dark.
export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" className="shrink-0">
      <defs>
        <linearGradient id="argus-badge" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#6b74e0" />
          <stop offset="1" stopColor="#363b8f" />
        </linearGradient>
        <radialGradient id="argus-iris" cx="0.42" cy="0.36" r="0.75">
          <stop offset="0" stopColor="#8b93ef" />
          <stop offset="1" stopColor="#3a3f9e" />
        </radialGradient>
      </defs>
      {/* hexagonal badge (rounded via round-join stroke) */}
      <path d="M21 12 16.5 19.79 7.5 19.79 3 12 7.5 4.21 16.5 4.21Z" fill="url(#argus-badge)" stroke="#363b8f" strokeWidth="1.4" strokeLinejoin="round" />
      {/* the eye */}
      <path d="M6.3 12C8.8 7.8 15.2 7.8 17.7 12 15.2 16.2 8.8 16.2 6.3 12Z" fill="#fff" />
      <circle cx="12" cy="12" r="3.75" fill="none" stroke="#4b53c4" strokeWidth="0.5" opacity="0.4" />
      <circle cx="12" cy="12" r="2.9" fill="url(#argus-iris)" />
      <circle cx="12" cy="12" r="1.2" fill="#0d0e26" />
      <circle cx="13" cy="10.95" r="0.58" fill="#fff" />
    </svg>
  );
}

// Wordmark is the Logo + "Argus" name, used in the header and the login
// page so the brand is one component, not a scattered string.
export function Wordmark({ size = 22, className = "" }: { size?: number; className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <Logo size={size} />
      <span className="font-bold tracking-tight">Argus</span>
    </span>
  );
}

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
  const order = ["SAST", "SECRET", "SCA", "IAC", "DAST", "CLOUD"];
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
  const suppressed = gate.suppressed ?? 0;
  const suffix = suppressed > 0
    ? <span className="opacity-70" title="findings excluded from the gate by accepted-risk / false-positive disposition">· {suppressed} accepted</span>
    : null;
  return gate.failed ? (
    <span className="inline-flex items-center gap-1 rounded-full bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-800 dark:bg-red-900/40 dark:text-red-300">
      ● FAIL <span className="opacity-70">≥ {gate.threshold}</span> {suffix}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full bg-green-100 px-2 py-0.5 text-xs font-semibold text-green-800 dark:bg-green-900/40 dark:text-green-300">
      ● PASS <span className="opacity-70">≥ {gate.threshold}</span> {suffix}
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

// Skeleton is a single shimmering placeholder block. Compose them into a
// content-shaped skeleton so a loading view keeps the layout it will fill.
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} />;
}

// ConsoleSkeleton stands in for the whole app shell while the first payload
// loads: a header bar, a row of stat tiles, and a couple of panels, so the boot
// reads as "arriving" rather than a bare "Loading…" line.
export function ConsoleSkeleton() {
  return (
    <div className="mx-auto min-h-full max-w-7xl px-4 pb-16" aria-busy="true" aria-label="Loading console">
      <div className="mb-6 flex items-center gap-3 py-3">
        <Skeleton className="h-6 w-24" />
        <Skeleton className="h-6 w-64" />
        <Skeleton className="ml-auto h-6 w-40" />
      </div>
      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="rounded-xl border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="mt-3 h-8 w-16" />
            <Skeleton className="mt-3 h-3 w-32" />
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {[0, 1, 2].map((i) => (
          <div key={i} className="rounded-xl border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900">
            <Skeleton className="h-3 w-32" />
            <Skeleton className="mt-4 h-40 w-full" />
          </div>
        ))}
      </div>
    </div>
  );
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
