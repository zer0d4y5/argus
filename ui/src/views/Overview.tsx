import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
  Cell,
} from "recharts";
import { SummaryResponse } from "../api";
import { Panel, StatCard, SeverityDonut, GateBadge, EmptyState, CategoryBreakdown } from "../components";
import { OWASP_COLORS, SEV_COLOR, fmtTime } from "../theme";

export function Overview({ summary }: { summary: SummaryResponse }) {
  if (summary.runCount === 0) {
    return (
      <EmptyState
        title="No runs saved yet"
        hint="Run `appsec scan <path> --save` to record a run, then reload. Two or more runs unlock the trend."
      />
    );
  }

  const trend = summary.trend.map((p) => ({
    label: fmtTime(p.createdAt),
    total: p.total,
    critical: p.bySeverity.critical || 0,
    high: p.bySeverity.high || 0,
    risk: p.riskAvg,
  }));

  const owasp = summary.owasp
    .filter((b) => b.count > 0)
    .map((b) => ({ name: `${b.category.id} ${b.category.title}`, count: b.count }));

  const risk = summary.riskBands;
  const riskData = [
    { name: "Low", value: risk.low, color: "#2563eb" },
    { name: "Medium", value: risk.medium, color: "#d97706" },
    { name: "High", value: risk.high, color: "#ea580c" },
    { name: "Critical", value: risk.critical, color: "#b91c1c" },
  ];

  return (
    <div className="space-y-4">
      {/* Headline stats */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total findings" value={summary.total} sub={`latest run · ${fmtTime(summary.createdAt)}`} />
        <StatCard
          label="Critical + High"
          value={(summary.bySeverity.critical || 0) + (summary.bySeverity.high || 0)}
          accent={SEV_COLOR.high}
          sub="severity that trips the gate"
        />
        <StatCard
          label="Gate outcome"
          value={<GateBadge gate={summary.gate} />}
          sub="against configured threshold"
        />
        <StatCard
          label="Triaged FPs"
          value={summary.verdicts.falsePositive}
          sub={`${summary.verdicts.truePositive} TP · ${summary.verdicts.uncertain} uncertain`}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="Severity distribution">
          <SeverityDonut bySeverity={summary.bySeverity} />
          <div className="mt-2 flex flex-wrap justify-center gap-3 text-xs">
            {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
              <span key={s} className="inline-flex items-center gap-1">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: SEV_COLOR[s] }} />
                {s} <span className="tabular-nums text-gray-500">{summary.bySeverity[s] || 0}</span>
              </span>
            ))}
          </div>
        </Panel>

        <Panel title="Findings by category">
          <CategoryBreakdown byCategory={summary.byCategory} />
          <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
            One platform, app code and the infrastructure it runs on: SAST + secrets + dependencies + IaC misconfigurations.
          </p>
        </Panel>

        <Panel title="Risk score bands">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-gray-200 dark:stroke-gray-800" />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {riskData.map((d, i) => (
                    <Cell key={i} fill={d.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            0–10 risk = deterministic baseline ± bounded AI adjustment. Bands: Low &lt;4 · Medium 4–7 · High 7–9 · Critical ≥9.
          </p>
        </Panel>
      </div>

      <Panel title="Trend across runs">
        {trend.length < 2 ? (
          <p className="py-8 text-center text-sm text-gray-500 dark:text-gray-400">
            Save a second run to see the trend line.
          </p>
        ) : (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ top: 8, right: 12, bottom: 0, left: -16 }}>
                <defs>
                  <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#2563eb" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#2563eb" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" className="stroke-gray-200 dark:stroke-gray-800" />
                <XAxis dataKey="label" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Area type="monotone" dataKey="total" stroke="#2563eb" fill="url(#gTotal)" strokeWidth={2} name="total" />
                <Area type="monotone" dataKey="critical" stroke={SEV_COLOR.critical} fill="none" strokeWidth={2} name="critical" />
                <Area type="monotone" dataKey="high" stroke={SEV_COLOR.high} fill="none" strokeWidth={2} name="high" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </Panel>

      <Panel title="OWASP Top 10 (2021) rollup">
        {owasp.length === 0 ? (
          <p className="py-6 text-center text-sm text-gray-500">No categorized findings.</p>
        ) : (
          <div style={{ height: Math.max(180, owasp.length * 34) }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={owasp} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} className="stroke-gray-200 dark:stroke-gray-800" />
                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12 }} />
                <YAxis type="category" dataKey="name" width={210} tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {owasp.map((_, i) => (
                    <Cell key={i} fill={OWASP_COLORS[i % OWASP_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
          Computed from finding CWEs at report time (not written into the model).
        </p>
      </Panel>
    </div>
  );
}
