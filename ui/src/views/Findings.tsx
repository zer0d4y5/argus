import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { FixedSizeList, ListChildComponentProps } from "react-window";
import { api, CoverageAccounting, Disposition, DispositionStatus, ExplainResponse, Finding, locationLabel, Mitigation, opsApi, RemediationArtifact, RemediationResponse, RiskSignal, RunDetail, Severity, SEVERITIES, ValidationResponse } from "../api";
import { Panel, SeverityBadge, CategoryBadge, EmptyState } from "../components";
import { SidePane } from "../SidePane";
import { CloudRemediationPanel } from "./CloudRemediationPanel";
import { exportFindingsCSV, exportFindingsJSON } from "../export";
import { useToast } from "../toast";
import { DISPOSITION_CHIP, DISPOSITION_LABEL, VERDICT_CHIP, VERDICT_LABEL, riskColor } from "../theme";

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// One neutral style for every drawer action button — the theme, not a rainbow.
const ACTION_BTN =
  "rounded-md border border-gray-300 px-2.5 py-1 text-sm font-medium text-gray-700 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800";

// Section is a labeled block in the finding drawer, so the detail reads as
// Details / Compliance / Fix / Triage instead of one wall of text.
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-gray-200 pt-3 dark:border-gray-800">
      <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-gray-400">{title}</h4>
      <div className="space-y-2">{children}</div>
    </section>
  );
}

// Per-finding explain/remediate lifecycles; cached client-side so re-clicks don't refetch.
type ExplainState = { loading: boolean; data?: ExplainResponse; error?: string };
type RemediateState = { loading: boolean; data?: RemediationResponse; error?: string };
type ValidateState = { loading: boolean; data?: ValidationResponse; error?: string };

// CoverageStrip renders the run's skip accounting (schema 2.0.0): what the
// scan did NOT look at. "No findings" over a tree of unscanned binaries is a
// different claim than over a fully-analyzable tree — keep the difference
// visible. Absent on pre-2.0.0 runs (feature-detected by the caller).
// Sample paths are hostile data: rendered as escaped text only.
function CoverageStrip({ cov }: { cov: CoverageAccounting }) {
  const skipped = cov.unsupportedSource + cov.binary + cov.oversize + cov.unreadable;
  const cells: Array<{ label: string; value: number; title: string; warn?: boolean }> = [
    { label: "files", value: cov.filesTotal, title: "Regular files walked (excluding .git and .appsec)" },
    { label: "SAST-covered", value: cov.sastCovered, title: "Source files in languages the semgrep profiles analyze" },
    { label: "IaC / config", value: cov.iacConfig, title: "IaC, manifest and config files the IaC/SCA scanners parse" },
    { label: "secrets-only", value: cov.secretsOnly, title: "Other text: the secret scanner reads it; no static analyzer does" },
    { label: "unsupported source", value: cov.unsupportedSource, title: "Recognizable code in a language no profile analyzes — secrets-only coverage", warn: true },
    { label: "binary", value: cov.binary, title: "Binary files: no scanner analyzes their content", warn: true },
    { label: `oversize (>${Math.round(cov.oversizeLimitBytes / 1048576)} MB)`, value: cov.oversize, title: "Files too large for static analysis — effectively unscanned", warn: true },
    { label: "unreadable", value: cov.unreadable, title: "Stat/open failures during the walk", warn: true },
  ];
  const samples = [
    ...(cov.unsupportedSample ?? []),
    ...(cov.binarySample ?? []),
    ...(cov.oversizeSample ?? []),
  ];
  return (
    <Panel title="Scan coverage">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
        {cells.map((c) =>
          c.value === 0 && c.warn ? null : (
            <span key={c.label} title={c.title} className="inline-flex items-center gap-1">
              <span className={`tabular-nums font-semibold ${c.warn ? "text-amber-600 dark:text-amber-400" : ""}`}>{c.value}</span>
              <span className="text-gray-500 dark:text-gray-400">{c.label}</span>
            </span>
          ),
        )}
        {cov.gitRepo && (
          <span
            className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px] uppercase text-gray-600 dark:bg-gray-800 dark:text-gray-300"
            title={cov.gitShallow ? "Shallow clone: secret history coverage is the single fetched commit" : "Git repository: the secret scanner also scanned commit history"}
          >
            git history{cov.gitShallow ? " (shallow)" : ""}
          </span>
        )}
      </div>
      {skipped > 0 && samples.length > 0 && (
        <p className="mt-2 break-all text-[12px] text-gray-500 dark:text-gray-400">
          e.g. {samples.slice(0, 6).join(" · ")}
        </p>
      )}
    </Panel>
  );
}

// Column grid shared by the list header and every virtualized row so they line
// up. The leading 2rem checkbox column is present only when the user can triage.
function listColumns(canDispose: boolean): string {
  return `${canDispose ? "2rem " : ""}3.5rem 5rem minmax(0,1fr) 6rem`;
}

// FINDING_ROW_H is the fixed row height react-window positions against; it must
// fit the two text lines (title + location) plus padding.
const FINDING_ROW_H = 56;

type RowData = {
  items: Finding[];
  columns: string;
  selectedId: string | null;
  selectedIds: Set<string>;
  canDispose: boolean;
  newSet: Set<string>;
  dispositions: Record<string, { status: string }>;
  onSelect: (id: string) => void;
  onToggle: (id: string) => void;
};

// FindingRow renders one virtualized row. react-window supplies `style` with the
// absolute position; we merge the grid template into it.
function FindingRow({ index, style, data }: ListChildComponentProps<RowData>) {
  const f = data.items[index];
  const isSel = f.id === data.selectedId;
  const disp = data.dispositions[f.id];
  return (
    <div
      id={`finding-row-${f.id}`}
      onClick={() => data.onSelect(f.id)}
      style={{ ...style, gridTemplateColumns: data.columns }}
      className={`grid cursor-pointer items-center gap-x-2 border-t border-gray-100 px-3 text-sm dark:border-gray-800/70 ${
        isSel ? "bg-accent-100 dark:bg-accent-500/10" : "hover:bg-gray-50 dark:hover:bg-gray-800/50"
      }`}
    >
      {data.canDispose && (
        <span onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            checked={data.selectedIds.has(f.id)}
            onChange={() => data.onToggle(f.id)}
            aria-label="Select finding"
            className="cursor-pointer"
          />
        </span>
      )}
      <span>
        <RiskPill score={f.riskScore} />
      </span>
      <span>
        <SeverityBadge severity={f.severity} />
      </span>
      <span className="min-w-0">
        <span className="flex min-w-0 items-center gap-2">
          {data.newSet.has(f.id) && (
            <span className="shrink-0 rounded bg-emerald-100 px-1 text-[11px] font-bold text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-300">
              NEW
            </span>
          )}
          {disp?.status === "fixed" && (
            <span className="shrink-0 rounded bg-red-100 px-1 text-[11px] font-bold text-red-700 dark:bg-red-900/50 dark:text-red-300" title="Marked fixed but still detected — a regression">
              REGRESSED
            </span>
          )}
          {disp && disp.status !== "fixed" && (
            <span className={`shrink-0 rounded px-1 text-[11px] font-semibold ${DISPOSITION_CHIP[disp.status]}`}>
              {DISPOSITION_LABEL[disp.status]}
            </span>
          )}
          <span className="truncate text-sm font-medium">{f.displayName ?? f.title}</span>
        </span>
        <span className="flex min-w-0 items-center gap-1.5 text-[12px] text-gray-400">
          <CategoryBadge category={f.category} compact />
          <span className="truncate">{locationLabel(f.location)}</span>
        </span>
      </span>
      <span>
        {f.triage ? (
          <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${VERDICT_CHIP[f.triage.verdict]}`}>
            {VERDICT_LABEL[f.triage.verdict]}
          </span>
        ) : (
          <span className="text-[12px] text-gray-400">—</span>
        )}
      </span>
    </div>
  );
}

export function Findings({
  detail,
  origin,
  canExplain,
  canRemediate,
  canSuppress,
  onSuppress,
  framework,
  onFrameworkChange,
  severity,
  onSeverityChange,
  status,
  onStatusChange,
  openItem,
  onOpenItemChange,
}: {
  detail: RunDetail;
  origin?: {
    targetId?: string;
    gitUrl?: string;
    commit?: string;
  };
  canExplain?: boolean;
  canRemediate?: boolean;
  canSuppress?: boolean;
  onSuppress?: (ruleId: string) => void;
  // These filters are controlled by App so the Overview panels can deep-link
  // into a filtered Findings view (drill-down on any stat).
  framework: string;
  onFrameworkChange: (v: string) => void;
  severity: string;
  onSeverityChange: (v: string) => void;
  status: string;
  onStatusChange: (v: string) => void;
  // When provided, the open pane item is controlled by App and lives in the
  // URL (?item=…) so a pane is shareable and reload-safe. Absent (e.g. inside
  // RunDetailView) the pane state stays local and ephemeral.
  openItem?: string;
  onOpenItemChange?: (v: string) => void;
}) {
  const [q, setQ] = useState("");
  const sev = severity, setSev = onSeverityChange;
  const [cat, setCat] = useState<string>("all");
  const [tool, setTool] = useState<string>("all");
  const [verdict, setVerdict] = useState<string>("all");
  const setStatus = onStatusChange;
  const [minRisk, setMinRisk] = useState(0);
  const [newOnly, setNewOnly] = useState(false);
  const [localItem, setLocalItem] = useState<string | null>(null);
  const selectedId = openItem !== undefined ? openItem || null : localItem;
  const setSelectedId = (id: string | null) => {
    if (onOpenItemChange) onOpenItemChange(id ?? "");
    else setLocalItem(id);
  };

  // A "clear filters" affordance — especially useful after deep-linking in
  // from an Overview stat, which sets a filter for you.
  const activeCount = [sev !== "all", cat !== "all", tool !== "all", verdict !== "all", status !== "all", framework !== "all", minRisk > 0, newOnly, q.trim() !== ""].filter(Boolean).length;
  const filtersActive = activeCount > 0;
  const clearFilters = () => {
    setQ(""); setSev("all"); setCat("all"); setTool("all"); setVerdict("all");
    setStatus("all"); onFrameworkChange("all"); setMinRisk(0); setNewOnly(false);
  };

  // Local, optimistic overlay of finding dispositions seeded from the run
  // detail; re-seeded when the run changes. Operator+ can set/clear. A finding
  // with status "fixed" that is still present in this run is a REGRESSION.
  const toast = useToast();
  const canDispose = !!canExplain; // operator+, same gate as explain/remediate
  const [dispositions, setDispositions] = useState<Record<string, Disposition>>(detail.dispositions ?? {});
  useEffect(() => { setDispositions(detail.dispositions ?? {}); }, [detail.id, detail.dispositions]);
  const setDisposition = async (findingId: string, s: DispositionStatus, note: string) => {
    try {
      const rec = await opsApi.setDisposition({ targetId: origin?.targetId, findingId, status: s, note });
      setDispositions((prev) => ({ ...prev, [findingId]: rec }));
      toast({ kind: "success", message: `Marked ${DISPOSITION_LABEL[s].toLowerCase()}.` });
    } catch (e) {
      toast({ kind: "error", message: `Could not set disposition: ${String(e)}` });
    }
  };
  const clearDisposition = async (findingId: string) => {
    try {
      await opsApi.clearDisposition(findingId, origin?.targetId);
      setDispositions((prev) => { const next = { ...prev }; delete next[findingId]; return next; });
      toast({ kind: "success", message: "Disposition cleared (back to open)." });
    } catch (e) {
      toast({ kind: "error", message: `Could not clear disposition: ${String(e)}` });
    }
  };

  // Multi-select for bulk actions. Cleared when the run changes.
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  useEffect(() => { setSelectedIds(new Set()); }, [detail.id]);
  const toggleSelect = (id: string) =>
    setSelectedIds((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const bulkDispose = async (status?: DispositionStatus) => {
    const ids = [...selectedIds];
    if (!ids.length) return;
    try {
      await opsApi.bulkDisposition({ targetId: origin?.targetId, findingIds: ids, status });
      setDispositions((prev) => {
        const next = { ...prev };
        for (const id of ids) {
          if (status) next[id] = { findingId: id, status, actor: "", updatedAt: new Date().toISOString() };
          else delete next[id];
        }
        return next;
      });
      toast({ kind: "success", message: status ? `Marked ${ids.length} as ${DISPOSITION_LABEL[status].toLowerCase()}.` : `Cleared ${ids.length}.` });
      setSelectedIds(new Set());
    } catch (e) {
      toast({ kind: "error", message: `Bulk update failed: ${String(e)}` });
    }
  };

  // Open a ticket over the current selection — the payoff loop: findings become
  // tracked work in one step, linked by fingerprint to this target. The title
  // seeds from the first selected finding; rename it in the Tickets tab (no
  // blocking browser prompt, per the console's no-native-dialog rule).
  const createTicketFromSelection = async () => {
    const ids = [...selectedIds];
    if (!ids.length) return;
    const first = filtered.find((f) => selectedIds.has(f.id));
    const seed = first?.displayName ?? first?.title ?? "findings";
    const title = ids.length === 1 ? seed : `${seed} (+${ids.length - 1} more)`;
    try {
      const t = await opsApi.createTicket({ title, targetId: origin?.targetId ?? "", findingIds: ids });
      toast({ kind: "success", message: `Ticket ${t.id} created with ${ids.length} finding${ids.length === 1 ? "" : "s"}. Open Tickets to edit.` });
      setSelectedIds(new Set());
    } catch (e) {
      toast({ kind: "error", message: `Create ticket failed: ${String(e)}` });
    }
  };

  // Explain + remediate lifecycles, per finding (cached client-side).
  const [explainState, setExplainState] = useState<Record<string, ExplainState>>({});
  const [remediateState, setRemediateState] = useState<Record<string, RemediateState>>({});
  const [validateState, setValidateState] = useState<Record<string, ValidateState>>({});

  const newSet = useMemo(() => new Set(detail.newIds), [detail.newIds]);
  const tools = useMemo(
    () => Array.from(new Set(detail.findings.flatMap((f) => f.tools ?? [f.tool]))).sort(),
    [detail.findings],
  );
  const cats = useMemo(
    () => Array.from(new Set(detail.findings.map((f) => f.category))).sort(),
    [detail.findings],
  );

  // Framework filter options: distinct prefixes from complianceControls
  const frameworks = useMemo(() => {
    const set = new Set<string>();
    detail.findings.forEach((f) => {
      if (f.complianceControls) {
        f.complianceControls.forEach((c) => {
          const idx = c.indexOf(":");
          if (idx !== -1) set.add(c.slice(0, idx));
        });
      }
    });
    return Array.from(set).sort();
  }, [detail.findings]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return detail.findings
      .filter((f) => sev === "all" || f.severity === sev)
      .filter((f) => cat === "all" || f.category === cat)
      .filter((f) => tool === "all" || (f.tools ?? [f.tool]).includes(tool))
      .filter((f) => verdict === "all" || (verdict === "untriaged" ? !f.triage : f.triage?.verdict === verdict))
      .filter((f) => (f.riskScore ?? 0) >= minRisk)
      .filter((f) => !newOnly || newSet.has(f.id))
      .filter((f) => framework === "all" || (f.complianceControls ?? []).some((c) => c.startsWith(framework + ":")))
      .filter((f) => {
        if (status === "all") return true;
        const st = dispositions[f.id]?.status;
        if (status === "open") return !st;
        if (status === "regression") return st === "fixed"; // fixed but still present
        return st === status;
      })
      .filter(
        (f) =>
          needle === "" ||
          f.title.toLowerCase().includes(needle) ||
          (f.description ?? "").toLowerCase().includes(needle) ||
          (f.location.file ?? "").toLowerCase().includes(needle) ||
          (f.location.resource ?? "").toLowerCase().includes(needle) ||
          f.ruleId.toLowerCase().includes(needle) ||
          (f.cwes ?? []).some((c) => c.toLowerCase().includes(needle)),
      )
      .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0) || SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  }, [detail.findings, q, sev, cat, tool, verdict, minRisk, newOnly, newSet, framework, status, dispositions]);

  // No first-row fallback: the detail pane is closed until a row is opened.
  const selected = filtered.find((f) => f.id === selectedId) ?? null;

  const allSelected = filtered.length > 0 && filtered.every((f) => selectedIds.has(f.id));
  const toggleSelectAll = () =>
    setSelectedIds((prev) => {
      const n = new Set(prev);
      if (filtered.every((f) => n.has(f.id))) filtered.forEach((f) => n.delete(f.id));
      else filtered.forEach((f) => n.add(f.id));
      return n;
    });

  // The list virtualizes (react-window) so a 5,000-finding run renders only the
  // rows on screen. It needs a pixel height, so measure the container.
  const listBoxRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<FixedSizeList>(null);
  const [listHeight, setListHeight] = useState(480);
  useEffect(() => {
    const el = listBoxRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setListHeight(el.clientHeight));
    ro.observe(el);
    setListHeight(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  // Keyboard navigation: ↑/↓ or j/k move the selection through the visible
  // list; x toggles it into the multi-select. Ignored while typing in a field.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || !filtered.length) return;
      const idx = filtered.findIndex((f) => f.id === selected?.id);
      let nextIdx = idx;
      if (e.key === "ArrowDown" || e.key === "j") nextIdx = Math.min(idx + 1, filtered.length - 1);
      else if (e.key === "ArrowUp" || e.key === "k") nextIdx = Math.max(idx - 1, 0);
      else if (e.key === "x" && selected) { toggleSelect(selected.id); e.preventDefault(); return; }
      else return;
      e.preventDefault();
      const next = filtered[nextIdx];
      if (next) {
        setSelectedId(next.id);
        // scrollToItem, not scrollIntoView: a virtualized row may not be in the
        // DOM until the list scrolls to it.
        listRef.current?.scrollToItem(nextIdx, "smart");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [filtered, selected]);

  const handleExplain = async (f: Finding) => {
    if (!canExplain) return;
    setExplainState((prev) => ({
      ...prev,
      [f.id]: { loading: true, data: prev[f.id]?.data },
    }));
    try {
      const res = await opsApi.explain({ targetId: origin?.targetId, runId: detail.id, findingId: f.id });
      setExplainState((prev) => ({ ...prev, [f.id]: { loading: false, data: res } }));
    } catch (err) {
      const msg = err instanceof Error ? err.message : "explanation failed";
      setExplainState((prev) => ({ ...prev, [f.id]: { loading: false, error: msg } }));
    }
  };

  const handleRemediate = async (f: Finding) => {
    if (!canExplain) return; // remediation is the same operator+ gate as explain
    setRemediateState((prev) => ({ ...prev, [f.id]: { loading: true, data: prev[f.id]?.data } }));
    try {
      const res = await opsApi.remediate({ targetId: origin?.targetId, runId: detail.id, findingId: f.id });
      setRemediateState((prev) => ({ ...prev, [f.id]: { loading: false, data: res } }));
    } catch (err) {
      const msg = err instanceof Error ? err.message : "remediation failed";
      setRemediateState((prev) => ({ ...prev, [f.id]: { loading: false, error: msg } }));
    }
  };

  const handleValidate = async (f: Finding) => {
    if (!canExplain) return; // operator+ gate, same as explain/remediate
    setValidateState((prev) => ({ ...prev, [f.id]: { loading: true, data: prev[f.id]?.data } }));
    try {
      const res = await opsApi.validate({ targetId: origin?.targetId, runId: detail.id, findingId: f.id });
      setValidateState((prev) => ({ ...prev, [f.id]: { loading: false, data: res } }));
    } catch (err) {
      const msg = err instanceof Error ? err.message : "validation failed";
      setValidateState((prev) => ({ ...prev, [f.id]: { loading: false, error: msg } }));
    }
  };

  if (detail.findings.length === 0) {
    return (
      <div className="space-y-4">
        {detail.coverage && <CoverageStrip cov={detail.coverage} />}
        <EmptyState title="No findings in this run" hint="This run recorded a clean scan. Nice." />
      </div>
    );
  }

  return (
    <div className="space-y-4">
    {detail.coverage && <CoverageStrip cov={detail.coverage} />}
    <div>
      {/* Full-width list; the detail opens in a right-anchored SidePane (below)
          so the list stays visible and keyboard-navigable while it's open. */}
      <div className="min-w-0">
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
            <Select
              value={status}
              onChange={setStatus}
              label="Status"
              options={["all", "open", "in-progress", "accepted-risk", "false-positive", "fixed", "regression"]}
            />
            <Select
              value={framework}
              onChange={onFrameworkChange}
              label="Framework"
              // Include the externally-set framework even if this run has no
              // finding mapped to it, so a deep-link never shows a blank Select.
              options={["all", ...(framework !== "all" && !frameworks.includes(framework) ? [framework] : []), ...frameworks]}
            />
            <label className="inline-flex items-center gap-1 text-sm text-gray-500">
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
            {detail.baselineId !== "" && (
              <label className="inline-flex items-center gap-1.5 self-center text-sm text-gray-600 dark:text-gray-300" title="Show only findings new since the baseline">
                <input type="checkbox" checked={newOnly} onChange={(e) => setNewOnly(e.target.checked)} className="cursor-pointer" />
                New only
              </label>
            )}
            {filtersActive && (
              <button
                onClick={clearFilters}
                className="inline-flex items-center gap-1 self-center rounded-md border border-gray-300 px-2 py-1 text-sm text-gray-600 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
                title="Reset all filters"
              >
                ✕ Clear filters ({activeCount})
              </button>
            )}
            <span className="ml-auto flex items-center gap-1 self-center text-sm">
              <span className="text-gray-400">Export {filtered.length}</span>
              <button onClick={() => exportFindingsCSV(filtered)} className="rounded-md border border-gray-300 px-1.5 py-1 font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800" title="Export the filtered findings as CSV">CSV</button>
              <button onClick={() => exportFindingsJSON(filtered)} className="rounded-md border border-gray-300 px-1.5 py-1 font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800" title="Export the filtered findings as JSON">JSON</button>
              <a
                href={api.exportUrl(detail.id, "html", origin?.targetId)}
                target="_blank"
                rel="noopener"
                className="inline-flex items-center gap-1 rounded-md border border-accent-200 bg-accent-50 px-2 py-1 font-medium text-accent-700 hover:bg-accent-100 dark:border-accent-800 dark:bg-accent-500/10 dark:text-accent-300 dark:hover:bg-accent-500/20"
                title="Open a professional report for this run (print to PDF from the browser)"
              >
                ↗ Report
              </a>
            </span>
          </div>

          {/* Bulk action bar: one locked write across the selection. */}
          {canDispose && selectedIds.size > 0 && (
            <div className="mb-2 flex flex-wrap items-center gap-1.5 rounded-md bg-accent-50 px-3 py-2 text-sm dark:bg-accent-500/10">
              <span className="font-semibold text-accent-800 dark:text-accent-200">{selectedIds.size} selected</span>
              <span className="ml-1 text-gray-500">set</span>
              {(["in-progress", "accepted-risk", "false-positive", "fixed"] as DispositionStatus[]).map((s) => (
                <button
                  key={s}
                  onClick={() => bulkDispose(s)}
                  className={`rounded px-1.5 py-0.5 font-semibold ${DISPOSITION_CHIP[s]}`}
                >
                  {DISPOSITION_LABEL[s]}
                </button>
              ))}
              <button onClick={() => bulkDispose(undefined)} className="rounded bg-gray-200 px-1.5 py-0.5 font-semibold text-gray-600 hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-300">
                Open
              </button>
              <span className="mx-1 h-4 w-px bg-gray-300 dark:bg-gray-600" />
              <button onClick={createTicketFromSelection} className="rounded bg-accent-600 px-1.5 py-0.5 font-semibold text-white hover:bg-accent-700">
                Create ticket
              </button>
              <span className="mx-1 h-4 w-px bg-gray-300 dark:bg-gray-600" />
              <span className="text-gray-500">export</span>
              <button onClick={() => exportFindingsCSV(filtered.filter((f) => selectedIds.has(f.id)), "argus-selection")} className="rounded bg-gray-200 px-1.5 py-0.5 font-semibold text-gray-600 hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-300">CSV</button>
              <button onClick={() => exportFindingsJSON(filtered.filter((f) => selectedIds.has(f.id)), "argus-selection")} className="rounded bg-gray-200 px-1.5 py-0.5 font-semibold text-gray-600 hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-300">JSON</button>
              <button onClick={() => setSelectedIds(new Set())} className="ml-auto text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                Deselect
              </button>
            </div>
          )}

          {/* Header row, its columns matched to the virtualized rows below so a
              long title/ARN truncates inside its cell instead of widening the
              list into the detail pane. */}
          <div
            className="grid items-center gap-x-2 border-b border-gray-200 px-3 py-2 text-sm uppercase text-gray-500 dark:border-gray-800 dark:text-gray-400"
            style={{ gridTemplateColumns: listColumns(canDispose) }}
          >
            {canDispose && (
              <input
                type="checkbox"
                checked={allSelected}
                onChange={toggleSelectAll}
                aria-label="Select all visible findings"
                className="cursor-pointer"
              />
            )}
            <span>Risk</span>
            <span>Sev</span>
            <span>Title</span>
            <span>Verdict</span>
          </div>
          {/* Virtualized body: only the on-screen rows render, so a 5,000-finding
              run stays smooth. The fixed-height box lets react-window measure. */}
          <div ref={listBoxRef} className="h-[62vh]">
            {filtered.length === 0 ? (
              <div className="py-12 text-center text-sm text-gray-500">
                {detail.findings.length === 0 ? (
                  "No findings in this run."
                ) : (
                  <>
                    No findings match these filters.{" "}
                    <button onClick={clearFilters} className="font-medium text-accent-600 hover:underline dark:text-accent-400">
                      Clear filters
                    </button>
                  </>
                )}
              </div>
            ) : (
              <FixedSizeList
                ref={listRef}
                height={listHeight}
                width="100%"
                itemCount={filtered.length}
                itemSize={FINDING_ROW_H}
                className="scroll-thin"
                itemData={{
                  items: filtered,
                  columns: listColumns(canDispose),
                  selectedId: selected?.id ?? null,
                  selectedIds,
                  canDispose,
                  newSet,
                  dispositions,
                  onSelect: setSelectedId,
                  onToggle: toggleSelect,
                }}
              >
                {FindingRow}
              </FixedSizeList>
            )}
          </div>
        </Panel>
      </div>

    </div>

      {/* Detail: a Datadog-style right-anchored pane. Opens on row click or
          keyboard nav; the list stays live underneath. */}
      <SidePane
        open={!!selected}
        onClose={() => setSelectedId(null)}
        title={null}
        onPrev={(() => {
          const idx = filtered.findIndex((f) => f.id === selected?.id);
          if (idx <= 0) return null;
          return () => { setSelectedId(filtered[idx - 1].id); listRef.current?.scrollToItem(idx - 1, "smart"); };
        })()}
        onNext={(() => {
          const idx = filtered.findIndex((f) => f.id === selected?.id);
          if (idx < 0 || idx >= filtered.length - 1) return null;
          return () => { setSelectedId(filtered[idx + 1].id); listRef.current?.scrollToItem(idx + 1, "smart"); };
        })()}
        actions={selected ? (
          <span className="flex items-center gap-1 text-[12px]">
            <span className="text-gray-400">Export</span>
            <button onClick={() => exportFindingsCSV([selected])} className="rounded border border-gray-300 px-1.5 py-0.5 font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800">CSV</button>
            <button onClick={() => exportFindingsJSON([selected])} className="rounded border border-gray-300 px-1.5 py-0.5 font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800">JSON</button>
          </span>
        ) : undefined}
      >
        {selected && (
          <div className="p-4">
            <Detail f={selected} isNew={newSet.has(selected.id)} origin={origin} runId={detail.id} canRemediate={canRemediate} canExplain={canExplain} explainState={explainState[selected.id]} onExplain={() => handleExplain(selected)} remediateState={remediateState[selected.id]} onRemediate={() => handleRemediate(selected)} validateState={validateState[selected.id]} onValidate={() => handleValidate(selected)} canSuppress={canSuppress} onSuppress={onSuppress} disposition={dispositions[selected.id]} canDispose={canDispose} onDispose={(s, n) => setDisposition(selected.id, s, n)} onClearDispose={() => clearDisposition(selected.id)} />
          </div>
        )}
      </SidePane>
    </div>
  );
}

function Detail({ f, isNew, origin, runId, canRemediate, canExplain, explainState, onExplain, remediateState, onRemediate, validateState, onValidate, canSuppress, onSuppress, disposition, canDispose, onDispose, onClearDispose }: {
  f: Finding;
  isNew: boolean;
  origin?: { targetId?: string; gitUrl?: string; commit?: string };
  runId: string;
  canRemediate?: boolean;
  canExplain?: boolean;
  explainState?: ExplainState;
  onExplain: () => void;
  remediateState?: RemediateState;
  onRemediate: () => void;
  validateState?: ValidateState;
  onValidate: () => void;
  canSuppress?: boolean;
  onSuppress?: (ruleId: string) => void;
  disposition?: Disposition;
  canDispose?: boolean;
  onDispose: (status: DispositionStatus, note: string) => void;
  onClearDispose: () => void;
}) {
  // Forge deep link logic
  let forgeLink = null;
  if (origin?.gitUrl && origin?.commit && f.location.file) {
    try {
      const urlObj = new URL(origin.gitUrl);
      if (urlObj.hostname === "github.com" || urlObj.hostname === "gitlab.com") {
        // The link needs a repo-relative path: strip the server workspace
        // prefix when present; a bare absolute path can't be mapped — no link.
        let relativeFile: string | null = f.location.file;
        const marker = origin.targetId ? `/workspace/${origin.targetId}/` : null;
        if (marker && relativeFile.includes(marker)) {
          relativeFile = relativeFile.slice(relativeFile.indexOf(marker) + marker.length);
        } else if (relativeFile.startsWith("/")) {
          relativeFile = null;
        }

        const gitUrlClean = origin.gitUrl.replace(/\.git$/, "");
        let href = "";
        if (relativeFile === null) {
          href = "";
        } else if (urlObj.hostname === "github.com") {
          href = `${gitUrlClean}/blob/${origin.commit}/${relativeFile}#L${f.location.startLine ?? ""}`;
        } else if (urlObj.hostname === "gitlab.com") {
          href = `${gitUrlClean}/-/blob/${origin.commit}/${relativeFile}#L${f.location.startLine ?? ""}`;
        }
        
        if (href) {
          forgeLink = { href, shortSha: origin.commit.slice(0, 8) };
        }
      }
    } catch {
      // Invalid URL, ignore
    }
  }

  // Group compliance controls by framework
  const groupedControls: Record<string, string[]> = {};
  if (f.complianceControls) {
    f.complianceControls.forEach((c) => {
      const idx = c.indexOf(":");
      if (idx !== -1) {
        const fw = c.slice(0, idx);
        if (!groupedControls[fw]) groupedControls[fw] = [];
        groupedControls[fw].push(c);
      }
    });
  }

  // CWE links helper
  const renderCwe = (cwe: string) => {
    const match = cwe.match(/^CWE-(\d+)$/);
    if (match) {
      return (
        <a
          key={cwe}
          href={`https://cwe.mitre.org/data/definitions/${match[1]}.html`}
          target="_blank"
          rel="noreferrer"
          className="rounded bg-gray-100 px-1.5 py-0.5 text-sm hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 cursor-pointer"
        >
          {cwe}
        </a>
      );
    }
    return (
      <span key={cwe} className="rounded bg-gray-100 px-1.5 py-0.5 text-sm dark:bg-gray-800">
        {cwe}
      </span>
    );
  };

  return (
    <Panel title="Finding detail">
      <div className="space-y-3 text-sm">
        {/* Header: what you're viewing and where it sits in severity. */}
        <div>
          <h3 className="break-words text-base font-semibold">{f.displayName ?? f.title}</h3>
          <p className="break-words font-mono text-[12px] text-gray-400">{f.displayName ? f.title : f.ruleId}{f.displayName && f.ruleId ? ` · ${f.ruleId}` : ""}</p>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <CategoryBadge category={f.category} />
            <RiskPill score={f.riskScore} />
            {f.toolSeverity && f.toolSeverity !== f.severity && (
              <span className="rounded border border-gray-300 px-1.5 py-0.5 text-[11px] uppercase text-gray-500 dark:border-gray-700 dark:text-gray-400" title="Severity is banded from the deterministic risk score; this is what the tool itself reported.">tool said: {f.toolSeverity}</span>
            )}
            {f.meta?.gitHistory === "true" && (
              <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[11px] font-bold text-amber-800 dark:bg-amber-900/50 dark:text-amber-300" title="Found in git history, not the current worktree — rotate the credential; deleting the file does not revoke it.">GIT HISTORY{f.meta?.gitShallow === "true" ? " (shallow)" : ""}</span>
            )}
            {isNew && <span className="rounded bg-emerald-100 px-1.5 text-[11px] font-bold text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-300">NEW</span>}
            <span className="text-sm text-gray-400">{(f.tools ?? [f.tool]).join(", ")}</span>
          </div>
        </div>

        <Section title="Details">
          {f.description && <p className="whitespace-pre-wrap break-words text-gray-600 dark:text-gray-300">{f.description}</p>}
          {f.location.snippet && (
            <div className="scroll-thin overflow-x-auto whitespace-pre rounded border border-gray-200 bg-gray-50 p-2 font-mono text-sm dark:border-gray-800 dark:bg-gray-900">
              {f.location.snippet.lines.map((line, i) => {
                const lineNum = f.location.snippet!.startLine + i;
                const start = f.location.startLine ?? 0;
                const end = f.location.endLine ?? start;
                const isHighlighted = start > 0 && lineNum >= start && lineNum <= end;
                return (
                  <div key={i} className={`flex ${isHighlighted ? "bg-amber-100 dark:bg-amber-900/30" : ""}`}>
                    <span className="w-4 select-none text-amber-600 dark:text-amber-400">{isHighlighted ? ">" : " "}</span>
                    <span className="w-10 select-none pr-2 text-right text-gray-400">{lineNum}</span>
                    <span className={isHighlighted ? "text-gray-900 dark:text-white" : "text-gray-600 dark:text-gray-300"}>{line}</span>
                  </div>
                );
              })}
            </div>
          )}
          <Row label={f.location.resource && !f.location.file ? "Resource" : "Location"}><code className="break-all text-sm">{locationLabel(f.location)}</code></Row>
          {f.meta?.commit && <Row label="Commit"><code className="break-all text-sm">{f.meta.commit}</code></Row>}
          <Row label="Rule"><code className="break-all text-sm">{f.ruleId}</code></Row>
          {f.cwes && f.cwes.length > 0 && <Row label="CWE"><span className="flex flex-wrap gap-1">{f.cwes.map(renderCwe)}</span></Row>}
          {f.package && <Row label="Package"><code className="text-sm">{f.package}</code></Row>}
          {f.cve && <Row label="CVE"><code className="text-sm">{f.cve}</code></Row>}
          {forgeLink && <Row label="Source"><a href={forgeLink.href} target="_blank" rel="noreferrer" className="text-sm text-accent-600 hover:underline dark:text-accent-400">view at {forgeLink.shortSha} →</a></Row>}
          <RiskSignals signals={f.riskSignals} />
        </Section>

        {Object.keys(groupedControls).length > 0 && (
          <Section title="Compliance">
            {Object.entries(groupedControls).map(([fw, controls]) => (
              <Row key={fw} label={fw}><span className="flex flex-wrap gap-1">{controls.map((c) => (<span key={c} className="rounded bg-indigo-50 px-1.5 py-0.5 font-mono text-sm text-indigo-700 dark:bg-indigo-950/60 dark:text-indigo-300" title="Framework control this finding violates (see `argus comply`)">{c}</span>))}</span></Row>
            ))}
          </Section>
        )}

        {(canExplain || f.remediation || (f.cwes && f.cwes.length > 0)) && (
          <Section title="Fix">
            {canExplain && (
              <div className="flex flex-wrap items-center gap-2">
                {!explainState && <button onClick={onExplain} className={ACTION_BTN}>Explain</button>}
                {!remediateState && <button onClick={onRemediate} className={ACTION_BTN}>Suggest fix</button>}
                {canSuppress && f.ruleId && <button onClick={() => onSuppress?.(f.ruleId)} className={ACTION_BTN} title={`Add rule "${f.ruleId}" to this target's ignore list (admin, audited)`}>Suppress rule</button>}
              </div>
            )}
            {explainState && (
              <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-900/40">
                {explainState.loading ? <p className="text-sm text-gray-500">Explaining…</p> : explainState.error ? (<div className="space-y-1"><p className="text-sm text-red-600 dark:text-red-400">{explainState.error}</p><button onClick={onExplain} className="text-sm text-gray-500 hover:underline">retry</button></div>) : explainState.data ? (<><p className="whitespace-pre-wrap break-words text-sm text-gray-800 dark:text-gray-200">{explainState.data.explanation}</p>{explainState.data.remediation && (<p className="mt-2 whitespace-pre-wrap break-words text-sm text-gray-600 dark:text-gray-300"><span className="font-semibold text-gray-500">Fix: </span>{explainState.data.remediation}</p>)}<p className="mt-1 text-[11px] text-gray-400">{explainState.data.model}{explainState.data.cached ? " (cached)" : ""}</p></>) : null}
              </div>
            )}
            {remediateState && (remediateState.loading ? <p className="text-sm text-gray-500">Generating fix…</p> : remediateState.error ? (<div className="space-y-1"><p className="text-sm text-red-600 dark:text-red-400">{remediateState.error}</p><button onClick={onRemediate} className="text-sm text-gray-500 hover:underline">retry</button></div>) : remediateState.data ? (<RemediationPanel r={remediateState.data} category={f.category} location={f.location.file ? `${f.location.file}:${f.location.startLine ?? ""}` : locationLabel(f.location)} source={f.location.snippet && f.location.snippet.lines.length > 0 ? { lines: f.location.snippet.lines, startLine: f.location.snippet.startLine, flaggedStart: f.location.startLine ?? f.location.snippet.startLine, flaggedEnd: f.location.endLine ?? f.location.startLine ?? f.location.snippet.startLine } : undefined} onRegenerate={onRemediate} />) : null)}
            <MitigationPanel finding={f} />
            {f.remediation && <p className="whitespace-pre-wrap break-words text-sm text-gray-600 dark:text-gray-300"><span className="font-semibold text-gray-500">Scanner note: </span>{f.remediation}</p>}
          </Section>
        )}

        {f.category === "CLOUD" && (
          <Section title="Approved remediation">
            <CloudRemediationPanel finding={f.id} runId={runId} targetId={origin?.targetId} canApply={!!canRemediate} />
          </Section>
        )}

        <Section title="Triage">
          {canExplain && (
            <div className="space-y-2">
              {!validateState && <button onClick={onValidate} className={ACTION_BTN}>Validate severity</button>}
              {validateState && (validateState.loading ? <p className="text-sm text-gray-500">Validating severity…</p> : validateState.error ? (<div className="space-y-1"><p className="text-sm text-red-600 dark:text-red-400">{validateState.error}</p><button onClick={onValidate} className="text-sm text-gray-500 hover:underline">retry</button></div>) : validateState.data ? (<ValidationPanel v={validateState.data} bandedSeverity={f.severity} onRevalidate={onValidate} />) : null)}
            </div>
          )}
          <DispositionControl disposition={disposition} canDispose={canDispose} onDispose={onDispose} onClear={onClearDispose} />
          {f.triage && (
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-800/50">
              <div className="mb-1 flex items-center gap-2">
                <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${VERDICT_CHIP[f.triage.verdict]}`}>{VERDICT_LABEL[f.triage.verdict]}</span>
                {typeof f.triage.confidence === "number" && <span className="text-sm text-gray-500">confidence {(f.triage.confidence * 100).toFixed(0)}%</span>}
                {f.triage.model && <span className="ml-auto text-[11px] text-gray-400">{f.triage.model}</span>}
              </div>
              {f.triage.rationale && <p className="whitespace-pre-wrap break-words text-sm text-gray-600 dark:text-gray-300">{f.triage.rationale}</p>}
            </div>
          )}
          {f.evidence && (f.evidence.request || f.evidence.response) && (
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-800/50">
              <div className="mb-2 flex items-center gap-2">
                <span className="text-xs font-semibold text-gray-700 dark:text-gray-300">Evidence</span>
                {f.evidence.fuzzParam && (
                  <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[11px] text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">
                    fuzzed: {f.evidence.fuzzParam}{f.evidence.fuzzPos ? ` (${f.evidence.fuzzPos})` : ""}
                  </span>
                )}
                <span className="ml-auto text-[10px] text-gray-400">auth headers redacted</span>
              </div>
              {f.evidence.request && (
                <div className="mb-2">
                  <div className="mb-1 text-[10px] font-medium uppercase tracking-wide text-gray-500">Request</div>
                  <pre className="max-h-48 overflow-auto rounded bg-white p-2 text-[11px] leading-snug text-gray-800 dark:bg-gray-900 dark:text-gray-200">{f.evidence.request}</pre>
                </div>
              )}
              {f.evidence.response && (
                <div>
                  <div className="mb-1 text-[10px] font-medium uppercase tracking-wide text-gray-500">Response</div>
                  <pre className="max-h-64 overflow-auto rounded bg-white p-2 text-[11px] leading-snug text-gray-800 dark:bg-gray-900 dark:text-gray-200">{f.evidence.response}</pre>
                </div>
              )}
            </div>
          )}
        </Section>
      </div>
    </Panel>
  );
}

// DispositionControl: set/clear a finding's durable workflow status + note.
// Read-only (a chip) for viewers; interactive for operator+. The note is a
// justification (accepted-risk) or context; it is audited by status, not text.
const DISPO_OPTIONS: DispositionStatus[] = ["in-progress", "accepted-risk", "false-positive", "fixed"];
function DispositionControl({ disposition, canDispose, onDispose, onClear }: {
  disposition?: Disposition;
  canDispose?: boolean;
  onDispose: (status: DispositionStatus, note: string) => void;
  onClear: () => void;
}) {
  const [note, setNote] = useState(disposition?.note ?? "");
  const [busy, setBusy] = useState(false);
  useEffect(() => { setNote(disposition?.note ?? ""); }, [disposition?.findingId, disposition?.status]);

  const current = disposition?.status ?? "open";
  const regressed = disposition?.status === "fixed";
  const act = async (fn: () => Promise<void> | void) => { setBusy(true); try { await fn(); } finally { setBusy(false); } };

  if (!canDispose) {
    // Viewer: read-only status.
    if (!disposition) return null;
    return (
      <div className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 text-sm dark:border-gray-800 dark:bg-gray-800/50">
        <span className="text-gray-500">Status: </span>
        <span className={`rounded px-1.5 py-0.5 font-semibold ${DISPOSITION_CHIP[disposition.status]}`}>{DISPOSITION_LABEL[disposition.status]}</span>
        {disposition.note && <p className="mt-1 whitespace-pre-wrap break-words text-gray-600 dark:text-gray-300">{disposition.note}</p>}
        <p className="mt-1 text-[11px] text-gray-400">{disposition.actor}</p>
      </div>
    );
  }

  return (
    <div className={`rounded-lg border px-3 py-2 ${regressed ? "border-red-300 bg-red-50 dark:border-red-900 dark:bg-red-950/20" : "border-gray-200 bg-gray-50 dark:border-gray-800 dark:bg-gray-800/50"}`}>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-sm font-semibold text-gray-500">Status</span>
        <button
          onClick={() => act(onClear)}
          disabled={busy}
          className={`rounded px-1.5 py-0.5 text-[12px] font-semibold ${current === "open" ? "bg-accent-600 text-white" : "bg-gray-200 text-gray-600 hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-300"}`}
        >
          Open
        </button>
        {DISPO_OPTIONS.map((s) => (
          <button
            key={s}
            onClick={() => act(() => onDispose(s, note))}
            disabled={busy}
            className={`rounded px-1.5 py-0.5 text-[12px] font-semibold ${current === s ? DISPOSITION_CHIP[s] + " ring-1 ring-current" : "bg-gray-200 text-gray-600 hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-300"}`}
          >
            {DISPOSITION_LABEL[s]}
          </button>
        ))}
        {regressed && <span className="ml-auto text-[11px] font-bold text-red-600 dark:text-red-400" title="Marked fixed but still detected in this run">⟳ REGRESSION</span>}
      </div>
      <div className="mt-2 flex items-start gap-2">
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Note / justification (saved with the status)"
          rows={2}
          className="w-full resize-y rounded border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
        />
        {disposition && note !== (disposition.note ?? "") && (
          <button
            onClick={() => act(() => onDispose(disposition.status, note))}
            disabled={busy}
            className="shrink-0 rounded bg-accent-600 px-2 py-1 text-[12px] font-semibold text-white hover:bg-accent-700 disabled:opacity-50"
          >
            Save note
          </button>
        )}
      </div>
      {disposition && <p className="mt-1 text-[11px] text-gray-400">by {disposition.actor}</p>}
    </div>
  );
}

// langForFile mirrors internal/mitigation.LanguageForFile so the panel can
// pick the right snippet before the fetch returns.
function langForFile(path?: string): string {
  const ext = (path ?? "").toLowerCase().match(/\.[a-z0-9]+$/)?.[0] ?? "";
  const map: Record<string, string> = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript", ".java": "java",
    ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp",
  };
  return map[ext] ?? "";
}

// CodeBlock is a copyable, escaped code snippet with a good/bad accent.
function CodeBlock({ code, tone }: { code: string; tone: "bad" | "good" }) {
  const [copied, setCopied] = useState(false);
  const border = tone === "bad" ? "border-red-200 dark:border-red-900" : "border-emerald-200 dark:border-emerald-900";
  return (
    <div className={`relative overflow-hidden rounded border ${border}`}>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
        className="absolute right-1 top-1 rounded bg-white/80 px-1.5 py-0.5 text-[11px] text-gray-600 hover:bg-white dark:bg-gray-800/80 dark:text-gray-300"
      >
        {copied ? "copied" : "copy"}
      </button>
      <pre className="scroll-thin overflow-x-auto bg-gray-50 p-2 font-mono text-[12px] text-gray-800 dark:bg-gray-900 dark:text-gray-200">{code}</pre>
    </div>
  );
}

// MitigationPanel shows curated secure-coding guidance for a finding's weakness
// class: the fixing principle, a before/after snippet in the finding's language
// (switchable), the library to reach for, and references. Static, human-vetted
// content — distinct from the AI remediation above. Renders nothing when the
// library has no entry for the finding's CWEs.
function MitigationPanel({ finding }: { finding: Finding }) {
  const cwes = finding.cwes ?? [];
  const [state, setState] = useState<{ loading: boolean; data?: Mitigation | null; error?: string }>({ loading: false });
  const [lang, setLang] = useState<string>("");

  useEffect(() => {
    if (!cwes.length) { setState({ loading: false, data: null }); return; }
    let cancelled = false;
    setState({ loading: true });
    api
      .mitigation(cwes, langForFile(finding.location.file))
      .then((m) => {
        if (cancelled) return;
        setState({ loading: false, data: m });
        setLang(m?.matchedLanguage || m?.snippets[0]?.language || "");
      })
      .catch((e) => { if (!cancelled) setState({ loading: false, error: String(e) }); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finding.id]);

  if (!cwes.length || state.error) return null;
  const m = state.data;
  if (state.loading || !m) return null;
  const snippet = m.snippets.find((s) => s.language === lang) ?? m.snippets[0];

  return (
    <div className="rounded-lg border border-indigo-200 bg-indigo-50/40 p-3 dark:border-indigo-900 dark:bg-indigo-950/20">
      <div className="mb-1 flex items-center justify-between gap-2">
        <h4 className="text-sm font-semibold text-indigo-800 dark:text-indigo-300">Secure code fix: {m.title}</h4>
        <span className="text-[11px] uppercase tracking-wide text-gray-400">curated · human-vetted</span>
      </div>
      <p className="mb-2 text-sm text-gray-700 dark:text-gray-300">{m.principle}</p>

      {m.snippets.length > 1 && (
        <div className="mb-2 flex flex-wrap gap-1">
          {m.snippets.map((s) => (
            <button
              key={s.language}
              onClick={() => setLang(s.language)}
              className={`rounded px-1.5 py-0.5 text-[12px] font-medium ${s.language === snippet.language ? "bg-indigo-600 text-white" : "bg-white text-gray-600 hover:bg-gray-100 dark:bg-gray-800 dark:text-gray-300"}`}
            >
              {s.language}
            </button>
          ))}
        </div>
      )}

      {snippet && (
        <div className="space-y-1.5">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-red-600 dark:text-red-400">Vulnerable</div>
          <CodeBlock code={snippet.vulnerable} tone="bad" />
          <div className="text-[11px] font-semibold uppercase tracking-wide text-emerald-600 dark:text-emerald-400">Secure</div>
          <CodeBlock code={snippet.secure} tone="good" />
          {snippet.library && <p className="text-sm text-gray-600 dark:text-gray-300"><span className="font-semibold">Use:</span> {snippet.library}</p>}
          {snippet.note && <p className="text-sm text-gray-500 dark:text-gray-400">{snippet.note}</p>}
        </div>
      )}

      {m.references.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[12px]">
          {m.references.map((r) => (
            <a key={r.url} href={r.url} target="_blank" rel="noopener noreferrer" className="text-indigo-600 hover:underline dark:text-indigo-400">
              {r.title} ↗
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

// ValidationPanel shows the advisory severity assessment: verdict, a CVSS 3.1
// score computed from the model's vector, and the impact/likelihood behind it.
// It never changes the finding's stored (banded) severity — it sits beside it.
function ValidationPanel({ v, bandedSeverity, onRevalidate }: { v: ValidationResponse; bandedSeverity: Severity; onRevalidate: () => void }) {
  const rated = v.cvssSeverity !== "unrated" && v.cvssSeverity !== "";
  return (
    <div className="space-y-2 rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-900/40">
      <div className="flex items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Severity validation</span>
        <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${VERDICT_CHIP[v.verdict]}`}>{VERDICT_LABEL[v.verdict] ?? v.verdict}</span>
        <button onClick={onRevalidate} className="ml-auto text-[11px] text-gray-500 hover:underline">re-validate</button>
      </div>

      {rated ? (
        <>
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="text-2xl font-bold tabular-nums" style={{ color: riskColor(v.cvssScore) }}>{v.cvssScore.toFixed(1)}</span>
            <span className="text-sm font-semibold uppercase" style={{ color: riskColor(v.cvssScore) }}>{v.cvssSeverity}</span>
            <span className="text-[11px] text-gray-400">CVSS 3.1 base · this scan's banded severity: {bandedSeverity}</span>
          </div>
          <div className="break-all font-mono text-[11px] text-gray-500 dark:text-gray-400">{v.cvssVector}</div>
        </>
      ) : (
        <p className="text-sm text-gray-500">No valid CVSS vector returned — showing the model's assessment only.</p>
      )}

      <div className="grid grid-cols-[74px_minmax(0,1fr)] gap-x-2 gap-y-1 text-sm">
        {v.impact && (<><span className="text-gray-400">Impact</span><span className="break-words text-gray-700 dark:text-gray-300">{v.impact}</span></>)}
        {v.likelihood && (<><span className="text-gray-400">Likelihood</span><span className="break-words text-gray-700 dark:text-gray-300">{v.likelihood}</span></>)}
      </div>
      {v.rationale && <p className="break-words text-[12px] text-gray-500 dark:text-gray-400">{v.rationale}</p>}
      <p className="text-[11px] text-gray-400">{v.model} · advisory; does not change the stored severity</p>
    </div>
  );
}

// RemediationPanel renders an AI-assisted remediation: summary, ordered
// steps, copyable script/patch artifacts, and a verification (re-scan) step.
// Everything is escaped text (hostile-data rule). The amber banner and the
// "you run this" framing are load-bearing: the platform never executes any of
// it, and a finding clears only on re-scan.
const KIND_LABEL: Record<string, string> = {
  "cli-script": "CLI script", "code-patch": "Code patch",
  "dependency-upgrade": "Dependency upgrade", "secret-rotation": "Secret rotation",
  manual: "Manual steps",
};
// stripStepNumber removes a leading "1." / "2)" the model often prepends, so a
// numbered list doesn't render as "1. 1. …".
function stripStepNumber(s: string): string {
  return s.replace(/^\s*\d+[.)]\s+/, "");
}

function RemediationPanel({ r, category, location, source, onRegenerate }: { r: RemediationResponse; category: string; location?: string; source?: DiffSource; onRegenerate: () => void }) {
  const infra = category === "CLOUD" || category === "IAC";
  // Neutral card, one caution accent — the fix is the content, not the colour.
  return (
    <div className="space-y-2.5 rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-900/40">
      <div className="flex items-center gap-2">
        <span className="rounded bg-gray-200 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-gray-600 dark:bg-gray-700 dark:text-gray-300">
          {KIND_LABEL[r.kind] ?? r.kind}
        </span>
        <span className="text-[11px] uppercase tracking-wide text-gray-400">AI-generated</span>
        <button onClick={onRegenerate} className="ml-auto text-[11px] text-gray-500 hover:text-gray-700 hover:underline dark:hover:text-gray-300">regenerate</button>
      </div>

      <p className="break-words text-sm font-medium text-gray-800 dark:text-gray-200">{r.summary}</p>

      {/* One caution accent: you run it yourself, and a re-scan confirms it. */}
      <div className="flex gap-1.5 rounded border-l-2 border-amber-400 bg-amber-50/60 px-2 py-1.5 text-[12px] text-amber-800 dark:bg-amber-900/15 dark:text-amber-300">
        <span>Review before running. You apply this with your own credentials{infra ? "; it modifies live infrastructure" : ""}. The finding clears only on re-scan.</span>
      </div>

      {r.safetyIssues && r.safetyIssues.length > 0 && (
        <div className="rounded border-l-2 border-red-400 bg-red-50/60 px-2 py-1.5 text-[12px] text-red-800 dark:bg-red-950/20 dark:text-red-300">
          <span className="font-semibold">Safety linter defanged this suggestion:</span>
          <ul className="ml-4 list-disc">{r.safetyIssues.map((s, i) => <li key={i}>{s}</li>)}</ul>
        </div>
      )}

      {r.steps && r.steps.length > 0 && (
        <ol className="ml-4 list-decimal space-y-1 text-sm text-gray-700 dark:text-gray-300 marker:text-gray-400">
          {r.steps.map((s, i) => <li key={i} className="break-words pl-1">{stripStepNumber(s)}</li>)}
        </ol>
      )}

      {r.artifacts?.map((a, i) => (a.language === "diff" ? <DiffView key={i} content={a.content} title={a.title} location={location} source={source} /> : <ArtifactBlock key={i} a={a} />))}

      {r.warnings && r.warnings.length > 0 && (
        <ul className="ml-4 list-disc space-y-0.5 text-[12px] text-gray-600 dark:text-gray-400">
          {r.warnings.map((w, i) => <li key={i}>{w}</li>)}
        </ul>
      )}

      {r.verification && (
        <p className="text-[12px] text-gray-600 dark:text-gray-400"><span className="font-semibold">Verify:</span> {r.verification}</p>
      )}
      <p className="text-[11px] text-gray-400">{r.model}</p>
    </div>
  );
}

// CopyButton is the shared copy affordance for code blocks.
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); }).catch(() => {}); }}
      className="rounded px-1.5 py-0.5 text-[11px] font-medium text-gray-500 hover:bg-gray-200 dark:text-gray-400 dark:hover:bg-gray-700"
    >
      {copied ? "copied" : "copy"}
    </button>
  );
}

function ArtifactBlock({ a }: { a: RemediationArtifact }) {
  return (
    <div className="overflow-hidden rounded border border-gray-200 dark:border-gray-800">
      <div className="flex items-center gap-2 bg-gray-100 px-2 py-1 text-[11px] text-gray-500 dark:bg-gray-800">
        <span className="font-mono uppercase">{a.language}</span>
        {a.title && <span className="truncate">{a.title}</span>}
        <span className="ml-auto"><CopyButton text={a.content} /></span>
      </div>
      {/* Escaped text only — never dangerouslySetInnerHTML. */}
      <pre className="scroll-thin overflow-x-auto whitespace-pre bg-gray-50 p-2 font-mono text-[12px] text-gray-800 dark:bg-gray-900 dark:text-gray-200">{a.content}</pre>
    </div>
  );
}

// A parsed unified-diff row for the side-by-side view. A context line appears
// on both sides; a removal only on the left, an addition only on the right,
// with removals/additions paired so the two columns stay aligned.
type DiffRow = { left: string | null; right: string | null; leftDel: boolean; rightAdd: boolean };

// DiffSource is the finding's captured code: the authoritative "before".
type DiffSource = { lines: string[]; startLine: number; flaggedStart: number; flaggedEnd: number };

// reconstructFromSnippet builds the side-by-side rows with the LEFT column
// taken verbatim from the finding's own snippet — not from the model. Only the
// fix (the added lines) comes from the diff, so the model can never misrepresent
// the vulnerable code. The flagged line(s) are replaced by the model's fix;
// additions that don't pair with a removal (a new import, say) show as add-only
// rows up top. Returns null when it can't line things up, so the caller falls
// back to parsing the raw diff.
function reconstructFromSnippet(src: DiffSource, diff: string): DiffRow[] | null {
  const fi = src.flaggedStart - src.startLine;
  const fcount = Math.max(1, src.flaggedEnd - src.flaggedStart + 1);
  if (fi < 0 || fi >= src.lines.length) return null;

  // Classify the fix's additions PER HUNK SEGMENT, not per row. A segment that
  // removes anything is an inline replacement, so all of its additions (a
  // multi-line fix) belong together at the flagged position; a segment with no
  // removal is a lead-in (a new import, say) shown above the frame. Pairing
  // per row instead hoisted the 2nd+ lines of a multi-line fix above the code.
  const paired: string[] = [];
  const extras: string[] = [];
  let segHasDel = false;
  let segAdds: string[] = [];
  const flushSeg = () => {
    if (segAdds.length) (segHasDel ? paired : extras).push(...segAdds);
    segHasDel = false;
    segAdds = [];
  };
  for (const line of diff.replace(/\n$/, "").split("\n")) {
    if (/^(@@|diff |index |--- |\+\+\+ )/.test(line)) { flushSeg(); continue; }
    if (line.startsWith("-")) segHasDel = true;
    else if (line.startsWith("+")) segAdds.push(line.slice(1));
    else flushSeg(); // a context line closes the segment
  }
  flushSeg();

  const fix = paired.length ? paired : extras.length ? extras : null;
  if (!fix) return null;
  const leadIns = paired.length ? extras : [];

  const rows: DiffRow[] = [];
  for (const e of leadIns) rows.push({ left: null, right: e, leftDel: false, rightAdd: true });
  for (let i = 0; i < src.lines.length; i++) {
    if (i === fi) {
      const dels = src.lines.slice(fi, fi + fcount);
      const n = Math.max(dels.length, fix.length);
      for (let k = 0; k < n; k++) {
        rows.push({ left: dels[k] ?? null, right: fix[k] ?? null, leftDel: k < dels.length, rightAdd: k < fix.length });
      }
      i += fcount - 1;
    } else {
      rows.push({ left: src.lines[i], right: src.lines[i], leftDel: false, rightAdd: false });
    }
  }
  return rows;
}

// DiffView renders a code patch as before/after side by side: the left column
// is the finding's actual code with its surrounding lines, the right is the
// same with the fix applied. Changed lines get a restrained tint; everything
// else is neutral. Columns size to their content and the whole grid scrolls
// both ways (long lines don't wrap or clip), with the Before/After labels
// pinned on vertical scroll.
function DiffView({ content, title, location, source }: { content: string; title?: string; location?: string; source?: DiffSource }) {
  // The side-by-side view is only shown when the LEFT column can be rebuilt from
  // the finding's own snippet — that is the whole point: the model can't
  // misrepresent the vulnerable code. Without a snippet to anchor "Before" (or
  // when the fix is deletion-only and can't be reconstructed), fall back to the
  // raw unified diff, whose -/+ lines read as the model's proposal rather than
  // as your verified current code under a "Before" label.
  const rows = useMemo(() => {
    if (source && source.lines.length > 0) return reconstructFromSnippet(source, content);
    return null;
  }, [content, source]);
  if (!rows || rows.length === 0) return <ArtifactBlock a={{ language: "diff", title: title ?? "", content }} />;
  // Wrap long lines inside each fixed 50% column (break anywhere for code) so a
  // long line can't overflow its cell and collide with the other side. Each
  // diff row is one grid row, so the two cells stay top-aligned even when one
  // side wraps taller than the other.
  const cell = "min-w-0 whitespace-pre-wrap break-all px-2 py-px";
  const label = "sticky top-0 z-10 border-b border-gray-200 bg-gray-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-400 dark:border-gray-800 dark:bg-gray-800";
  return (
    <div className="overflow-hidden rounded border border-gray-200 dark:border-gray-800">
      <div className="flex items-center gap-2 bg-gray-100 px-2 py-1 text-[11px] text-gray-500 dark:bg-gray-800">
        <span className="font-mono uppercase">patch</span>
        {location && <span className="truncate font-mono">{location}</span>}
        <span className="ml-auto"><CopyButton text={content} /></span>
      </div>
      <div className="scroll-thin max-h-96 overflow-y-auto">
        <div className="grid grid-cols-2 font-mono text-[12px] leading-relaxed">
          <div className={`${label} border-r`}>Before</div>
          <div className={label}>After</div>
          {rows.map((row, i) => (
            <Fragment key={i}>
              <div className={`${cell} border-r border-gray-200 dark:border-gray-800 ${row.leftDel ? "bg-red-50 text-red-800 dark:bg-red-950/30 dark:text-red-300" : "text-gray-700 dark:text-gray-300"}`}>
                {row.left ?? ""}
              </div>
              <div className={`${cell} ${row.rightAdd ? "bg-emerald-50 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300" : "text-gray-700 dark:text-gray-300"}`}>
                {row.right ?? ""}
              </div>
            </Fragment>
          ))}
        </div>
      </div>
    </div>
  );
}

// Why a finding ranks where it does: the stage-2 context signals from the Go
// risk engine, as chips. Rose raises risk, emerald lowers it; the fixed note
// string is the tooltip. All values render as escaped text only.
function RiskSignals({ signals }: { signals?: RiskSignal[] }) {
  if (!signals || signals.length === 0) return null;

  return (
    <Row label="Why">
      <span className="flex flex-wrap gap-1">
        {signals.map((s) => {
          const colorClass =
            s.delta > 0
              ? "bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300"
              : s.delta < 0
                ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300"
                : "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300";

          const magnitude = Math.abs(s.delta).toFixed(2).replace(/\.?0+$/, "");
          const deltaStr = `${s.delta < 0 ? "−" : "+"}${magnitude}`;

          return (
            <span
              key={s.code}
              className={`rounded px-1.5 py-0.5 font-mono text-sm ${colorClass}`}
              title={s.note}
            >
              {s.code}{" "}
              <span className="font-semibold tabular-nums">{deltaStr}</span>
            </span>
          );
        })}
      </span>
    </Row>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  // minmax(0,1fr) (not bare 1fr, whose implicit min-width:auto is min-content)
  // so a long unbreakable token in the value column can't force the grid wider
  // than the pane; min-w-0 lets the value wrap/scroll inside its own box.
  return (
    <div className="grid grid-cols-[80px_minmax(0,1fr)] gap-2">
      <span className="text-sm font-medium uppercase text-gray-400">{label}</span>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function RiskPill({ score }: { score?: number }) {
  if (score === undefined || score === null) return <span className="text-sm text-gray-400">—</span>;
  return (
    <span
      className="inline-block rounded px-1.5 py-0.5 text-sm font-bold tabular-nums text-white"
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
    <label className="inline-flex items-center gap-1 text-sm text-gray-500">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-gray-300 bg-white px-1.5 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
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

