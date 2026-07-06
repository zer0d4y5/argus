import { useMemo, useState } from "react";
import { CoverageAccounting, ExplainResponse, Finding, locationLabel, opsApi, RiskSignal, RunDetail, Severity, SEVERITIES } from "../api";
import { Panel, SeverityBadge, CategoryBadge, EmptyState } from "../components";
import { VERDICT_CHIP, VERDICT_LABEL, riskColor } from "../theme";

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Per-finding explain lifecycle; cached client-side so re-clicks don't refetch.
type ExplainState = { loading: boolean; data?: ExplainResponse; error?: string };

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
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
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
            className="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] uppercase text-gray-600 dark:bg-gray-800 dark:text-gray-300"
            title={cov.gitShallow ? "Shallow clone: secret history coverage is the single fetched commit" : "Git repository: the secret scanner also scanned commit history"}
          >
            git history{cov.gitShallow ? " (shallow)" : ""}
          </span>
        )}
      </div>
      {skipped > 0 && samples.length > 0 && (
        <p className="mt-2 break-all text-[11px] text-gray-500 dark:text-gray-400">
          e.g. {samples.slice(0, 6).join(" · ")}
        </p>
      )}
    </Panel>
  );
}

export function Findings({
  detail,
  origin,
  canExplain,
  canSuppress,
  onSuppress,
}: {
  detail: RunDetail;
  origin?: {
    targetId?: string;
    gitUrl?: string;
    commit?: string;
  };
  canExplain?: boolean;
  canSuppress?: boolean;
  onSuppress?: (ruleId: string) => void;
}) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string>("all");
  const [cat, setCat] = useState<string>("all");
  const [tool, setTool] = useState<string>("all");
  const [verdict, setVerdict] = useState<string>("all");
  const [minRisk, setMinRisk] = useState(0);
  const [framework, setFramework] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Explain state per finding
  const [explainState, setExplainState] = useState<Record<string, ExplainState>>({});

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
      .filter((f) => framework === "all" || (f.complianceControls ?? []).some((c) => c.startsWith(framework + ":")))
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
  }, [detail.findings, q, sev, cat, tool, verdict, minRisk, framework]);

  const selected = filtered.find((f) => f.id === selectedId) ?? filtered[0] ?? null;

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
            <Select
              value={framework}
              onChange={setFramework}
              label="Framework"
              options={["all", ...frameworks]}
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
                      <div className="flex items-center gap-1.5 text-[11px] text-gray-400">
                        <CategoryBadge category={f.category} compact />
                        <span className="truncate">{locationLabel(f.location)}</span>
                      </div>
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
        {selected ? <Detail f={selected} isNew={newSet.has(selected.id)} origin={origin} canExplain={canExplain} explainState={explainState[selected.id]} onExplain={() => handleExplain(selected)} canSuppress={canSuppress} onSuppress={onSuppress} /> : null}
      </div>
    </div>
    </div>
  );
}

function Detail({ f, isNew, origin, canExplain, explainState, onExplain, canSuppress, onSuppress }: {
  f: Finding;
  isNew: boolean;
  origin?: { targetId?: string; gitUrl?: string; commit?: string };
  canExplain?: boolean;
  explainState?: ExplainState;
  onExplain: () => void;
  canSuppress?: boolean;
  onSuppress?: (ruleId: string) => void;
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
          className="rounded bg-gray-100 px-1.5 py-0.5 text-xs hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 cursor-pointer"
        >
          {cwe}
        </a>
      );
    }
    return (
      <span key={cwe} className="rounded bg-gray-100 px-1.5 py-0.5 text-xs dark:bg-gray-800">
        {cwe}
      </span>
    );
  };

  return (
    <Panel title="Finding detail">
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          <CategoryBadge category={f.category} />
          <RiskPill score={f.riskScore} />
          {f.toolSeverity && f.toolSeverity !== f.severity && (
            <span className="rounded border border-gray-300 px-1.5 py-0.5 text-[10px] uppercase text-gray-500 dark:border-gray-700 dark:text-gray-400" title="Severity is banded from the deterministic risk score; this is what the tool itself reported.">tool said: {f.toolSeverity}</span>
          )}
          {f.meta?.gitHistory === "true" && (
            <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-bold text-amber-800 dark:bg-amber-900/50 dark:text-amber-300" title="Found in git history, not the current worktree — rotate the credential; deleting the file does not revoke it.">GIT HISTORY{f.meta?.gitShallow === "true" ? " (shallow)" : ""}</span>
          )}
          {isNew && (
            <span className="rounded bg-emerald-100 px-1.5 text-[10px] font-bold text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-300">
              NEW
            </span>
          )}
          <span className="text-xs text-gray-400">{(f.tools ?? [f.tool]).join(", ")}</span>
        </div>

        {/* Code Frame */}
        {f.location.snippet && (
          <Row label="Code">
            <div className="overflow-x-auto whitespace-pre font-mono text-xs bg-gray-50 dark:bg-gray-900 p-2 rounded border border-gray-200 dark:border-gray-800">
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
          </Row>
        )}

        {/* All values below are hostile data rendered as escaped text only. */}
        <h3 className="break-words font-mono text-sm font-semibold">{f.title}</h3>
        {f.description && <p className="whitespace-pre-wrap break-words text-gray-600 dark:text-gray-300">{f.description}</p>}

        <Row label={f.location.resource && !f.location.file ? "Resource" : "Location"}>
          <code className="break-all text-xs">{locationLabel(f.location)}</code>
        </Row>
        {f.meta?.commit && (
          <Row label="Commit"><code className="break-all text-xs">{f.meta.commit}</code></Row>
        )}
        <Row label="Rule">
          <code className="break-all text-xs">{f.ruleId}</code>
        </Row>
        {f.cwes && f.cwes.length > 0 && (
          <Row label="CWE">
            <span className="flex flex-wrap gap-1">
              {f.cwes.map(renderCwe)}
            </span>
          </Row>
        )}
        {f.package && <Row label="Package"><code className="text-xs">{f.package}</code></Row>}
        {f.cve && <Row label="CVE"><code className="text-xs">{f.cve}</code></Row>}
        
        {/* Grouped Compliance Controls */}
        {Object.keys(groupedControls).length > 0 && (
          Object.entries(groupedControls).map(([fw, controls]) => (
            <Row key={fw} label={fw}>
              <span className="flex flex-wrap gap-1">
                {controls.map((c) => (
                  <span
                    key={c}
                    className="rounded bg-indigo-50 px-1.5 py-0.5 font-mono text-xs text-indigo-700 dark:bg-indigo-950/60 dark:text-indigo-300"
                    title="Framework control this finding violates (see `appsec comply`)"
                  >
                    {c}
                  </span>
                ))}
              </span>
            </Row>
          ))
        )}

        {/* Forge Deep Link */}
        {forgeLink && (
          <Row label="Source">
            <a
              href={forgeLink.href}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-blue-600 hover:underline dark:text-blue-400"
            >
              view at {forgeLink.shortSha} →
            </a>
          </Row>
        )}

        <RiskSignals signals={f.riskSignals} />

        {/* Actions: explain (operator+) and suppress (admin, target-scoped) */}
        {(canExplain || canSuppress) && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {canSuppress && f.ruleId && (
              <button
                onClick={() => onSuppress?.(f.ruleId)}
                className="rounded border border-amber-300 bg-amber-50 px-2 py-1 text-xs font-semibold text-amber-800 hover:bg-amber-100 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-300 dark:hover:bg-amber-900/40"
                title={`Add rule "${f.ruleId}" to this target's ignore list so it stops appearing (admin, audited)`}
              >
                Suppress rule
              </button>
            )}
          </div>
        )}

        {/* Explain Button & Result */}
        {canExplain && (
          <div className="mt-2">
            {!explainState ? (
              <button
                onClick={onExplain}
                className="rounded bg-blue-50 px-2 py-1 text-xs font-semibold text-blue-700 hover:bg-blue-100 dark:bg-blue-900/30 dark:text-blue-300 dark:hover:bg-blue-900/50"
              >
                Explain Finding
              </button>
            ) : (
              <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-800/50">
                {explainState.loading ? (
                  <p className="text-xs text-gray-500">Explaining...</p>
                ) : explainState.error ? (
                  <div className="space-y-1">
                    <p className="text-xs text-red-600 dark:text-red-400">{explainState.error}</p>
                    <button onClick={onExplain} className="text-xs text-blue-600 hover:underline dark:text-blue-400">retry</button>
                  </div>
                ) : explainState.data ? (
                  <>
                    <p className="whitespace-pre-wrap break-words text-xs text-gray-800 dark:text-gray-200">
                      {explainState.data.explanation}
                    </p>
                    {explainState.data.remediation && (
                      <div className="mt-2">
                        <span className="text-xs font-semibold text-gray-500">Fix:</span>
                        <p className="whitespace-pre-wrap break-words text-xs text-gray-600 dark:text-gray-300">
                          {explainState.data.remediation}
                        </p>
                      </div>
                    )}
                    <div className="mt-1 flex items-center gap-2 text-[10px] text-gray-400">
                      <span>{explainState.data.model}</span>
                      {explainState.data.cached && <span>(cached)</span>}
                    </div>
                  </>
                ) : null}
              </div>
            )}
          </div>
        )}

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
              className={`rounded px-1.5 py-0.5 font-mono text-xs ${colorClass}`}
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

