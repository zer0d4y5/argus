import { useEffect, useState } from "react";
import { opsApi, Target, Job, JobOptions, ApiError, KNOWN_SCANNERS, PROFILES, FrameworkInfo } from "../api";
import { Panel, Loading, ErrorNote, EmptyState } from "../components";
import { fmtTime } from "../theme";

export function Operate({ canLaunch, onOpenRun }: { canLaunch: boolean; onOpenRun: (runId: string, targetId?: string, commit?: string) => void }) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Launcher state
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [scanners, setScanners] = useState<Set<string>>(new Set());
  const [profile, setProfile] = useState("");
  const [triage, setTriage] = useState<"default" | "on" | "off">("default");
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);

  // Expanded job state
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Frameworks state
  const [frameworks, setFrameworks] = useState<FrameworkInfo[]>([]);
  const [selectedFrameworks, setSelectedFrameworks] = useState<Set<string>>(new Set());

  // Scope input state
  const [scope, setScope] = useState("");

  // One stable effect: initial load plus a fixed-interval poll (the queue
  // advances server-side). A transient poll failure never blanks the page —
  // only the first load surfaces as a full-screen error.
  useEffect(() => {
    let alive = true;
    let first = true;
    const load = async () => {
      try {
        const [t, j] = await Promise.all([opsApi.targets(), opsApi.jobs()]);
        if (!alive) return;
        setTargets(t.targets);
        setJobs(j.jobs);
        setSelectedTargetId((cur) => cur || t.targets[0]?.id || "");
        setError(null);
        setLoading(false);
      } catch (err) {
        if (!alive) return;
        if (first) {
          setError(err instanceof ApiError ? err.message : String(err));
          setLoading(false);
        }
      }
      first = false;
    };
    load();
    const interval = setInterval(load, 2500);
    return () => {
      alive = false;
      clearInterval(interval);
    };
  }, []);

  // Fetch frameworks once on mount
  useEffect(() => {
    let alive = true;
    opsApi.frameworks().then((res) => {
      if (alive) setFrameworks(res.frameworks);
    }).catch(() => {
      // ignore framework fetch errors gracefully
    });
    return () => { alive = false; };
  }, []);

  // Reset scanners and frameworks when target changes
  const handleTargetChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newId = e.target.value;
    setSelectedTargetId(newId);
    setScanners(new Set());
    setSelectedFrameworks(new Set());
  };

  const toggleScanner = (scanner: string) => {
    setScanners((prev) => {
      const next = new Set(prev);
      if (next.has(scanner)) next.delete(scanner);
      else next.add(scanner);
      return next;
    });
  };

  const toggleFramework = (id: string) => {
    setSelectedFrameworks((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleLaunch = async () => {
    if (!selectedTargetId || launching) return;
    setLaunching(true);
    setLaunchError(null);
    try {
      // Cloud posture targets take only the triage toggle — the filesystem
      // knobs are hidden and the server rejects them, so never send stale
      // scanner/profile/scope state left over from a code target.
      const isCloud = selectedTarget?.type === "cloud";
      const options: JobOptions = {};
      if (!isCloud && scanners.size > 0) options.scanners = Array.from(scanners);
      if (!isCloud && profile) options.profile = profile;
      if (triage !== "default") options.triage = triage === "on";
      if (!isCloud && scope.trim()) options.scope = scope.trim();
      if (!isCloud && selectedFrameworks.size > 0) options.frameworks = Array.from(selectedFrameworks);

      const job = await opsApi.launchScan(selectedTargetId, options);
      setJobs((prev) => [job, ...prev]);
    } catch (err) {
      setLaunchError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setLaunching(false);
    }
  };

  if (loading) return <Loading what="data" />;
  if (error) return <ErrorNote error={error} />;

  const selectedTarget = targets.find((t) => t.id === selectedTargetId);
  const allowedScanners = selectedTarget?.scanners && selectedTarget.scanners.length > 0
    ? selectedTarget.scanners
    : KNOWN_SCANNERS;

  const queuedCount = jobs.filter((j) => j.status === "queued").length;
  const runningCount = jobs.filter((j) => j.status === "running").length;

  // Config summary pieces
  const configPieces: string[] = [];
  if (selectedTarget?.config) {
    if (selectedTarget.config.timeoutSec && selectedTarget.config.timeoutSec !== 0) {
      configPieces.push(`timeout ${selectedTarget.config.timeoutSec}s`);
    }
    if (selectedTarget.config.triage === true) {
      configPieces.push("triage on");
    } else if (selectedTarget.config.triage === false) {
      configPieces.push("triage off");
    }
    if (selectedTarget.config.ignorePaths && selectedTarget.config.ignorePaths.length > 0) {
      configPieces.push(`${selectedTarget.config.ignorePaths.length} ignore path(s)`);
    }
    if (selectedTarget.config.ignoreRules && selectedTarget.config.ignoreRules.length > 0) {
      configPieces.push(`${selectedTarget.config.ignoreRules.length} ignore rule(s)`);
    }
  }
  if (selectedTarget?.scanners && selectedTarget.scanners.length > 0) {
    configPieces.push(`${selectedTarget.scanners.length} scanner(s)`);
  }
  if (selectedTarget?.profile) {
    configPieces.push(`profile ${selectedTarget.profile}`);
  }

  return (
    <div className="space-y-6">
      {canLaunch && (
        <Panel title="Launch scan">
          {targets.length === 0 ? (
            <EmptyState
              title="No targets registered"
              hint="An admin must register targets: appsec target add <path> --name <label> (or Admin → Targets)."
            />
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {/* Target Select */}
              <div>
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Target</label>
                <select
                  value={selectedTargetId}
                  onChange={handleTargetChange}
                  className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>{t.type === "git" ? `${t.name} (git)` : t.type === "cloud" ? `${t.name} (cloud)` : t.name}</option>
                  ))}
                </select>
                {selectedTarget?.type === "git" && selectedTarget.url && (
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {selectedTarget.url}{selectedTarget.branch ? `@${selectedTarget.branch}` : ""}
                  </p>
                )}
                {selectedTarget?.type === "cloud" && (
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    cloud · {selectedTarget.provider} · profile {selectedTarget.profileName}
                    {selectedTarget.regions && selectedTarget.regions.length ? ` · ${selectedTarget.regions.join(",")}` : ""}
                    <br />prowler posture scan — scanner/profile/scope options do not apply
                  </p>
                )}
              </div>

              {/* Filesystem scan options — hidden for cloud posture targets,
                  whose only knob is the AI-triage toggle below. */}
              {selectedTarget?.type !== "cloud" && (<>
              {/* Scanners Checkboxes */}
              <div className="md:col-span-2">
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Scanners</label>
                <div className="flex flex-wrap gap-3">
                  {allowedScanners.map((s) => (
                    <label key={s} className="inline-flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={scanners.has(s)}
                        onChange={() => toggleScanner(s)}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800"
                      />
                      <span>{s}</span>
                    </label>
                  ))}
                </div>
                {scanners.size === 0 && (
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    None checked = target default (all allowed scanners run)
                  </p>
                )}
              </div>

              {/* Frameworks Multi-select */}
              {frameworks.length > 0 && (
                <div className="md:col-span-2">
                  <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Frameworks</label>
                  <div className="flex flex-wrap gap-3">
                    {frameworks.map((f) => (
                      <label key={f.id} className="inline-flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none" title={`${f.name} ${f.version} — scanners: ${f.scanners.join(", ")}`}>
                        <input
                          type="checkbox"
                          checked={selectedFrameworks.has(f.id)}
                          onChange={() => toggleFramework(f.id)}
                          className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800"
                        />
                        <span>{f.id}</span>
                      </label>
                    ))}
                  </div>
                  {selectedFrameworks.size > 0 && (
                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                      Focuses reporting and narrows scanners to the relevant set
                    </p>
                  )}
                </div>
              )}

              {/* Scope Input */}
              <div className="md:col-span-2">
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Scope (optional)</label>
                <input
                  type="text"
                  value={scope}
                  onChange={(e) => setScope(e.target.value)}
                  placeholder="subpath/or/file inside the target"
                  className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  relative path; validated server-side
                </p>
              </div>

              {/* Profile Select */}
              <div>
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Profile</label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                >
                  <option value="">target default</option>
                  {PROFILES.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>
              </>)}

              {/* Triage Select */}
              <div>
                <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">AI Triage</label>
                <select
                  value={triage}
                  onChange={(e) => setTriage(e.target.value as "default" | "on" | "off")}
                  className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                >
                  <option value="default">repo config</option>
                  <option value="on">enabled</option>
                  <option value="off">disabled</option>
                </select>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Model/provider always come from the repo's appsec.yml
                </p>
              </div>

              {/* Config Summary */}
              {configPieces.length > 0 && (
                <div className="md:col-span-2">
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    config: {configPieces.join(" · ")}
                  </p>
                </div>
              )}

              {/* Launch Button */}
              <div className="md:col-span-2 flex items-end justify-start">
                <button
                  onClick={handleLaunch}
                  disabled={!selectedTargetId || launching}
                  className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                >
                  {launching ? "Launching..." : "Launch Scan"}
                </button>
              </div>
            </div>
          )}
          {launchError && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{launchError}</p>}
        </Panel>
      )}

      <Panel title="Scan jobs" right={<span className="text-xs font-medium text-gray-500 dark:text-gray-400">
        {queuedCount} queued · {runningCount} running
      </span>}>
        {jobs.length === 0 ? (
          <EmptyState
            title="No scans launched yet"
            hint={canLaunch ? "Pick a target above and hit Launch." : "Operators and admins can launch scans."}
          />
        ) : (
          <div className="scroll-thin overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="text-xs uppercase text-gray-500">
                <tr>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Target</th>
                  <th className="py-2 pr-3">Launched by</th>
                  <th className="py-2 pr-3">Queued</th>
                  <th className="py-2 pr-3">Finished</th>
                  <th className="py-2 pr-3">Run</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <JobRow
                    key={job.id}
                    job={job}
                    expandedId={expandedId}
                    onToggle={() => setExpandedId(expandedId === job.id ? null : job.id)}
                    onOpenRun={onOpenRun}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
          One scan runs at a time; up to 10 queue behind it. Progress refreshes every few seconds.
        </p>
      </Panel>
    </div>
  );
}

function JobRow({
  job,
  expandedId,
  onToggle,
  onOpenRun,
}: {
  job: Job;
  expandedId: string | null;
  onToggle: () => void;
  onOpenRun: (runId: string, targetId?: string, commit?: string) => void;
}) {
  const isExpanded = expandedId === job.id;

  // Status Chip Logic
  let statusClass = "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300";
  let dotColor = "bg-gray-400";
  if (job.status === "queued") {
    statusClass = "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300";
    dotColor = "bg-gray-400";
  } else if (job.status === "running") {
    statusClass = "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300";
    dotColor = "bg-blue-500 animate-pulse";
  } else if (job.status === "done") {
    statusClass = "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300";
    dotColor = "bg-green-500";
  } else if (job.status === "failed") {
    statusClass = "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300";
    dotColor = "bg-red-500";
  }

  // Job metadata chips
  const scopeSuffix = job.options?.scope ? <span className="ml-1 text-gray-400">/{job.options.scope}</span> : null;
  const commitChip = job.commit ? (
    <span title={job.commit} className="ml-1 inline-block rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[10px] text-gray-600 dark:bg-gray-800 dark:text-gray-400">
      {job.commit.slice(0, 8)}
    </span>
  ) : null;
  const frameworkChips = job.options?.frameworks && job.options.frameworks.length > 0 ? (
    <span className="ml-1 inline-flex gap-1">
      {job.options.frameworks.map((f) => (
        <span key={f} className="inline-block rounded bg-blue-50 px-1.5 py-0.5 text-[10px] text-blue-600 dark:bg-blue-900/30 dark:text-blue-400">
          {f}
        </span>
      ))}
    </span>
  ) : null;

  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-t border-gray-100 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50 ${isExpanded ? "bg-gray-50 dark:bg-gray-900" : ""}`}
      >
        <td className="py-2.5 pr-3">
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-semibold ${statusClass}`}>
            <span className={`h-2 w-2 rounded-full ${dotColor}`} />
            {job.status}
          </span>
        </td>
        <td className="py-2.5 pr-3 font-medium">
          {job.targetName}{scopeSuffix}{commitChip}{frameworkChips}
        </td>
        <td className="py-2.5 pr-3 text-gray-600 dark:text-gray-400">{job.launchedBy}</td>
        <td className="py-2.5 pr-3 text-gray-600 dark:text-gray-400">
          {fmtTime(job.queuedAt)}
        </td>
        <td className="py-2.5 pr-3 text-gray-600 dark:text-gray-400">
          {job.finishedAt ? fmtTime(job.finishedAt) : "—"}
        </td>
        <td className="py-2.5 pr-3">
          {job.runId ? (
            <button
              onClick={(e) => { e.stopPropagation(); onOpenRun(job.runId!, job.targetId, job.commit); }}
              className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
            >
              view run →
            </button>
          ) : job.status === "failed" ? (
            <span title={job.error || "Unknown error"} className="text-red-600 dark:text-red-400">
              failed
            </span>
          ) : (
            <span className="text-gray-400">—</span>
          )}
        </td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={6} className="p-0">
            <div className="px-4 pb-4 pt-2">
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-lg bg-gray-950 p-3 font-mono text-[11px] leading-relaxed text-gray-200">
                {job.progress.join("")}
              </pre>
              {job.error && (
                <p className="mt-2 text-xs text-red-600 dark:text-red-400">
                  Error: {job.error}
                </p>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
