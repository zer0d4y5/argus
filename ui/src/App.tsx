import { useCallback, useEffect, useState } from "react";
import {
  api,
  opsApi,
  setCsrfToken,
  ApiError,
  MeResponse,
  UserInfo,
  RunDetail,
  RunsResponse,
  SummaryResponse,
  Target,
} from "./api";
import { Loading, ErrorNote, Wordmark } from "./components";
import { fmtTime } from "./theme";
import { Overview } from "./views/Overview";
import { Findings } from "./views/Findings";
import { Runs } from "./views/Runs";
import { Login } from "./views/Login";
import { Operate } from "./views/Operate";
import { Admin } from "./views/Admin";

type Tab = "overview" | "findings" | "runs" | "operate" | "admin";

const ROLE_CHIP: Record<string, string> = {
  admin: "bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300",
  operator: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300",
  viewer: "bg-gray-200 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
};

function tabFromHash(): Tab {
  const h = window.location.hash.replace("#", "");
  return h === "findings" || h === "runs" || h === "operate" || h === "admin" ? h : "overview";
}

export function App() {
  const [tab, setTabState] = useState<Tab>(tabFromHash);
  const setTab = (t: Tab) => {
    setTabState(t);
    window.location.hash = t;
  };
  const [dark, setDark] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);

  const [me, setMe] = useState<MeResponse | null>(null);
  const [user, setUser] = useState<UserInfo | null>(null);
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [runs, setRuns] = useState<RunsResponse | null>(null);
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [selectedRun, setSelectedRun] = useState<string | null>(null);
  const [selectedRunTarget, setSelectedRunTarget] = useState<string | undefined>(undefined);
  const [selectedRunCommit, setSelectedRunCommit] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [targets, setTargets] = useState<Target[]>([]);
  // "" = the served repo's own run store; otherwise a registered target's id.
  // Overview/Runs/Findings all read this store.
  const [activeTarget, setActiveTarget] = useState<string>("");
  const [rescanBusy, setRescanBusy] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  // Session expiry mid-use surfaces as a 401 on any call: drop back to the
  // login page instead of a dead error screen.
  const onApiError = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) {
      setUser(null);
      setCsrfToken(null);
      return;
    }
    setError(String(e));
  }, []);

  // Boot: ask the server whether this console requires a login at all.
  useEffect(() => {
    opsApi
      .me()
      .then((m) => {
        setMe(m);
        if (m.authenticated && m.user) {
          setUser(m.user);
          setCsrfToken(m.csrfToken ?? null);
        }
      })
      .catch((e) => setError(String(e)));
  }, []);

  const authed = me !== null && (!me.authRequired || user !== null);

  // Load read data once authenticated (or immediately in zero-users mode).
  // Everything is scoped to the active target (empty = the served repo's own
  // store): Overview, Runs, and the run picker all follow it, so a scan
  // launched against a registered target shows up instead of vanishing into a
  // store nothing reads. Changing the target resets the selected run.
  useEffect(() => {
    if (!authed) return;
    const tgt = activeTarget || undefined;
    Promise.all([api.summary(tgt), api.runs(tgt)])
      .then(([s, r]) => {
        setSummary(s);
        setRuns(r);
        setSelectedRunTarget(tgt);
        setSelectedRun(s.latestId || r.runs?.[0]?.id || null);
      })
      .catch(onApiError);
  }, [authed, activeTarget, reloadKey, onApiError]);

  // Fetch targets when ops is enabled
  useEffect(() => {
    if (!authed || !me?.authRequired) return;
    opsApi.targets().then((r) => setTargets(r.targets)).catch(() => {});
  }, [authed, me?.authRequired, reloadKey]);

  useEffect(() => {
    if (!authed || !selectedRun) return;
    api.run(selectedRun, selectedRunTarget).then(setDetail).catch(onApiError);
  }, [authed, selectedRun, selectedRunTarget, onApiError]);

  const handleLogin = (u: UserInfo, csrf: string) => {
    setCsrfToken(csrf);
    setUser(u);
  };

  const handleLogout = () => {
    opsApi.logout().catch(() => undefined);
    setCsrfToken(null);
    setUser(null);
    setSummary(null);
    setRuns(null);
    setDetail(null);
    setSelectedRunTarget(undefined);
    setSelectedRunCommit(undefined);
    setTab("overview");
  };

  // A finished job links straight to its run: refresh the lists so the new
  // run exists in the picker, then open it in Findings.
  // Re-scan the active target: enqueue a job (options default; cloud targets
  // take none) and refresh the lists so the run appears when the queue
  // finishes. Closes the remediation loop — "re-scan to confirm the fix".
  const handleRescan = () => {
    if (!activeTarget || rescanBusy) return;
    setRescanBusy(true);
    opsApi
      .launchScan(activeTarget, {})
      .then(() => {
        // The run lands when the serial queue finishes; nudge a reload shortly.
        setTimeout(() => setReloadKey((k) => k + 1), 1500);
      })
      .catch(onApiError)
      .finally(() => setRescanBusy(false));
  };

  // Suppress a finding's rule: append its ruleId to the ACTIVE TARGET's
  // ignore list (admin, audited). Only registered targets have a
  // console-editable config; the served repo's own appsec.yml is not touched
  // from here. Preserves the rest of the target's config block.
  const handleSuppress = (ruleId: string) => {
    const t = targets.find((t) => t.id === activeTarget);
    if (!t || !ruleId) return;
    const existing = t.config ?? {};
    const rules = existing.ignoreRules ?? [];
    if (rules.includes(ruleId)) {
      window.alert(`Rule "${ruleId}" is already suppressed for this target.`);
      return;
    }
    if (!window.confirm(`Suppress rule "${ruleId}" for target "${t.name}"? Findings from this rule will stop appearing (admin action, audited).`))
      return;
    opsApi
      .updateTarget(activeTarget, { config: { ...existing, ignoreRules: [...rules, ruleId] } })
      .then((updated) => {
        setTargets((prev) => prev.map((x) => (x.id === updated.id ? updated : x)));
        setReloadKey((k) => k + 1);
      })
      .catch(onApiError);
  };

  const handleDeleteRun = (runId: string) => {
    if (!window.confirm("Delete this run from history? This cannot be undone.")) return;
    opsApi
      .deleteRun(runId, activeTarget || undefined)
      .then(() => {
        if (selectedRun === runId) setSelectedRun(null);
        setReloadKey((k) => k + 1);
      })
      .catch(onApiError);
  };

  const openRun = (runId: string, targetId?: string, commit?: string) => {
    // Switch the whole app to that run's target so Overview/Runs agree with
    // the finding drawer, then open it.
    setActiveTarget(targetId ?? "");
    setSelectedRun(runId);
    setSelectedRunTarget(targetId);
    setSelectedRunCommit(commit);
    setReloadKey((k) => k + 1);
    setTab("findings");
  };

  if (error) return <ErrorNote error={error} />;
  if (me === null) return <Loading what="console" />;
  if (me.authRequired && !user) return <Login onLogin={handleLogin} />;
  if (!summary || !runs) return <Loading what="console" />;

  const role = user?.role ?? "";
  const opsEnabled = me.authRequired; // zero users = the read-only console
  const canLaunch = role === "operator" || role === "admin";
  const canExplain = opsEnabled && (role === "operator" || role === "admin");

  // Build origin for Findings if a target-scoped run is selected
  let origin: { targetId?: string; gitUrl?: string; commit?: string } | undefined;
  if (selectedRunTarget) {
    const t = targets.find((t) => t.id === selectedRunTarget);
    if (t) {
      origin = { targetId: t.id, gitUrl: t.url, commit: selectedRunCommit };
    } else {
      origin = { targetId: selectedRunTarget, commit: selectedRunCommit };
    }
  }

  const tabs: { id: Tab; label: string; persona: string }[] = [
    { id: "overview", label: "Overview", persona: "GRC / exec" },
    { id: "findings", label: "Findings", persona: "AppSec" },
    { id: "runs", label: "Runs", persona: "SecOps" },
    ...(opsEnabled ? [{ id: "operate" as Tab, label: "Operate", persona: "scan jobs" }] : []),
    ...(opsEnabled && role === "admin" ? [{ id: "admin" as Tab, label: "Admin", persona: "users / audit" }] : []),
  ];
  const activeTab = tabs.some((t) => t.id === tab) ? tab : "overview";

  return (
    <div className="mx-auto min-h-full max-w-7xl px-4 pb-16">
      <header className="sticky top-0 z-10 -mx-4 mb-4 border-b border-gray-200 bg-gray-50/90 px-4 py-3 backdrop-blur dark:border-gray-800 dark:bg-gray-950/90">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <Wordmark size={22} className="text-lg" />
            <span className="rounded bg-gray-200 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-gray-600 dark:bg-gray-800 dark:text-gray-300">
              console
            </span>
          </div>

          <nav className="flex gap-1">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                  activeTab === t.id
                    ? "bg-blue-600 text-white"
                    : "text-gray-600 hover:bg-gray-200 dark:text-gray-300 dark:hover:bg-gray-800"
                }`}
                title={t.persona}
              >
                {t.label}
                <span className="ml-1.5 hidden text-[10px] opacity-70 sm:inline">{t.persona}</span>
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            {opsEnabled && targets.length > 0 && (
              <label className="hidden items-center gap-1 text-xs text-gray-500 lg:flex">
                Target
                <select
                  value={activeTarget}
                  onChange={(e) => setActiveTarget(e.target.value)}
                  className="max-w-[200px] rounded-md border border-gray-300 bg-white px-1.5 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
                  title="Which run history to show across Overview, Runs, and Findings"
                >
                  <option value="">This repo</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}{t.type === "cloud" ? " (cloud)" : t.type === "git" ? " (git)" : ""}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {runs.runs.length > 0 && (
              <label className="hidden items-center gap-1 text-xs text-gray-500 md:flex">
                Run
                <select
                  value={selectedRun ?? ""}
                  onChange={(e) => {
                    setSelectedRun(e.target.value);
                    setSelectedRunCommit(undefined);
                  }}
                  className="max-w-[190px] rounded-md border border-gray-300 bg-white px-1.5 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
                >
                  {runs.runs.map((r) => (
                    <option key={r.id} value={r.id}>
                      {fmtTime(r.createdAt)} ({r.total})
                    </option>
                  ))}
                </select>
              </label>
            )}
            {user && (
              <div className="flex items-center gap-2 text-xs">
                <span className="font-medium">{user.username}</span>
                <span className={`rounded px-1.5 py-0.5 font-semibold ${ROLE_CHIP[role] || ROLE_CHIP.viewer}`}>
                  {role}
                </span>
                <button
                  onClick={handleLogout}
                  className="rounded-lg border border-gray-300 px-2 py-1 text-xs text-gray-600 hover:bg-gray-200 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
                >
                  Sign out
                </button>
              </div>
            )}
            <button
              onClick={() => setDark((d) => !d)}
              className="rounded-lg border border-gray-300 px-2 py-1 text-sm dark:border-gray-700"
              title="Toggle theme"
            >
              {dark ? "☀️" : "🌙"}
            </button>
          </div>
        </div>
      </header>

      <main>
        {activeTab === "overview" && <Overview summary={summary} />}
        {activeTab === "findings" &&
          (detail ? (
            <Findings
              detail={detail}
              origin={origin}
              canExplain={canExplain}
              canSuppress={role === "admin" && !!activeTarget}
              onSuppress={handleSuppress}
            />
          ) : (
            <Loading what="findings" />
          ))}
        {activeTab === "runs" && (
          <Runs
            runs={runs}
            selectedId={selectedRun}
            onSelect={(id) => {
              setSelectedRun(id);
              setTab("findings");
            }}
            activeTarget={activeTarget}
            canLaunch={canLaunch}
            canDelete={role === "admin"}
            rescanBusy={rescanBusy}
            onRescan={handleRescan}
            onDeleteRun={handleDeleteRun}
          />
        )}
        {activeTab === "operate" && opsEnabled && <Operate canLaunch={canLaunch} onOpenRun={openRun} />}
        {activeTab === "admin" && role === "admin" && <Admin selfUsername={user?.username ?? ""} />}
      </main>

      <footer className="mt-8 text-center text-[11px] text-gray-400">
        {opsEnabled
          ? "Local-first · authenticated console · actions audited to .appsec/audit.jsonl · finding data rendered inert"
          : "Local-first · read-only (no users configured — bootstrap: bulwark user add) · finding data rendered inert"}
      </footer>
    </div>
  );
}
