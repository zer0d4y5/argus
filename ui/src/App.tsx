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
import { Loading, ErrorNote } from "./components";
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
  useEffect(() => {
    if (!authed) return;
    Promise.all([api.summary(), api.runs()])
      .then(([s, r]) => {
        setSummary(s);
        setRuns(r);
        // Default selection: the served repo's latest run; otherwise the
        // newest aggregated run — which may belong to a registered target,
        // so its origin must ride along or the detail fetch 404s.
        setSelectedRun((cur) => {
          if (cur) return cur;
          if (s.latestId) return s.latestId;
          const first = r.runs[0];
          if (first?.target) setSelectedRunTarget(first.target.id);
          return first?.id ?? null;
        });
      })
      .catch(onApiError);
  }, [authed, reloadKey, onApiError]);

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
  const openRun = (runId: string, targetId?: string, commit?: string) => {
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
            <span className="text-lg font-bold">🛡️ appsec</span>
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
            {runs.runs.length > 0 && (
              <label className="hidden items-center gap-1 text-xs text-gray-500 md:flex">
                Run
                <select
                  value={`${selectedRunTarget ?? ""}|${selectedRun ?? ""}`}
                  onChange={(e) => {
                    // Composite value: "<targetId>|<runId>" — run IDs are
                    // timestamps and can collide across stores.
                    const sep = e.target.value.indexOf("|");
                    const tid = e.target.value.slice(0, sep);
                    setSelectedRun(e.target.value.slice(sep + 1));
                    setSelectedRunTarget(tid || undefined);
                    setSelectedRunCommit(undefined);
                  }}
                  className="max-w-[230px] rounded-md border border-gray-300 bg-white px-1.5 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
                >
                  {runs.runs.map((r) => (
                    <option key={`${r.target?.id ?? ""}|${r.id}`} value={`${r.target?.id ?? ""}|${r.id}`}>
                      {r.target ? `${r.target.name} · ` : ""}{fmtTime(r.createdAt)} ({r.total})
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
          (detail ? <Findings detail={detail} origin={origin} canExplain={canExplain} /> : <Loading what="findings" />)}
        {activeTab === "runs" && (
          <Runs
            runs={runs}
            selectedId={selectedRun}
            onSelect={(id, targetId) => {
              setSelectedRun(id);
              setSelectedRunTarget(targetId);
              setSelectedRunCommit(undefined);
              setTab("findings");
            }}
          />
        )}
        {activeTab === "operate" && opsEnabled && <Operate canLaunch={canLaunch} onOpenRun={openRun} />}
        {activeTab === "admin" && role === "admin" && <Admin selfUsername={user?.username ?? ""} />}
      </main>

      <footer className="mt-8 text-center text-[11px] text-gray-400">
        {opsEnabled
          ? "Local-first · authenticated console · actions audited to .appsec/audit.jsonl · finding data rendered inert"
          : "Local-first · read-only (no users configured — bootstrap: appsec user add) · finding data rendered inert"}
      </footer>
    </div>
  );
}
