import { useCallback, useEffect, useRef, useState } from "react";
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
import { ConsoleSkeleton, ErrorNote, Wordmark, EmptyState } from "./components";
import { CommandPalette, Command } from "./CommandPalette";
import { useToast, useConfirm } from "./toast";
import { fmtTime } from "./theme";
import { Overview } from "./views/Overview";
import { Findings } from "./views/Findings";
import { RunDetailView } from "./views/RunDetailView";
import { Runs } from "./views/Runs";
import { Login } from "./views/Login";
import { Operate } from "./views/Operate";
import { Admin } from "./views/Admin";
import { Tickets } from "./views/Tickets";
import { Threats } from "./views/Threats";
import { Engagements } from "./views/Engagements";

type Tab = "overview" | "findings" | "tickets" | "threats" | "runs" | "operate" | "engagements" | "admin";

// One neutral chip for the role badge — it's identity, not urgency, so it
// stays quiet and lets severity own the app's only saturated color.
const ROLE_CHIP: Record<string, string> = {
  admin: "bg-gray-200 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
  operator: "bg-gray-200 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
  viewer: "bg-gray-200 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
};

// ALL_TARGETS is the portfolio scope: the Overview aggregates every target's
// latest run. The default when nothing is specified.
const ALL_TARGETS = "@all";

// UrlState is the app view encoded in the query string so a view is
// shareable, reload-safe, and back/forward-navigable.
type UrlState = { tab: Tab; target: string; run: string | null; fw: string; sev: string; status: string; item: string };

function readUrlState(): UrlState {
  const p = new URLSearchParams(window.location.search);
  const t = p.get("tab") ?? "";
  const tab = (["findings", "tickets", "threats", "runs", "operate", "admin"].includes(t) ? t : "overview") as Tab;
  return {
    // No target param → portfolio; an explicit (even empty) one is honored.
    target: p.has("target") ? (p.get("target") ?? "") : ALL_TARGETS,
    tab,
    run: p.get("run"),
    fw: p.get("fw") ?? "all",
    sev: p.get("sev") ?? "all",
    status: p.get("st") ?? "all",
    item: p.get("item") ?? "",
  };
}

function urlFromState(s: UrlState): string {
  const p = new URLSearchParams();
  if (s.tab !== "overview") p.set("tab", s.tab);
  if (s.target !== ALL_TARGETS) p.set("target", s.target); // @all is the default, omitted
  if (s.run) p.set("run", s.run);
  if (s.fw !== "all") p.set("fw", s.fw);
  if (s.sev !== "all") p.set("sev", s.sev);
  if (s.status !== "all") p.set("st", s.status);
  if (s.item) p.set("item", s.item);
  const qs = p.toString();
  return qs ? `?${qs}` : window.location.pathname;
}

// PickTarget is shown on Findings/Runs under the portfolio scope: those tabs
// need one target's store, so it invites the user to pick one.
function PickTarget({ what, targets, onPick }: { what: string; targets: Target[]; onPick: (id: string) => void }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-10 text-center dark:border-gray-800 dark:bg-gray-900">
      <p className="text-sm font-medium text-gray-700 dark:text-gray-200">All targets</p>
      <p className="mx-auto mt-1 max-w-md text-sm text-gray-500 dark:text-gray-400">
        The Overview combines every target. Pick one to see its {what}.
      </p>
      <div className="mt-4 flex flex-wrap justify-center gap-2">
        <button onClick={() => onPick("")} className="rounded-md border border-gray-300 px-3 py-1.5 text-xs hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800">
          This repo
        </button>
        {targets.map((t) => (
          <button key={t.id} onClick={() => onPick(t.id)} className="rounded-md border border-gray-300 px-3 py-1.5 text-xs hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800">
            {t.name}{t.type === "cloud" ? " (cloud)" : t.type === "git" ? " (git)" : ""}
          </button>
        ))}
      </div>
    </div>
  );
}

export function App() {
  const [initial] = useState(readUrlState);
  // Captured before the URL-sync effect below rewrites the query: a failed SSO
  // round-trip returns as ?sso_error=1, and the login page surfaces it.
  const [ssoError] = useState(() => new URLSearchParams(window.location.search).has("sso_error"));
  const [tab, setTab] = useState<Tab>(initial.tab);
  const [dark, setDark] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);

  const [me, setMe] = useState<MeResponse | null>(null);
  const [user, setUser] = useState<UserInfo | null>(null);
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [runs, setRuns] = useState<RunsResponse | null>(null);
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [selectedRun, setSelectedRun] = useState<string | null>(initial.run);
  const [selectedRunTarget, setSelectedRunTarget] = useState<string | undefined>(initial.run ? initial.target || undefined : undefined);
  const [selectedRunCommit, setSelectedRunCommit] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [targets, setTargets] = useState<Target[]>([]);
  // "" = the served repo's own run store; otherwise a registered target's id.
  // Overview/Runs/Findings all read this store.
  const [activeTarget, setActiveTarget] = useState<string>(initial.target);
  const [rescanBusy, setRescanBusy] = useState(false);
  // Findings filters lifted here so the Overview panels can deep-link into a
  // filtered Findings view (every stat is a drill-down).
  const [findingsFramework, setFindingsFramework] = useState<string>(initial.fw);
  const [findingsSeverity, setFindingsSeverity] = useState<string>(initial.sev);
  const [findingsStatus, setFindingsStatus] = useState<string>(initial.status);
  // The open side-pane item (a finding fingerprint or ticket id), in the URL
  // so a pane deep-links: shareable and reload-safe. Incidental for history
  // purposes (replaceState), like the filters.
  const [openItem, setOpenItem] = useState<string>(initial.item);
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Keep the URL in lockstep with the view: pushState on navigation-significant
  // changes (tab/target/run) so Back works, replaceState for incidental filter
  // tweaks. A popstate re-applies the URL without re-pushing (navKey guard).
  const navKeyRef = useRef(`${initial.tab}|${initial.target}|${initial.run ?? ""}`);
  useEffect(() => {
    const s: UrlState = { tab, target: activeTarget, run: selectedRun, fw: findingsFramework, sev: findingsSeverity, status: findingsStatus, item: openItem };
    const url = urlFromState(s);
    const navKey = `${tab}|${activeTarget}|${selectedRun ?? ""}`;
    if (navKey !== navKeyRef.current) {
      navKeyRef.current = navKey;
      window.history.pushState(null, "", url);
    } else {
      window.history.replaceState(null, "", url);
    }
  }, [tab, activeTarget, selectedRun, findingsFramework, findingsSeverity, findingsStatus, openItem]);

  useEffect(() => {
    const onPop = () => {
      const s = readUrlState();
      navKeyRef.current = `${s.tab}|${s.target}|${s.run ?? ""}`; // so the sync effect replaces, not pushes
      setTab(s.tab);
      setActiveTarget(s.target);
      setSelectedRun(s.run);
      setSelectedRunTarget(s.run ? s.target || undefined : undefined);
      setFindingsFramework(s.fw);
      setFindingsSeverity(s.sev);
      setFindingsStatus(s.status);
      setOpenItem(s.item);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  // Cmd/Ctrl-K opens the command palette from anywhere; it toggles so the same
  // chord closes it. Ignored while typing in a field other than to open it.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Session expiry mid-use surfaces as a 401 on any call: drop back to the
  // login page instead of a dead error screen.
  const toast = useToast();
  const confirm = useConfirm();

  const onApiError = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) {
      setUser(null);
      setCsrfToken(null);
      return;
    }
    setError(String(e));
  }, []);

  // For action failures (not page loads): a toast, not a full-page error.
  const onActionError = useCallback(
    (e: unknown) => {
      if (e instanceof ApiError && e.status === 401) return onApiError(e);
      toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    },
    [onApiError, toast],
  );

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

  // concreteTarget is the single store the drill-down tabs (Findings/Runs)
  // read. The portfolio scope (@all) with registered targets has no single
  // store, so it's null and those tabs prompt to pick one; @all with no
  // targets is just the served repo ("").
  const isPortfolio = activeTarget === ALL_TARGETS && targets.length > 0;
  const concreteTarget: string | null = isPortfolio ? null : activeTarget === ALL_TARGETS ? "" : activeTarget;

  // The Overview summary follows the selector; @all aggregates every target's
  // latest run into one portfolio posture.
  useEffect(() => {
    if (!authed) return;
    api.summary(activeTarget || undefined).then(setSummary).catch(onApiError);
  }, [authed, activeTarget, reloadKey, onApiError]);

  // Runs (and the Findings latest run) need a concrete store. Under the
  // portfolio scope there is none, so the list is empty and the tabs prompt.
  // runsTarget records which target `runs` was loaded for: on a target switch
  // `runs` is briefly the previous target's list, and a run id from it is a 404
  // against the new target — so consumers must wait until runsTarget matches.
  const [runsTarget, setRunsTarget] = useState<string | null>(null);
  useEffect(() => {
    if (!authed) return;
    if (concreteTarget === null) {
      setRuns({ runs: [] });
      setRunsTarget(null);
      setSelectedRunTarget(undefined);
      return;
    }
    setSelectedRunTarget(concreteTarget || undefined);
    api.runs(concreteTarget || undefined)
      .then((r) => { setRuns(r); setRunsTarget(concreteTarget); })
      .catch(onApiError);
  }, [authed, concreteTarget, reloadKey, onApiError]);

  // The Findings tab shows the concrete target's LATEST run — every current
  // finding, no run to pick. Per-run history lives in the Runs tab. Gate on
  // runsTarget === concreteTarget so a stale run id from the previous target is
  // never fetched against the new one.
  const [latestDetail, setLatestDetail] = useState<RunDetail | null>(null);
  useEffect(() => {
    if (!authed || concreteTarget === null) { setLatestDetail(null); return; }
    if (runsTarget !== concreteTarget) return; // runs list not yet for this target
    const lid = runs?.runs?.[0]?.id;
    if (!lid) { setLatestDetail(null); return; }
    api.run(lid, concreteTarget || undefined).then(setLatestDetail).catch(onApiError);
  }, [authed, concreteTarget, runsTarget, runs, reloadKey, onApiError]);

  // Fetch targets when ops is enabled
  useEffect(() => {
    if (!authed || !me?.authRequired) return;
    opsApi.targets().then((r) => setTargets(r.targets)).catch(() => {});
  }, [authed, me?.authRequired, reloadKey]);

  // detail is the run opened in the Runs tab (its drill-down). Null → the Runs
  // tab shows the list.
  useEffect(() => {
    if (!authed || !selectedRun) { setDetail(null); return; }
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
        toast({ kind: "success", message: "Re-scan queued — results will appear when it finishes." });
        // The run lands when the serial queue finishes; nudge a reload shortly.
        setTimeout(() => setReloadKey((k) => k + 1), 1500);
      })
      .catch(onActionError)
      .finally(() => setRescanBusy(false));
  };

  // Suppress a finding's rule: append its ruleId to the ACTIVE TARGET's
  // ignore list (admin, audited). Only registered targets have a
  // console-editable config; the served repo's own appsec.yml is not touched
  // from here. Preserves the rest of the target's config block.
  const handleSuppress = async (ruleId: string) => {
    const t = targets.find((t) => t.id === activeTarget);
    if (!t || !ruleId) return;
    const existing = t.config ?? {};
    const rules = existing.ignoreRules ?? [];
    if (rules.includes(ruleId)) {
      toast({ kind: "info", message: `Rule "${ruleId}" is already suppressed for this target.` });
      return;
    }
    const ok = await confirm({
      title: `Suppress rule "${ruleId}"?`,
      message: `Findings from this rule will stop appearing for target "${t.name}" (admin action, audited).`,
      confirmLabel: "Suppress",
      danger: true,
    });
    if (!ok) return;
    opsApi
      .updateTarget(activeTarget, { config: { ...existing, ignoreRules: [...rules, ruleId] } })
      .then((updated) => {
        setTargets((prev) => prev.map((x) => (x.id === updated.id ? updated : x)));
        setReloadKey((k) => k + 1);
        toast({ kind: "success", message: `Rule "${ruleId}" suppressed.` });
      })
      .catch(onActionError);
  };

  const handleDeleteRun = async (runId: string) => {
    const ok = await confirm({
      title: "Delete this run from history?",
      message: "This cannot be undone.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok) return;
    opsApi
      .deleteRun(runId, activeTarget || undefined)
      .then(() => {
        if (selectedRun === runId) setSelectedRun(null);
        setReloadKey((k) => k + 1);
        toast({ kind: "success", message: "Run deleted." });
      })
      .catch(onActionError);
  };

  // Deep-links from Overview panels into a filtered Findings view. Each sets
  // its own filter and resets the others so the drill-down is clean.
  const drillTo = (which: "framework" | "severity" | "status", value: string) => {
    setFindingsFramework(which === "framework" ? value : "all");
    setFindingsSeverity(which === "severity" ? value : "all");
    setFindingsStatus(which === "status" ? value : "all");
    setTab("findings");
  };
  const openFramework = (id: string) => drillTo("framework", id);

  // Switch the active scope from the UI (nav dropdown, target pickers, command
  // palette). A run selection is target-scoped — a run of target A is a 404
  // against target B — so clearing it here stops a stale api.run(oldRun,
  // newTarget) fetch on switch. openRun and the URL restore set target+run
  // together and must NOT go through here.
  const switchTarget = (targetId: string) => {
    setActiveTarget(targetId);
    setSelectedRun(null);
    setSelectedRunTarget(undefined);
    setSelectedRunCommit(undefined);
  };

  // Open one run's detail in the Runs tab (from a row, a deep link, or Operate).
  const openRun = (runId: string, targetId?: string, commit?: string) => {
    setActiveTarget(targetId ?? "");
    setSelectedRun(runId);
    setSelectedRunTarget(targetId);
    setSelectedRunCommit(commit);
    setFindingsFramework("all");
    setFindingsSeverity("all");
    setFindingsStatus("all");
    setTab("runs");
  };

  if (error) return <ErrorNote error={error} />;
  if (me === null) return <ConsoleSkeleton />;
  if (me.authRequired && !user) return <Login onLogin={handleLogin} ssoEnabled={!!me.ssoEnabled} ssoError={ssoError} />;
  if (!summary || !runs) return <ConsoleSkeleton />;

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

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "findings", label: "Findings" },
    { id: "tickets", label: "Tickets" },
    { id: "threats", label: "Threats" },
    { id: "runs", label: "Runs" },
    ...(opsEnabled ? [{ id: "operate" as Tab, label: "Operate" }] : []),
    ...(opsEnabled ? [{ id: "engagements" as Tab, label: "Engagements" }] : []),
    ...(opsEnabled && role === "admin" ? [{ id: "admin" as Tab, label: "Admin" }] : []),
  ];
  const activeTab = tabs.some((t) => t.id === tab) ? tab : "overview";

  // Command palette actions, rebuilt from live state (tabs, targets, filters).
  // Picking a filter or target drops you into Findings, where it takes effect.
  const commands: Command[] = [
    ...tabs.map((t) => ({
      id: `nav-${t.id}`,
      group: "Go to",
      label: t.label,
      keywords: "view tab navigate",
      run: () => setTab(t.id),
    })),
    {
      id: "target-all",
      group: "Target",
      label: "All targets (portfolio)",
      keywords: "scope overview aggregate",
      run: () => {
        switchTarget(ALL_TARGETS);
        setTab("overview");
      },
    },
    {
      id: "target-repo",
      group: "Target",
      label: "This repo",
      keywords: "scope served",
      run: () => {
        switchTarget("");
        setTab("findings");
      },
    },
    ...targets.map((t) => ({
      id: `target-${t.id}`,
      group: "Target",
      label: `${t.name}${t.type === "cloud" ? " (cloud)" : t.type === "git" ? " (git)" : ""}`,
      keywords: "scope",
      run: () => {
        switchTarget(t.id);
        setTab("findings");
      },
    })),
    ...(["critical", "high", "medium", "low"] as const).map((sev) => ({
      id: `sev-${sev}`,
      group: "Filter severity",
      label: `Severity: ${sev}`,
      keywords: "risk",
      run: () => {
        setFindingsSeverity(sev);
        setTab("findings");
      },
    })),
    ...(["open", "in-progress", "accepted-risk", "false-positive", "fixed"] as const).map((st) => ({
      id: `status-${st}`,
      group: "Filter status",
      label: `Status: ${st}`,
      keywords: "disposition workflow",
      run: () => {
        setFindingsStatus(st);
        setTab("findings");
      },
    })),
    {
      id: "filters-clear",
      group: "Filter status",
      label: "Clear all filters",
      keywords: "reset severity status framework",
      run: () => {
        setFindingsSeverity("all");
        setFindingsStatus("all");
        setFindingsFramework("all");
      },
    },
    {
      id: "toggle-theme",
      group: "Actions",
      label: dark ? "Switch to light theme" : "Switch to dark theme",
      keywords: "dark mode appearance",
      run: () => setDark((d) => !d),
    },
    ...(user
      ? [{ id: "sign-out", group: "Actions", label: "Sign out", keywords: "logout", run: handleLogout }]
      : []),
  ];

  return (
    <div className="mx-auto min-h-full max-w-7xl px-4 pb-16">
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
      <header className="sticky top-0 z-10 -mx-4 mb-4 border-b border-gray-200 bg-gray-50/90 px-4 py-3 backdrop-blur dark:border-gray-800 dark:bg-gray-950/90">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <Wordmark size={30} className="text-xl" />
            <span className="rounded bg-gray-200 px-1.5 py-0.5 text-[11px] font-semibold uppercase text-gray-600 dark:bg-gray-800 dark:text-gray-300">
              console
            </span>
          </div>

          <nav className="flex gap-1">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`rounded-md px-3.5 py-2 text-base font-medium transition ${
                  activeTab === t.id
                    ? "bg-accent-100 text-accent-700 dark:bg-accent-500/15 dark:text-accent-200"
                    : "text-gray-600 hover:bg-gray-200 dark:text-gray-300 dark:hover:bg-gray-800"
                }`}
              >
                {t.label}
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            {opsEnabled && targets.length > 0 && (
              <label className="hidden items-center gap-1.5 text-sm text-gray-500 lg:flex">
                Target
                <select
                  value={activeTarget}
                  onChange={(e) => switchTarget(e.target.value)}
                  className="max-w-[200px] rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                  title="Scope. All targets = portfolio Overview; pick one to drill into its Findings and Runs"
                >
                  <option value={ALL_TARGETS}>All targets</option>
                  <option value="">This repo</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}{t.type === "cloud" ? " (cloud)" : t.type === "git" ? " (git)" : ""}
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
              onClick={() => setPaletteOpen(true)}
              className="hidden items-center gap-1.5 rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-500 hover:bg-gray-200 sm:flex dark:border-gray-700 dark:text-gray-400 dark:hover:bg-gray-800"
              title="Command palette"
            >
              <span>Search</span>
              <kbd className="font-mono text-[10px]">⌘K</kbd>
            </button>
            <button
              onClick={() => setDark((d) => !d)}
              className="rounded-md border border-gray-300 px-2 py-1 text-sm dark:border-gray-700"
              title="Toggle theme"
            >
              {dark ? "☀️" : "🌙"}
            </button>
          </div>
        </div>
      </header>

      <main>
        {activeTab === "overview" && (
          <Overview
            summary={summary}
            onSelectFramework={openFramework}
            onSelectSeverity={(sev) => drillTo("severity", sev)}
            onSelectStatus={(st) => drillTo("status", st)}
            onGoTo={(t) => setTab(t)}
          />
        )}
        {activeTab === "findings" &&
          (concreteTarget === null ? (
            <PickTarget what="findings" targets={targets} onPick={switchTarget} />
          ) : latestDetail ? (
            <Findings
              detail={latestDetail}
              origin={concreteTarget ? { targetId: concreteTarget } : undefined}
              canExplain={canExplain}
              canRemediate={role === "admin"}
              canConfirm={role === "admin"}
              canSuppress={role === "admin" && !!concreteTarget}
              onSuppress={handleSuppress}
              framework={findingsFramework}
              onFrameworkChange={setFindingsFramework}
              severity={findingsSeverity}
              onSeverityChange={setFindingsSeverity}
              status={findingsStatus}
              onStatusChange={setFindingsStatus}
              openItem={openItem}
              onOpenItemChange={setOpenItem}
            />
          ) : (
            <EmptyState title="No findings yet" hint="Save a scan (argus scan --save, or the Operate tab) to populate this view." />
          ))}
        {activeTab === "runs" &&
          (concreteTarget === null ? (
            <PickTarget what="runs" targets={targets} onPick={switchTarget} />
          ) : selectedRun && detail ? (
            <RunDetailView
              detail={detail}
              runLabel={fmtTime(runs.runs.find((r) => r.id === selectedRun)?.createdAt ?? "")}
              targetId={concreteTarget || undefined}
              origin={origin}
              onBack={() => setSelectedRun(null)}
              onSelectFramework={openFramework}
              canExplain={canExplain}
              canRemediate={role === "admin"}
              canConfirm={role === "admin"}
              canSuppress={role === "admin" && !!concreteTarget}
              onSuppress={handleSuppress}
              framework={findingsFramework}
              onFrameworkChange={setFindingsFramework}
              severity={findingsSeverity}
              onSeverityChange={setFindingsSeverity}
              status={findingsStatus}
              onStatusChange={setFindingsStatus}
            />
          ) : (
            <Runs
              runs={runs}
              selectedId={selectedRun}
              onSelect={(id) => {
                setSelectedRun(id);
                setFindingsFramework("all");
                setFindingsSeverity("all");
                setFindingsStatus("all");
              }}
              activeTarget={concreteTarget}
              canLaunch={canLaunch}
              canDelete={role === "admin"}
              rescanBusy={rescanBusy}
              onRescan={handleRescan}
              onDeleteRun={handleDeleteRun}
            />
          ))}
        {activeTab === "tickets" && <Tickets canEdit={canLaunch} canDelete={role === "admin"} openItem={openItem} onOpenItemChange={setOpenItem} githubRepo={me?.githubRepo} />}
        {activeTab === "threats" && <Threats canEdit={canLaunch} canDelete={role === "admin"} target={activeTarget === ALL_TARGETS ? "" : activeTarget} />}
        {activeTab === "operate" && opsEnabled && <Operate canLaunch={canLaunch} onOpenRun={openRun} />}
        {activeTab === "engagements" && opsEnabled && <Engagements canManage={role === "admin"} />}
        {activeTab === "admin" && role === "admin" && <Admin selfUsername={user?.username ?? ""} />}
      </main>

      <footer className="mt-8 text-center text-[11px] text-gray-400">
        {opsEnabled
          ? "Local-first · authenticated console · actions audited to .appsec/audit.jsonl · finding data rendered inert"
          : "Local-first · read-only (no users configured — bootstrap: argus user add) · finding data rendered inert"}
      </footer>
    </div>
  );
}
