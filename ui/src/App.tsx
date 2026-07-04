import { useEffect, useState } from "react";
import { api, RunDetail, RunsResponse, SummaryResponse } from "./api";
import { Loading, ErrorNote } from "./components";
import { fmtTime } from "./theme";
import { Overview } from "./views/Overview";
import { Findings } from "./views/Findings";
import { Runs } from "./views/Runs";

type Tab = "overview" | "findings" | "runs";

const TABS: { id: Tab; label: string; persona: string }[] = [
  { id: "overview", label: "Overview", persona: "GRC / exec" },
  { id: "findings", label: "Findings", persona: "AppSec" },
  { id: "runs", label: "Runs", persona: "SecOps" },
];

function tabFromHash(): Tab {
  const h = window.location.hash.replace("#", "");
  return h === "findings" || h === "runs" ? h : "overview";
}

export function App() {
  const [tab, setTabState] = useState<Tab>(tabFromHash);
  const setTab = (t: Tab) => {
    setTabState(t);
    window.location.hash = t;
  };
  const [dark, setDark] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);

  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [runs, setRuns] = useState<RunsResponse | null>(null);
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [selectedRun, setSelectedRun] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  // Initial load: summary + run list.
  useEffect(() => {
    Promise.all([api.summary(), api.runs()])
      .then(([s, r]) => {
        setSummary(s);
        setRuns(r);
        const initial = s.latestId || r.runs[0]?.id || null;
        setSelectedRun(initial);
      })
      .catch((e) => setError(String(e)));
  }, []);

  // Load run detail whenever the selected run changes.
  useEffect(() => {
    if (!selectedRun) return;
    api.run(selectedRun).then(setDetail).catch((e) => setError(String(e)));
  }, [selectedRun]);

  if (error) return <ErrorNote error={error} />;
  if (!summary || !runs) return <Loading what="console" />;

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
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                  tab === t.id
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
                  value={selectedRun ?? ""}
                  onChange={(e) => setSelectedRun(e.target.value)}
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
        {tab === "overview" && <Overview summary={summary} />}
        {tab === "findings" &&
          (detail ? <Findings detail={detail} /> : <Loading what="findings" />)}
        {tab === "runs" && (
          <Runs
            runs={runs}
            selectedId={selectedRun}
            onSelect={(id) => {
              setSelectedRun(id);
              setTab("findings");
            }}
          />
        )}
      </main>

      <footer className="mt-8 text-center text-[11px] text-gray-400">
        Local-first · no auth · reads .appsec/runs · finding data rendered inert (escaped, no HTML injection)
      </footer>
    </div>
  );
}
