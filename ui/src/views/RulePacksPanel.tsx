import { useEffect, useState } from "react";
import { opsApi, CatalogPack, ApiError } from "../api";
import { Panel } from "../components";

// The rule-pack catalog: a curated menu of semgrep registry packs grouped by
// language, framework, cloud stack, and weakness class. Enabling a pack adds it
// to the scan's custom rulesets (additive to the profile). Packs already run by
// the active profile are marked, so an admin sees what is new versus redundant.

const hintClass = "mt-1 text-xs text-gray-500 dark:text-gray-400";

const CATEGORY_LABELS: Record<string, string> = {
  language: "Languages",
  framework: "Frameworks & libraries",
  cloud: "Cloud & infrastructure",
  class: "Weakness classes",
};

export function RulePacksPanel(): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [categories, setCategories] = useState<string[]>([]);
  const [packs, setPacks] = useState<CatalogPack[]>([]);
  const [busy, setBusy] = useState<string | null>(null); // pack id being toggled
  const [error, setError] = useState<string | null>(null);

  function load() {
    opsApi
      .ruleCatalog()
      .then((r) => {
        setCategories(r.categories);
        setPacks(r.packs);
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : "Failed to load the rule catalog"))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  async function toggle(pack: CatalogPack) {
    setError(null);
    setBusy(pack.id);
    try {
      await opsApi.toggleRuleset(pack.id, !pack.active);
      const r = await opsApi.ruleCatalog();
      setCategories(r.categories);
      setPacks(r.packs);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to update the pack");
    } finally {
      setBusy(null);
    }
  }

  if (loading) return <Panel title="Rule packs"><div className="text-sm text-gray-500">Loading…</div></Panel>;

  return (
    <Panel title="Rule packs">
      <p className="mb-4 text-sm text-gray-600 dark:text-gray-400">
        Enable extra semgrep rule packs for the stacks you run. Packs add to your profile; nothing here removes the curated baseline.
      </p>
      {error && <div className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</div>}

      <div className="space-y-4">
        {categories.map((cat) => {
          const inCat = packs.filter((p) => p.category === cat);
          if (inCat.length === 0) return null;
          return (
            <div key={cat} className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">{CATEGORY_LABELS[cat] ?? cat}</div>
              <div className="mt-2 space-y-2">
                {inCat.map((p) => (
                  <div key={p.id} className="flex items-center justify-between gap-3 rounded-md border border-gray-200 px-3 py-2 dark:border-gray-700">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{p.label}</span>
                        <span className="font-mono text-[11px] text-gray-400">{p.id}</span>
                        {p.inProfile && (
                          <span className="rounded border border-gray-300 px-1 text-[10px] text-gray-500 dark:border-gray-600 dark:text-gray-400">in profile</span>
                        )}
                        {p.active && (
                          <span className="rounded border border-emerald-500 px-1 text-[10px] text-emerald-600 dark:text-emerald-400">enabled</span>
                        )}
                      </div>
                      <p className={hintClass}>{p.description}</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => toggle(p)}
                      disabled={busy !== null}
                      className={`shrink-0 rounded-md border px-3 py-1 text-xs font-medium disabled:opacity-50 ${
                        p.active
                          ? "border-gray-300 hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800"
                          : "border-accent-500 text-accent-700 hover:bg-accent-50 dark:text-accent-300 dark:hover:bg-accent-500/10"
                      }`}
                    >
                      {busy === p.id ? "…" : p.active ? "Disable" : "Enable"}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
