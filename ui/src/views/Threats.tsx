import { useCallback, useEffect, useMemo, useState } from "react";
import {
  opsApi, ThreatModel, ThreatModelDetail, Threat, ThreatStatus, StrideCategory, LibraryComponent, ThreatSuggestion, ApiError, ComponentSuggestion,
} from "../api";
import { Panel, Loading, EmptyState } from "../components";
import { useToast, useConfirm } from "../toast";
import { exportThreatsCSV, exportThreatsJSON } from "../export";
import { ThreatCanvas } from "./ThreatCanvas";

const STRIDE: { key: StrideCategory; label: string }[] = [
  { key: "spoofing", label: "Spoofing" },
  { key: "tampering", label: "Tampering" },
  { key: "repudiation", label: "Repudiation" },
  { key: "info-disclosure", label: "Information disclosure" },
  { key: "denial-of-service", label: "Denial of service" },
  { key: "elevation", label: "Elevation of privilege" },
];
const STATUS_LABEL: Record<ThreatStatus, string> = {
  open: "Open", mitigated: "Mitigated", accepted: "Accepted", transferred: "Transferred",
};
const STATUS_DOT: Record<ThreatStatus, string> = {
  open: "#c92a30", mitigated: "#1f8a4c", accepted: "#c98a10", transferred: "#6b7386",
};
const selectClass = "rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800";

export function Threats({ canEdit, canDelete, target }: { canEdit: boolean; canDelete: boolean; target: string }) {
  const [models, setModels] = useState<ThreatModel[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ThreatModelDetail | null>(null);
  const [library, setLibrary] = useState<LibraryComponent[]>([]);
  const [creating, setCreating] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const toast = useToast();
  const confirm = useConfirm();

  const load = useCallback(() => {
    opsApi.threatModels().then((r) => setModels(r.models)).catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, []);
  useEffect(() => { load(); }, [load, reloadKey]);
  useEffect(() => { opsApi.threatLibrary().then((r) => setLibrary(r.components)).catch(() => {}); }, []);

  const selected = useMemo(() => models?.find((m) => m.id === selectedId) ?? models?.[0] ?? null, [models, selectedId]);
  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    let live = true;
    opsApi.threatModel(selected.id).then((d) => live && setDetail(d)).catch(() => live && setDetail(null));
    return () => { live = false; };
  }, [selected, reloadKey]);

  const refresh = () => setReloadKey((k) => k + 1);
  const err = (e: unknown) => toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });

  const [generating, setGenerating] = useState(false);
  const generateFromIaC = async () => {
    setGenerating(true);
    try {
      const r = await opsApi.threatModelFromTarget(target, "Baseline from IaC");
      toast({ kind: "success", message: `Baseline created: ${r.components} component(s), ${r.threats} threat(s).` });
      setSelectedId(r.modelId);
      refresh();
    } catch (e) {
      err(e);
    } finally {
      setGenerating(false);
    }
  };

  const remove = async () => {
    if (!selected) return;
    const ok = await confirm({ title: "Delete this threat model?", message: "The model, its components, and its threats are removed. Findings are untouched.", confirmLabel: "Delete", danger: true });
    if (!ok) return;
    try { await opsApi.deleteThreatModel(selected.id); setSelectedId(null); refresh(); toast({ kind: "success", message: "Model deleted." }); }
    catch (e) { err(e); }
  };

  if (error) return <div className="m-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300">{error}</div>;
  if (models === null) return <Loading what="threat models" />;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
      <div className="lg:col-span-2">
        <Panel
          title={`Threat models (${models.length})`}
          right={canEdit ? (
            <div className="flex items-center gap-2">
              <button onClick={generateFromIaC} disabled={generating} className="rounded-md border border-gray-300 px-2.5 py-1 text-xs font-medium hover:bg-gray-100 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-800" title="Scan the current target's IaC and build a baseline model">
                {generating ? "Scanning…" : "Generate from IaC"}
              </button>
              <button onClick={() => setCreating(true)} className="rounded-md bg-accent-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-accent-700">New model</button>
            </div>
          ) : undefined}
        >
          {creating && <CreateModel onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); setSelectedId(id); refresh(); }} onErr={err} />}
          {models.length === 0 && !creating ? (
            <EmptyState title="No threat models" hint={canEdit ? "Create a model for an application, add its components, and enumerate STRIDE threats over them." : "An operator can create a threat model to enumerate STRIDE threats."} />
          ) : (
            <div className="divide-y divide-gray-100 dark:divide-gray-800">
              {models.map((m) => (
                <button key={m.id} onClick={() => setSelectedId(m.id)} className={`block w-full px-1 py-2 text-left ${selected?.id === m.id ? "bg-accent-100 dark:bg-accent-500/10" : "hover:bg-gray-50 dark:hover:bg-gray-800/50"}`}>
                  <span className="block text-sm font-medium">{m.name}</span>
                  <span className="font-mono text-[11px] text-gray-400">{m.id}{m.targetId ? ` · ${m.targetId}` : ""}</span>
                </button>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="min-w-0 lg:col-span-3">
        {selected && detail ? (
          <ModelDetail detail={detail} library={library} canEdit={canEdit} canDelete={canDelete} onChange={refresh} onDelete={remove} onErr={err} />
        ) : (
          <Panel title="Model"><p className="py-10 text-center text-sm text-gray-500">Select a model to see its components and threats.</p></Panel>
        )}
      </div>
    </div>
  );
}

function CreateModel({ onClose, onCreated, onErr }: { onClose: () => void; onCreated: (id: string) => void; onErr: (e: unknown) => void }) {
  const [name, setName] = useState("");
  const submit = async () => {
    if (!name.trim()) return;
    try { const m = await opsApi.createThreatModel({ name }); onCreated(m.id); } catch (e) { onErr(e); }
  };
  return (
    <div className="mb-3 flex gap-2 rounded-lg border border-gray-200 bg-gray-50 p-2 dark:border-gray-800 dark:bg-gray-800/40">
      <input autoFocus value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && submit()} placeholder="Model name (e.g. Checkout service)" className="min-w-0 flex-1 rounded-md border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-900" />
      <button onClick={onClose} className="rounded-md border border-gray-300 px-2.5 py-1 text-xs dark:border-gray-700">Cancel</button>
      <button onClick={submit} disabled={!name.trim()} className="rounded-md bg-accent-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-accent-700 disabled:opacity-50">Create</button>
    </div>
  );
}

function ModelDetail({ detail, library, canEdit, canDelete, onChange, onDelete, onErr }: {
  detail: ThreatModelDetail; library: LibraryComponent[]; canEdit: boolean; canDelete: boolean;
  onChange: () => void; onDelete: () => void; onErr: (e: unknown) => void;
}) {
  const byCategory = useMemo(() => {
    const m: Record<string, Threat[]> = {};
    for (const t of detail.threats) (m[t.category] ??= []).push(t);
    return m;
  }, [detail.threats]);

  const enumerate = async (componentId: string) => {
    try { await opsApi.enumerateComponent(detail.id, componentId); onChange(); }
    catch (e) { onErr(e); }
  };
  const setStatus = async (threatId: string, status: ThreatStatus) => {
    try { await opsApi.setThreatStatus(detail.id, threatId, status); onChange(); } catch (e) { onErr(e); }
  };

  const [view, setView] = useState<"list" | "canvas">("list");
  const savePositions = async (positions: { componentId: string; x: number; y: number; w?: number; h?: number }[]) => {
    try { await opsApi.saveThreatPositions(detail.id, positions); } catch (e) { onErr(e); }
  };
  const addCanvasComponent = async (kind: string, x: number, y: number) => {
    try { await opsApi.addThreatComponent(detail.id, { name: "New " + kind, kind, x, y }); onChange(); } catch (e) { onErr(e); }
  };
  const updateCanvasComponent = async (id: string, req: { name: string; tech?: string; kind?: string }) => {
    try { await opsApi.updateThreatComponent(detail.id, id, req); onChange(); } catch (e) { onErr(e); }
  };
  const deleteCanvasComponent = async (id: string) => {
    try { await opsApi.removeThreatComponent(detail.id, id); onChange(); } catch (e) { onErr(e); }
  };
  const addFlow = async (fromId: string, toId: string, label: string) => {
    try { await opsApi.addThreatFlow(detail.id, { fromId, toId, label: label || undefined }); onChange(); } catch (e) { onErr(e); }
  };
  const removeFlow = async (flowId: string) => {
    try { await opsApi.removeThreatFlow(detail.id, flowId); onChange(); } catch (e) { onErr(e); }
  };

  const [suggestions, setSuggestions] = useState<ThreatSuggestion[] | null>(null);
  const [suggesting, setSuggesting] = useState(false);
  const suggest = async () => {
    setSuggesting(true);
    try {
      const r = await opsApi.suggestThreats(detail.id);
      setSuggestions(r.suggestions);
      if (r.suggestions.length === 0) onErr("The model suggested no new threats.");
    } catch (e) { onErr(e); } finally { setSuggesting(false); }
  };
  const confirm = async (s: ThreatSuggestion) => {
    try {
      await opsApi.addThreat(detail.id, { category: s.category, title: s.title, description: s.description, source: "assisted" });
      setSuggestions((prev) => prev?.filter((x) => x !== s) ?? null);
      onChange();
    } catch (e) { onErr(e); }
  };

  const [compSuggestions, setCompSuggestions] = useState<ComponentSuggestion[] | null>(null);
  const [compSuggesting, setCompSuggesting] = useState(false);
  const suggestComponents = async () => {
    setCompSuggesting(true);
    try {
      const r = await opsApi.suggestComponents(detail.id);
      setCompSuggestions(r.suggestions);
      if (r.suggestions.length === 0) onErr("The model suggested no new components.");
    } catch (e) { onErr(e); } finally { setCompSuggesting(false); }
  };
  const confirmComponent = async (s: ComponentSuggestion) => {
    try {
      await opsApi.addThreatComponent(detail.id, { name: s.name, tech: s.tech ?? "", kind: s.kind, notes: s.rationale ?? "", source: "assisted" });
      setCompSuggestions((prev) => prev?.filter((x) => x !== s) ?? null);
      onChange();
    } catch (e) { onErr(e); }
  };

  const confirmDlg = useConfirm();
  const removeComponent = async (componentId: string) => {
    const ok = await confirmDlg({ title: "Remove this component?", message: "Its enumerated threats are removed with it.", confirmLabel: "Remove", danger: true });
    if (!ok) return;
    try {
      await opsApi.removeThreatComponent(detail.id, componentId);
      onChange();
    } catch (e) { onErr(e); }
  };

  const removeThreat = async (threatId: string) => {
    const ok = await confirmDlg({ title: "Remove this threat?", message: "Links to findings are removed with it.", confirmLabel: "Remove", danger: true });
    if (!ok) return;
    try {
      await opsApi.removeThreat(detail.id, threatId);
      onChange();
    } catch (e) { onErr(e); }
  };

  return (
    <Panel
      title={detail.id}
      right={
        <span className="flex items-center gap-2">
          <span className="flex items-center rounded-md border border-gray-300 text-[11px] dark:border-gray-700">
            {(["list", "canvas"] as const).map((v) => (
              <button key={v} onClick={() => setView(v)} className={`px-2 py-0.5 font-medium capitalize ${view === v ? "bg-accent-600 text-white" : "hover:bg-gray-100 dark:hover:bg-gray-800"} ${v === "list" ? "rounded-l" : "rounded-r"}`}>
                {v}
              </button>
            ))}
          </span>
          {detail.threats.length > 0 && (
            <span className="flex items-center gap-1 text-[11px]">
              <span className="text-gray-400">Export</span>
              <button onClick={() => exportThreatsCSV(detail.threats, { components: detail.components, links: detail.links })} className="rounded border border-gray-300 px-1.5 py-0.5 font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800">CSV</button>
              <button onClick={() => exportThreatsJSON(detail.threats)} className="rounded border border-gray-300 px-1.5 py-0.5 font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800">JSON</button>
            </span>
          )}
          {canDelete && <button onClick={onDelete} className="text-xs text-gray-400 hover:text-red-600 dark:hover:text-red-400">Delete</button>}
        </span>
      }
    >
      <h3 className="text-base font-semibold">{detail.name}</h3>
      {detail.description && <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">{detail.description}</p>}

      {view === "canvas" && (
        <div className="mt-4">
          <ThreatCanvas
            detail={detail}
            canEdit={canEdit}
            library={library}
            onSavePositions={savePositions}
            onAddComponent={addCanvasComponent}
            onUpdateComponent={updateCanvasComponent}
            onDeleteComponent={deleteCanvasComponent}
            onAddFlow={addFlow}
            onRemoveFlow={removeFlow}
          />
          <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
            Add nodes from the toolbar and click the canvas to place them; click a node to rename, re-tech, or delete it; drag to move. Give a selected trust boundary a zone type (DMZ, VPC, subnet…) and drag its corner to resize. The red badge counts a component's threats.
          </p>
        </div>
      )}

      <div className={view === "canvas" ? "hidden" : ""}>
      <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
        <div className="flex items-center justify-between">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Components ({detail.components.length})</div>
          {canEdit && (
            <button onClick={suggestComponents} disabled={compSuggesting} className="inline-flex items-center gap-1 rounded-md border border-amber-400/50 px-2 py-0.5 text-[11px] font-medium text-amber-600 hover:bg-amber-50 disabled:opacity-50 dark:text-amber-400 dark:hover:bg-amber-950/30" title="Ask the local LLM to propose components from the repo layout (you confirm each)">
              {compSuggesting ? "Thinking…" : "AI suggest"}
            </button>
          )}
        </div>
        {compSuggestions && compSuggestions.length > 0 && (
          <div className="mt-2 rounded-md border border-amber-400/40 bg-amber-50/50 p-2 dark:bg-amber-950/20">
            <div className="mb-1 text-[11px] font-medium text-amber-700 dark:text-amber-400">Suggested — advisory, confirm to keep</div>
            <ul className="space-y-1">
              {compSuggestions.map((s, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <span className="min-w-0 flex-1">
                    <span className="font-medium">{s.name}</span>
                    {s.tech && <span className="ml-1 rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[10px] text-gray-500 dark:bg-gray-800">{s.tech}</span>}
                    {s.kind && s.kind !== "component" && <span className="ml-1 text-gray-400">· {s.kind}</span>}
                    {s.rationale && <span className="block text-gray-500 dark:text-gray-400">{s.rationale}</span>}
                  </span>
                  <button onClick={() => confirmComponent(s)} className="shrink-0 rounded bg-accent-600 px-1.5 py-0.5 text-[11px] font-medium text-white hover:bg-accent-700">Add</button>
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="mt-2 space-y-1">
          {detail.components.map((c) => (
            <div key={c.id} className="flex items-center gap-2 text-sm">
              <span className="font-medium">{c.name}</span>
              {c.tech && <span className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[10px] text-gray-500 dark:bg-gray-800">{c.tech}</span>}
              {c.source === "assisted" && <span className="shrink-0 rounded border border-amber-400/50 px-1 text-[10px] text-amber-600 dark:text-amber-400">assisted</span>}
              {c.source === "detected" && <span className="shrink-0 rounded border border-gray-400/50 px-1 text-[10px] text-gray-500 dark:border-gray-600/50 dark:text-gray-400">detected</span>}
              {canEdit && c.tech && (
                <button onClick={() => enumerate(c.id)} className="ml-auto rounded-md border border-gray-300 px-2 py-0.5 text-[11px] hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800">
                  Enumerate STRIDE
                </button>
              )}
              {canEdit && (
                <button onClick={() => removeComponent(c.id)} className="shrink-0 text-gray-400 hover:text-red-600 dark:hover:text-red-400 text-xs" title="Remove component and its threats">✕</button>
              )}
            </div>
          ))}
          {detail.components.length === 0 && <p className="text-xs text-gray-500">No components yet.</p>}
        </div>
        {canEdit && <AddComponent modelId={detail.id} library={library} onAdded={onChange} onErr={onErr} />}
      </div>

      <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
        <div className="flex items-center justify-between">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Threats ({detail.threats.length})</div>
          {canEdit && (
            <button onClick={suggest} disabled={suggesting} className="inline-flex items-center gap-1 rounded-md border border-amber-400/50 px-2 py-0.5 text-[11px] font-medium text-amber-600 hover:bg-amber-50 disabled:opacity-50 dark:text-amber-400 dark:hover:bg-amber-950/30" title="Ask the local LLM to suggest additional threats (you confirm each)">
              {suggesting ? "Thinking…" : "AI suggest"}
            </button>
          )}
        </div>
        {suggestions && suggestions.length > 0 && (
          <div className="mt-2 rounded-md border border-amber-400/40 bg-amber-50/50 p-2 dark:bg-amber-950/20">
            <div className="mb-1 text-[11px] font-medium text-amber-700 dark:text-amber-400">Suggested — advisory, confirm to keep</div>
            <ul className="space-y-1">
              {suggestions.map((s, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <span className="min-w-0 flex-1"><span className="font-medium">{s.title}</span> <span className="text-gray-400">· {s.category}</span>{s.description && <span className="block text-gray-500 dark:text-gray-400">{s.description}</span>}</span>
                  <button onClick={() => confirm(s)} className="shrink-0 rounded bg-accent-600 px-1.5 py-0.5 text-[11px] font-medium text-white hover:bg-accent-700">Add</button>
                </li>
              ))}
            </ul>
          </div>
        )}
        {detail.threats.length === 0 ? (
          <p className="mt-1 text-xs text-gray-500">No threats yet. Add a component with a tech, then enumerate STRIDE over it.</p>
        ) : (
          <div className="mt-2 space-y-3">
            {STRIDE.filter((s) => byCategory[s.key]?.length).map((s) => (
              <div key={s.key}>
                <div className="text-[11px] font-semibold text-gray-500 dark:text-gray-400">{s.label}</div>
                <ul className="mt-1 space-y-1">
                  {byCategory[s.key].map((t) => {
                    const links = detail.links[t.id] ?? [];
                    const findings = links.filter((l) => l.kind === "finding").length;
                    return (
                      <li key={t.id} className="rounded-md border border-gray-200 px-2 py-1.5 dark:border-gray-800">
                        <div className="flex items-center gap-2">
                          <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: STATUS_DOT[t.status] }} />
                          <span className="min-w-0 flex-1 truncate text-sm">{t.title}</span>
                          {t.source === "assisted" && <span className="shrink-0 rounded border border-amber-400/50 px-1 text-[10px] text-amber-600 dark:text-amber-400">assisted</span>}
                          {canEdit ? (
                            <select value={t.status} onChange={(e) => setStatus(t.id, e.target.value as ThreatStatus)} className={selectClass}>
                              {(Object.keys(STATUS_LABEL) as ThreatStatus[]).map((st) => <option key={st} value={st}>{STATUS_LABEL[st]}</option>)}
                            </select>
                          ) : (
                            <span className="shrink-0 text-[11px] text-gray-500">{STATUS_LABEL[t.status]}</span>
                          )}
                          {canEdit && (
                            <button onClick={() => removeThreat(t.id)} className="shrink-0 text-gray-400 hover:text-red-600 dark:hover:text-red-400 text-xs" title="Remove threat">✕</button>
                          )}
                        </div>
                        {t.description && <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{t.description}</p>}
                        <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-gray-400">
                          {t.mitigation && <span>fix: <span className="font-mono text-gray-500 dark:text-gray-300">{t.mitigation}</span></span>}
                          {findings > 0 && <span>{findings} finding{findings === 1 ? "" : "s"} linked</span>}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>
      </div>
    </Panel>
  );
}

function AddComponent({ modelId, library, onAdded, onErr }: { modelId: string; library: LibraryComponent[]; onAdded: () => void; onErr: (e: unknown) => void }) {
  const [name, setName] = useState("");
  const [tech, setTech] = useState("");
  const submit = async () => {
    if (!name.trim()) return;
    try { await opsApi.addThreatComponent(modelId, { name, tech }); setName(""); setTech(""); onAdded(); } catch (e) { onErr(e); }
  };
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      <input value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && submit()} placeholder="Add a component…" className="min-w-0 flex-1 rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800" />
      <select value={tech} onChange={(e) => setTech(e.target.value)} className={selectClass}>
        <option value="">tech…</option>
        {library.map((c) => <option key={c.tech} value={c.tech}>{c.title}</option>)}
      </select>
      <button onClick={submit} disabled={!name.trim()} className="rounded-md bg-accent-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-accent-700 disabled:opacity-50">Add</button>
    </div>
  );
}
