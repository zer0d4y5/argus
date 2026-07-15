import { useEffect, useState } from "react";
import { api, opsApi, Engagement } from "../api";
import { Panel, Loading, EmptyState } from "../components";
import { useToast } from "../toast";

// Engagements: the authorization scope for active DAST testing. Operators see
// what is scoped and armed; admins create, activate, and export the pentest
// report. Creating an engagement declares authorization, so it is admin-only
// and audited server-side. The console never arms the destructive latch.
export function Engagements({ canManage }: { canManage: boolean }) {
  const toast = useToast();
  const [list, setList] = useState<Engagement[] | null>(null);
  const [busy, setBusy] = useState<string>("");
  const [showNew, setShowNew] = useState(false);

  const load = async () => {
    try {
      const res = await opsApi.engagements();
      setList(res.engagements);
    } catch (e) {
      toast({ kind: "error", message: `Could not load engagements: ${String(e)}` });
      setList([]);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const activate = async (id: string) => {
    setBusy(id);
    try {
      await opsApi.activateEngagement(id);
      toast({ kind: "success", message: "Engagement activated." });
      await load();
    } catch (e) {
      toast({ kind: "error", message: `Activate failed: ${String(e)}` });
    } finally {
      setBusy("");
    }
  };

  if (list === null) return <Loading what="engagements" />;

  return (
    <div className="space-y-4">
      <Panel
        title="Engagements"
        right={
          canManage ? (
            <button
              onClick={() => setShowNew((v) => !v)}
              className="rounded-md border border-gray-300 px-2 py-1 text-xs font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800"
            >
              {showNew ? "Cancel" : "New engagement"}
            </button>
          ) : undefined
        }
      >
        <p className="mb-3 text-xs text-gray-500">
          An engagement authorizes active testing of the in-scope targets. Active DAST refuses to send a packet without
          one. Every active request is scope-gated and recorded in a tamper-evident audit trail.
        </p>
        {showNew && canManage && <NewEngagementForm onDone={() => { setShowNew(false); load(); }} />}
        {list.length === 0 ? (
          <EmptyState title="No engagements yet" hint={canManage ? "Create one to authorize active DAST testing." : "An admin must create an engagement before active testing can run."} />
        ) : (
          <div className="space-y-2">
            {list.map((e) => (
              <div key={e.id} className="rounded-lg border border-gray-200 p-3 dark:border-gray-800">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">{e.name}</span>
                  {e.active && <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-medium text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300">active</span>}
                  {e.confirm && <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">confirmation armed</span>}
                  <span className="ml-auto font-mono text-[10px] text-gray-400">{e.id}</span>
                </div>
                <div className="text-[11px] text-gray-500">
                  authorization <span className="font-mono">{e.authorizationRef}</span>
                  {e.contact ? <> · contact {e.contact}</> : null}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1">
                  <span className="text-[10px] uppercase tracking-wide text-gray-400">in scope</span>
                  {e.inScope.map((s) => (
                    <span key={s} className="rounded bg-gray-200 px-1.5 py-0.5 text-[10px] font-mono text-gray-700 dark:bg-gray-700 dark:text-gray-200">{s}</span>
                  ))}
                  {(e.outOfScope ?? []).map((s) => (
                    <span key={s} className="rounded bg-rose-100 px-1.5 py-0.5 text-[10px] font-mono text-rose-800 line-through dark:bg-rose-900/30 dark:text-rose-300">{s}</span>
                  ))}
                </div>
                {canManage && (
                  <div className="mt-2 flex gap-2">
                    {!e.active && (
                      <button
                        onClick={() => activate(e.id)}
                        disabled={busy === e.id}
                        className="rounded border border-gray-300 px-2 py-1 text-[11px] font-medium hover:bg-gray-100 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-800"
                      >
                        {busy === e.id ? "Activating…" : "Make active"}
                      </button>
                    )}
                    <a
                      href={api.engagementReportUrl(e.id)}
                      className="rounded border border-gray-300 px-2 py-1 text-[11px] font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800"
                    >
                      Download pentest report
                    </a>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

function NewEngagementForm({ onDone }: { onDone: () => void }) {
  const toast = useToast();
  const [name, setName] = useState("");
  const [authRef, setAuthRef] = useState("");
  const [contact, setContact] = useState("");
  const [inScope, setInScope] = useState("");
  const [outScope, setOutScope] = useState("");
  const [allowConfirm, setAllowConfirm] = useState(false);
  const [activate, setActivate] = useState(true);
  const [saving, setSaving] = useState(false);

  const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

  const submit = async () => {
    if (!name.trim() || !authRef.trim() || lines(inScope).length === 0) {
      toast({ kind: "error", message: "Name, authorization reference, and at least one in-scope entry are required." });
      return;
    }
    setSaving(true);
    try {
      await opsApi.createEngagement({
        name: name.trim(), authorizationRef: authRef.trim(), contact: contact.trim(),
        inScope: lines(inScope), outOfScope: lines(outScope), allowConfirmation: allowConfirm, activate,
      });
      toast({ kind: "success", message: "Engagement created." });
      onDone();
    } catch (e) {
      toast({ kind: "error", message: `Create failed: ${String(e)}` });
    } finally {
      setSaving(false);
    }
  };

  const inputCls = "w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800";
  return (
    <div className="mb-3 space-y-2 rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-800/40">
      <div className="grid gap-2 md:grid-cols-2">
        <div>
          <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Name</label>
          <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme staging" />
        </div>
        <div>
          <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Authorization reference (required)</label>
          <input className={inputCls} value={authRef} onChange={(e) => setAuthRef(e.target.value)} placeholder="CVP-2026-0412" />
        </div>
      </div>
      <div>
        <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">In scope (one host/CIDR/URL-prefix/*.domain per line)</label>
        <textarea className={inputCls} rows={2} value={inScope} onChange={(e) => setInScope(e.target.value)} placeholder={"staging.acme.com\n*.staging.acme.com"} />
      </div>
      <div className="grid gap-2 md:grid-cols-2">
        <div>
          <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Out of scope (optional)</label>
          <textarea className={inputCls} rows={2} value={outScope} onChange={(e) => setOutScope(e.target.value)} placeholder="admin.staging.acme.com" />
        </div>
        <div>
          <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Contact (optional)</label>
          <input className={inputCls} value={contact} onChange={(e) => setContact(e.target.value)} placeholder="you@acme.com" />
        </div>
      </div>
      <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
        <input type="checkbox" checked={allowConfirm} onChange={(e) => setAllowConfirm(e.target.checked)} className="rounded border-gray-300 dark:border-gray-600" />
        <span>Allow bounded impact confirmation (a per-run confirmation is still required; never dumps data or changes state)</span>
      </label>
      <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
        <input type="checkbox" checked={activate} onChange={(e) => setActivate(e.target.checked)} className="rounded border-gray-300 dark:border-gray-600" />
        <span>Make this the active engagement</span>
      </label>
      <button
        onClick={submit}
        disabled={saving}
        className="rounded-md bg-accent-600 px-3 py-1 text-xs font-medium text-white hover:bg-accent-700 disabled:opacity-50"
      >
        {saving ? "Creating…" : "Create engagement"}
      </button>
    </div>
  );
}
