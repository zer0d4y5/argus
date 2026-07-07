import { useEffect, useState } from "react";
import { opsApi, OIDCConfigView, OIDCConfigInput, ApiError } from "../api";
import { Panel } from "../components";

const inputClass =
  "w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800 focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500";
const labelClass = "mb-1 block text-xs uppercase text-gray-500 dark:text-gray-400";
const hintClass = "mt-1 text-xs text-gray-500 dark:text-gray-400";

export function SSOConfigPanel(): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [view, setView] = useState<OIDCConfigView | null>(null);

  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [redirectUrl, setRedirectUrl] = useState("");
  const [allowedDomainsStr, setAllowedDomainsStr] = useState("");
  const [defaultRole, setDefaultRole] = useState("viewer");
  const [secretEnvName, setSecretEnvName] = useState("");
  const [groupClaim, setGroupClaim] = useState("");

  function seed(v: OIDCConfigView) {
    setView(v);
    setIssuer(v.issuer || "");
    setClientId(v.clientId || "");
    setRedirectUrl(v.redirectUrl || "");
    setAllowedDomainsStr((v.allowedDomains || []).join(", "));
    setDefaultRole(v.defaultRole || "viewer");
    setSecretEnvName(v.clientSecretEnv || "");
    setGroupClaim(v.groupClaim || "");
  }

  useEffect(() => {
    opsApi
      .getOIDCConfig()
      .then((v) => seed(v))
      .catch((err) => setError(err instanceof ApiError ? err.message : "Failed to load SSO config"))
      .finally(() => setLoading(false));
  }, []);

  async function handleSave() {
    setSaved(false);
    setError(null);
    setBusy(true);
    try {
      const domains = allowedDomainsStr.split(",").map((d) => d.trim()).filter(Boolean);
      const input: OIDCConfigInput = {
        issuer,
        clientId,
        redirectUrl,
        allowedDomains: domains,
        defaultRole: defaultRole || undefined,
        clientSecretEnv: secretEnvName || undefined,
        groupClaim: groupClaim || undefined,
        // roleMap has no editor here; pass the loaded value through so a save
        // never silently drops a configured group→role mapping.
        roleMap: view?.roleMap,
      };
      const resp = await opsApi.saveOIDCConfig(input);
      seed(resp);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save SSO config");
    } finally {
      setBusy(false);
    }
  }

  async function handleDisable() {
    setError(null);
    setBusy(true);
    try {
      seed(await opsApi.disableOIDCConfig());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to disable SSO");
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Panel title="Single sign-on (SSO)"><div className="text-sm text-gray-500">Loading…</div></Panel>;

  const roleMapEntries = view?.roleMap ? Object.entries(view.roleMap) : [];

  return (
    <Panel title="Single sign-on (SSO)">
      <p className="mb-4 text-sm text-gray-600 dark:text-gray-400">
        Sign in with Google, Microsoft, Okta, or any OpenID Connect provider. Password login always keeps working.
      </p>

      {view?.source === "config" && (
        <div className="mb-4 rounded bg-amber-50 p-2 text-xs text-amber-800 dark:bg-amber-900/30 dark:text-amber-300">
          Currently set in appsec.yml. Saving here moves it to the console-managed store.
        </div>
      )}

      <div className="space-y-4">
        <div>
          <label className={labelClass}>Issuer URL</label>
          <input type="text" placeholder="https://accounts.google.com" value={issuer} onChange={(e) => setIssuer(e.target.value)} className={inputClass} />
        </div>

        <div>
          <label className={labelClass}>Client ID</label>
          <input type="text" value={clientId} onChange={(e) => setClientId(e.target.value)} className={inputClass} />
        </div>

        <div>
          <label className={labelClass}>Redirect URL</label>
          <input type="text" placeholder="http://127.0.0.1:8080/api/auth/oidc/callback" value={redirectUrl} onChange={(e) => setRedirectUrl(e.target.value)} className={inputClass} />
          <p className={hintClass}>Must end in /api/auth/oidc/callback</p>
        </div>

        <div>
          <label className={labelClass}>Allowed email domains</label>
          <input type="text" placeholder="example.com, corp.io" value={allowedDomainsStr} onChange={(e) => setAllowedDomainsStr(e.target.value)} className={inputClass} />
          <p className={hintClass}>Only these domains auto-provision users. Empty = nobody auto-onboards.</p>
        </div>

        <div>
          <label className={labelClass}>Default role for new users</label>
          <select value={defaultRole} onChange={(e) => setDefaultRole(e.target.value)} className={inputClass}>
            <option value="viewer">viewer</option>
            <option value="operator">operator</option>
            <option value="admin">admin</option>
          </select>
        </div>

        <div>
          <label className={labelClass}>Client secret env var name</label>
          <input type="text" placeholder="ARGUS_OIDC_SECRET" value={secretEnvName} onChange={(e) => setSecretEnvName(e.target.value)} className={inputClass} />
          <div className="mt-1">
            {view?.secretPresent ? (
              <span className="text-xs text-green-600 dark:text-green-400">✓ Set on the server</span>
            ) : (
              <span className="text-xs text-amber-600 dark:text-amber-400">Not set — export {view?.secretEnvName} for the serve process</span>
            )}
          </div>
          <p className={hintClass}>The secret is read from this environment variable at sign-in time and never stored.</p>
        </div>

        <div>
          <label className={labelClass}>Group claim (optional)</label>
          <input type="text" placeholder="groups" value={groupClaim} onChange={(e) => setGroupClaim(e.target.value)} className={inputClass} />
          <p className={hintClass}>Optional: the ID-token claim that carries group names.</p>
        </div>

        {roleMapEntries.length > 0 && (
          <div>
            <label className={labelClass}>Group → role mapping</label>
            <ul className="text-xs text-gray-600 dark:text-gray-300">
              {roleMapEntries.map(([g, r]) => (
                <li key={g} className="font-mono">{g} → {r}</li>
              ))}
            </ul>
            <p className={hintClass}>Edit in appsec.yml; preserved on save.</p>
          </div>
        )}

        {saved && <div className="text-sm text-green-600 dark:text-green-400">Saved.</div>}
        {error && <div className="text-sm text-red-600 dark:text-red-400">{error}</div>}

        <div className="flex gap-3 pt-2">
          <button onClick={handleSave} disabled={busy} className="rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-700 disabled:opacity-50">
            {busy ? "Saving…" : "Save"}
          </button>
          {view?.enabled && (
            <button onClick={handleDisable} disabled={busy} className="rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700">
              Disable SSO
            </button>
          )}
        </div>
      </div>
    </Panel>
  );
}
