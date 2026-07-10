import { useEffect, useState } from "react";
import { opsApi, UserInfo, Target, TargetConfig, DastConfig, AuditEntry, ApiError, KNOWN_SCANNERS, PROFILES } from "../api";
import { Panel, Loading, ErrorNote, EmptyState } from "../components";
import { useConfirm } from "../toast";
import { fmtTime } from "../theme";
import { SSOConfigPanel } from "./SSOConfigPanel";
import { ConsoleSettingsPanel } from "./ConsoleSettingsPanel";
import { RuleAuthorPanel } from "./RuleAuthorPanel";
import { RulePacksPanel } from "./RulePacksPanel";

// targetTypeChip renders a target's kind as a colour-coded chip, so the
// targets table is scannable by kind at a glance.
function targetTypeChip(t: Target): { label: string; cls: string } {
  switch (t.type) {
    case "git": return { label: "git", cls: "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300" };
    case "cloud": return { label: `cloud · ${t.provider}`, cls: "bg-sky-100 text-sky-800 dark:bg-sky-900/30 dark:text-sky-300" };
    case "dast": return { label: "dast", cls: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300" };
    case "image": return { label: "image", cls: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300" };
    default: return { label: "dir", cls: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300" };
  }
}

// targetLocator is what a target points at, for the PATH / URL column: a
// path, a git URL, a cloud profile, a DAST URL, or an image reference. Every
// kind shows something; a blank cell would leave image/DAST targets illegible.
function targetLocator(t: Target): string {
  switch (t.type) {
    case "git": return t.url || "";
    case "cloud": return `profile: ${t.profileName}${t.regions && t.regions.length ? ` · ${t.regions.join(",")}` : ""}`;
    case "dast": return t.url || "";
    case "image": return t.ref || "";
    default: return t.path || "";
  }
}

// AdminTab groups the admin panels so the page reads as focused sections
// instead of one long scroll.
type AdminTab = "users" | "targets" | "integrations" | "rules" | "audit";

const ADMIN_TABS: { id: AdminTab; label: string }[] = [
  { id: "users", label: "Users & SSO" },
  { id: "targets", label: "Targets" },
  { id: "integrations", label: "Integrations & scanning" },
  { id: "rules", label: "Detection rules" },
  { id: "audit", label: "Audit log" },
];

export function Admin({ selfUsername }: { selfUsername: string }) {
  const confirm = useConfirm();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [subtab, setSubtab] = useState<AdminTab>("users");

  // Per-section errors
  const [userError, setUserError] = useState<string | null>(null);
  const [targetError, setTargetError] = useState<string | null>(null);

  // Controlled add-forms (never read back through the DOM).
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "viewer" });
  
  // New Target Add Form State
  const [newTargetType, setNewTargetType] = useState<"dir" | "git" | "cloud" | "dast" | "image">("dir");
  const [newTargetName, setNewTargetName] = useState("");
  const [newTargetPath, setNewTargetPath] = useState("");
  const [newTargetUrl, setNewTargetUrl] = useState("");
  const [newTargetBranch, setNewTargetBranch] = useState("");
  const [newTargetImageRef, setNewTargetImageRef] = useState(""); // image targets: the container reference (dast reuses the url field)
  const [newTargetProfile, setNewTargetProfile] = useState("");
  const [newTargetScanners, setNewTargetScanners] = useState<Set<string>>(new Set());
  // Cloud target form: a provider and a profile NAME chosen from the
  // server-discovered closed list (never a free-form key).
  const [cloudProvider, setCloudProvider] = useState("aws");
  const [cloudProfileName, setCloudProfileName] = useState("");
  const [cloudAccount, setCloudAccount] = useState(""); // Azure subscription id / GCP project id
  const [cloudRegions, setCloudRegions] = useState("");
  const [cloudProfileChoices, setCloudProfileChoices] = useState<string[]>([]);
  const [cloudProfileError, setCloudProfileError] = useState<string | null>(null);

  // Configure Drawer State
  const [configuringTargetId, setConfiguringTargetId] = useState<string | null>(null);
  const [configForm, setConfigForm] = useState<{
    scanners: string[];
    profile: string;
    timeoutSec: number | undefined;
    triage: "default" | "on" | "off";
    ignorePaths: string;
    ignoreRules: string;
    // DAST-target options (shown only for dast targets)
    dastFuzzing: boolean;
    dastTags: string;
    dastSeverities: string;
    dastRateLimit: number | undefined;
    dastAuthMode: "none" | "auto" | "creds";
    dastLoginUrl: string;
    dastUserEnv: string;
    dastPassEnv: string;
  }>({
    scanners: [],
    profile: "",
    timeoutSec: undefined,
    triage: "default",
    ignorePaths: "",
    ignoreRules: "",
    dastFuzzing: false,
    dastTags: "",
    dastSeverities: "",
    dastRateLimit: undefined,
    dastAuthMode: "none",
    dastLoginUrl: "",
    dastUserEnv: "",
    dastPassEnv: "",
  });
  const [configTargetType, setConfigTargetType] = useState<string>("");
  const [configError, setConfigError] = useState<string | null>(null);

  useEffect(() => {
    reload(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Mutations call reload() without the full-page loading flash.
  async function reload(initial = false) {
    if (initial) setLoading(true);
    setError(null);
    try {
      const [uRes, tRes, aRes] = await Promise.all([
        opsApi.users(),
        opsApi.targets(),
        opsApi.audit(200),
      ]);
      setUsers(uRes.users);
      setTargets(tRes.targets);
      setAudit(aRes.entries);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to load admin data");
      }
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <Loading what="admin data" />;
  if (error) return <ErrorNote error={error} />;

  return (
    <div className="space-y-6">
      <nav className="scroll-thin -mb-2 flex gap-1 overflow-x-auto border-b border-gray-200 pb-3 dark:border-gray-800">
        {ADMIN_TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setSubtab(t.id)}
            className={`whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition ${
              subtab === t.id
                ? "bg-accent-100 text-accent-700 dark:bg-accent-500/15 dark:text-accent-200"
                : "text-gray-600 hover:bg-gray-200 dark:text-gray-300 dark:hover:bg-gray-800"
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {subtab === "users" && (
      <div className="space-y-6">
      {/* Users */}
      <Panel title="Users">
        {userError && <div className="mb-3 text-xs text-red-600 dark:text-red-400">{userError}</div>}
        <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[600px] text-left text-sm">
          <thead className="text-xs uppercase text-gray-500">
            <tr>
              <th className="py-2 pr-3">Username</th>
              <th className="py-2 pr-3">Role</th>
              <th className="py-2 pr-3">Created</th>
              <th className="py-2 pr-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <UserRow
                key={u.id}
                user={u}
                selfUsername={selfUsername}
                onRoleChange={(role) => handleUserRoleChange(u.id, role)}
                onPasswordReset={(pw) => handleUserPasswordReset(u.id, pw)}
                onRemove={() => handleUserRemove(u.id, u.username)}
              />
            ))}
          </tbody>
        </table>
        </div>
        <div className="mt-4 grid gap-2 md:grid-cols-4">
          <input
            type="text"
            placeholder="Username"
            autoComplete="off"
            value={newUser.username}
            onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
            className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          />
          <input
            type="password"
            placeholder="Password (min 8)"
            autoComplete="new-password"
            value={newUser.password}
            onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
            className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          />
          <select
            value={newUser.role}
            onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
            className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          >
            <option value="viewer">viewer</option>
            <option value="operator">operator</option>
            <option value="admin">admin</option>
          </select>
          <button
            onClick={handleAddUser}
            disabled={!newUser.username || !newUser.password}
            className="rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-700 disabled:opacity-50"
          >
            Add user
          </button>
        </div>
      </Panel>

      {/* Single sign-on (authentication config) */}
      <SSOConfigPanel />
      </div>
      )}

      {subtab === "integrations" && <ConsoleSettingsPanel />}

      {subtab === "rules" && (
      <div className="space-y-6">
        <RulePacksPanel />
        <RuleAuthorPanel />
      </div>
      )}

      {subtab === "targets" && (
      <Panel title="Targets">
        {targetError && <div className="mb-3 text-xs text-red-600 dark:text-red-400">{targetError}</div>}
        <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[600px] text-left text-sm">
          <thead className="text-xs uppercase text-gray-500">
            <tr>
              <th className="py-2 pr-3">Name</th>
              <th className="py-2 pr-3">Type</th>
              <th className="py-2 pr-3">Path / URL</th>
              <th className="py-2 pr-3">Scanners</th>
              <th className="py-2 pr-3">Profile</th>
              <th className="py-2 pr-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} className="border-t border-gray-100 dark:border-gray-800">
                <td className="py-2 pr-3 font-medium">{t.name}</td>
                <td className="py-2 pr-3 text-xs">
                  <span className={`rounded px-1.5 py-0.5 ${targetTypeChip(t).cls}`}>
                    {targetTypeChip(t).label}
                  </span>
                </td>
                <td className="py-2 pr-3 font-mono text-xs text-gray-600 dark:text-gray-400">
                  {targetLocator(t)}
                  {t.type === 'git' && t.branch && <span className="text-blue-600 dark:text-blue-400 ml-1">@{t.branch}</span>}
                </td>
                <td className="py-2 pr-3 text-xs">
                  {t.scanners && t.scanners.length > 0 ? t.scanners.join(", ") : "all"}
                </td>
                <td className="py-2 pr-3 text-xs">{t.profile || "standard"}</td>
                <td className="py-2 pr-3">
                  <button
                    onClick={() => handleConfigureTarget(t)}
                    className="mr-2 text-xs text-accent-600 hover:underline dark:text-accent-400"
                  >
                    configure
                  </button>
                  <button
                    onClick={() => handleRemoveTarget(t.id)}
                    className="text-xs text-red-600 hover:underline dark:text-red-400"
                  >
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>

        {/* Add Target Form */}
        <div className="mt-4 space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Type:</span>
            <button
              onClick={() => setNewTargetType("dir")}
              className={`rounded px-2 py-1 text-xs ${newTargetType === 'dir' ? 'bg-accent-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}`}
            >
              Directory
            </button>
            <button
              onClick={() => setNewTargetType("git")}
              className={`rounded px-2 py-1 text-xs ${newTargetType === 'git' ? 'bg-accent-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}`}
            >
              Git Repo
            </button>
            <button
              onClick={() => { setNewTargetType("cloud"); loadCloudProfiles(); }}
              className={`rounded px-2 py-1 text-xs ${newTargetType === 'cloud' ? 'bg-accent-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}`}
            >
              Cloud
            </button>
            <button
              onClick={() => setNewTargetType("dast")}
              className={`rounded px-2 py-1 text-xs ${newTargetType === 'dast' ? 'bg-accent-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}`}
            >
              DAST (URL)
            </button>
            <button
              onClick={() => setNewTargetType("image")}
              className={`rounded px-2 py-1 text-xs ${newTargetType === 'image' ? 'bg-accent-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}`}
            >
              Image
            </button>
          </div>

          <input
            type="text"
            placeholder="Name"
            value={newTargetName}
            onChange={(e) => setNewTargetName(e.target.value)}
            className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          />

          {newTargetType === "dir" && (
            <input
              type="text"
              placeholder="/abs/path/to/repo"
              value={newTargetPath}
              onChange={(e) => setNewTargetPath(e.target.value)}
              className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-gray-700 dark:bg-gray-800"
            />
          )}
          {newTargetType === "git" && (
            <div className="grid gap-2 md:grid-cols-2">
              <input
                type="text"
                placeholder="https://host/org/repo.git"
                value={newTargetUrl}
                onChange={(e) => setNewTargetUrl(e.target.value)}
                className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-gray-700 dark:bg-gray-800"
              />
              <input
                type="text"
                placeholder="Branch (optional)"
                value={newTargetBranch}
                onChange={(e) => setNewTargetBranch(e.target.value)}
                className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-gray-700 dark:bg-gray-800"
              />
            </div>
          )}
          {newTargetType === "dast" && (
            <div className="space-y-1">
              <input
                type="text"
                placeholder="https://staging.example.com"
                value={newTargetUrl}
                onChange={(e) => setNewTargetUrl(e.target.value)}
                className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-gray-700 dark:bg-gray-800"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400">
                A running URL to scan with nuclei. Only scan targets you are authorized to test. The scan sends only requests to this URL.
              </p>
            </div>
          )}
          {newTargetType === "image" && (
            <div className="space-y-1">
              <input
                type="text"
                placeholder="nginx:1.27-alpine or registry.example.com/team/app:v1"
                value={newTargetImageRef}
                onChange={(e) => setNewTargetImageRef(e.target.value)}
                className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-gray-700 dark:bg-gray-800"
              />
              <p className="text-xs text-gray-500 dark:text-gray-400">
                A container image reference to scan with trivy. Private-registry images use the serve host's ambient docker config; no credential is stored.
              </p>
            </div>
          )}
          {newTargetType === "cloud" && (
            <div className="space-y-2">
              <div className="grid gap-2 md:grid-cols-2">
                <select
                  value={cloudProvider}
                  onChange={(e) => setCloudProvider(e.target.value)}
                  className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                >
                  <option value="aws">aws</option>
                  <option value="azure">azure</option>
                  <option value="gcp">gcp</option>
                </select>
                {cloudProvider === "aws" ? (
                  <select
                    value={cloudProfileName}
                    onChange={(e) => setCloudProfileName(e.target.value)}
                    className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
                  >
                    <option value="">select a local profile</option>
                    {cloudProfileChoices.map((p) => (
                      <option key={p} value={p}>{p}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    placeholder={cloudProvider === "azure" ? "Subscription id (GUID)" : "Project id"}
                    value={cloudAccount}
                    onChange={(e) => setCloudAccount(e.target.value)}
                    className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-gray-700 dark:bg-gray-800"
                  />
                )}
              </div>
              {cloudProvider === "aws" && (
                <input
                  type="text"
                  placeholder="Regions (optional, comma-separated, e.g. us-east-1,us-west-2)"
                  value={cloudRegions}
                  onChange={(e) => setCloudRegions(e.target.value)}
                  className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-gray-700 dark:bg-gray-800"
                />
              )}
              {cloudProfileError && <p className="text-xs text-red-600 dark:text-red-400">{cloudProfileError}</p>}
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {cloudProvider === "aws"
                  ? "The profile is a NAME from this host's cloud config (~/.aws): never a key. Point it at a read-only security-audit principal."
                  : cloudProvider === "azure"
                  ? "The subscription id is a reference: never a key. Provide a service principal (AZURE_CLIENT_ID/SECRET/TENANT) with the Reader role in the serve process's environment."
                  : "The project id is a reference: never a key. Provide Application Default Credentials with the Viewer role in the serve process's environment."}
              </p>
            </div>
          )}

          {(newTargetType === "dir" || newTargetType === "git") && (
            <>
              <select
                value={newTargetProfile}
                onChange={(e) => setNewTargetProfile(e.target.value)}
                className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
              >
                <option value="">standard (default)</option>
                {PROFILES.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>

              <div className="flex flex-wrap gap-4">
                {KNOWN_SCANNERS.map((s) => (
                  <label key={s} className="flex items-center gap-1 text-sm">
                    <input
                      type="checkbox"
                      checked={newTargetScanners.has(s)}
                      onChange={() =>
                        setNewTargetScanners((prev) => {
                          const next = new Set(prev);
                          if (next.has(s)) next.delete(s);
                          else next.add(s);
                          return next;
                        })
                      }
                      className="rounded border-gray-300 dark:border-gray-700"
                    />
                    <span>{s}</span>
                  </label>
                ))}
                <span className="text-xs text-gray-500 dark:text-gray-400">none checked = all allowed</span>
              </div>
            </>
          )}

          <button
            onClick={handleAddTarget}
            disabled={!newTargetName || (
              newTargetType === "dir" ? !newTargetPath :
              newTargetType === "git" ? !newTargetUrl :
              newTargetType === "dast" ? !newTargetUrl :
              newTargetType === "image" ? !newTargetImageRef :
              cloudProvider === "aws" ? !cloudProfileName : !cloudAccount)}
            className="rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-700 disabled:opacity-50"
          >
            Register target
          </button>
        </div>

        <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
          Paths are validated server-side: absolute, existing directory, never /. Git URLs must be accessible.
          Cloud profiles are validated against this host's local config; a raw key is never accepted.
        </p>

        {/* Configure Drawer */}
        {configuringTargetId && (
          <div className="mt-6 rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-800/50">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">Configure Target</h3>
              <button onClick={() => setConfiguringTargetId(null)} className="text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                Close
              </button>
            </div>
            
            {configError && <div className="mb-3 text-xs text-red-600 dark:text-red-400">{configError}</div>}

            {/* Scanners */}
            <div className="mb-4">
              <label className="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">Allowed Scanners</label>
              <div className="flex flex-wrap gap-2">
                {KNOWN_SCANNERS.map((s) => (
                  <label key={s} className="flex items-center gap-1 rounded border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800">
                    <input
                      type="checkbox"
                      checked={configForm.scanners.includes(s)}
                      onChange={(e) => {
                        const next = e.target.checked
                          ? [...configForm.scanners, s]
                          : configForm.scanners.filter(x => x !== s);
                        setConfigForm({ ...configForm, scanners: next });
                      }}
                      className="rounded border-gray-300 dark:border-gray-600"
                    />
                    <span>{s}</span>
                  </label>
                ))}
              </div>
              <p className="mt-1 text-[10px] text-gray-500">Leave all unchecked to allow all scanners.</p>
            </div>

            {/* Profile */}
            <div className="mb-4 grid gap-2 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">Profile</label>
                <select
                  value={configForm.profile}
                  onChange={(e) => setConfigForm({ ...configForm, profile: e.target.value })}
                  className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800"
                >
                  <option value="">default</option>
                  {PROFILES.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">Timeout (sec)</label>
                <input
                  type="number"
                  min={10}
                  max={3600}
                  placeholder="default"
                  value={configForm.timeoutSec ?? ""}
                  onChange={(e) => setConfigForm({ ...configForm, timeoutSec: e.target.value ? Number(e.target.value) : undefined })}
                  className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800"
                />
              </div>
            </div>

            {/* Triage */}
            <div className="mb-4">
              <label className="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">Triage</label>
              <select
                value={configForm.triage}
                onChange={(e) => setConfigForm({ ...configForm, triage: e.target.value as "default" | "on" | "off" })}
                className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800"
              >
                <option value="default">default</option>
                <option value="on">on</option>
                <option value="off">off</option>
              </select>
            </div>

            {/* Ignore Paths */}
            <div className="mb-4">
              <label className="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">Ignore Paths (one glob per line)</label>
              <textarea
                rows={3}
                value={configForm.ignorePaths}
                onChange={(e) => setConfigForm({ ...configForm, ignorePaths: e.target.value })}
                className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs font-mono dark:border-gray-600 dark:bg-gray-800"
              />
            </div>

            {/* Ignore Rules */}
            <div className="mb-4">
              <label className="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">Ignore Rules (one rule id per line)</label>
              <textarea
                rows={3}
                value={configForm.ignoreRules}
                onChange={(e) => setConfigForm({ ...configForm, ignoreRules: e.target.value })}
                className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs font-mono dark:border-gray-600 dark:bg-gray-800"
              />
            </div>

            <p className="mb-4 text-[10px] text-orange-600 dark:text-orange-400">
              Suppressions hide findings — every change is audited.
            </p>

            {configTargetType === "dast" && (
              <div className="mb-4 rounded-md border border-amber-200 bg-amber-50/50 p-3 dark:border-amber-900/40 dark:bg-amber-900/10">
                <h4 className="mb-2 text-xs font-semibold text-amber-800 dark:text-amber-300">DAST scan options</h4>

                <label className="mb-3 flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300">
                  <input
                    type="checkbox"
                    checked={configForm.dastFuzzing}
                    onChange={(e) => setConfigForm({ ...configForm, dastFuzzing: e.target.checked })}
                    className="rounded border-gray-300 dark:border-gray-600"
                  />
                  <span>Active fuzzing (nuclei -dast): probe parameters for injection (SQLi, XSS)</span>
                </label>

                <div className="mb-3 grid gap-2 md:grid-cols-3">
                  <div>
                    <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Tags</label>
                    <input
                      type="text"
                      placeholder="misconfig, cve"
                      value={configForm.dastTags}
                      onChange={(e) => setConfigForm({ ...configForm, dastTags: e.target.value })}
                      className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Severities</label>
                    <input
                      type="text"
                      placeholder="medium, high, critical"
                      value={configForm.dastSeverities}
                      onChange={(e) => setConfigForm({ ...configForm, dastSeverities: e.target.value })}
                      className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Rate limit (req/s)</label>
                    <input
                      type="number"
                      min={0}
                      placeholder="default"
                      value={configForm.dastRateLimit ?? ""}
                      onChange={(e) => setConfigForm({ ...configForm, dastRateLimit: e.target.value ? Number(e.target.value) : undefined })}
                      className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800"
                    />
                  </div>
                </div>

                <div className="mb-2">
                  <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Authentication</label>
                  <select
                    value={configForm.dastAuthMode}
                    onChange={(e) => setConfigForm({ ...configForm, dastAuthMode: e.target.value as "none" | "auto" | "creds" })}
                    className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800"
                  >
                    <option value="none">None (scan unauthenticated)</option>
                    <option value="auto">Auto: detect login, try default credentials</option>
                    <option value="creds">Credentials from environment variables</option>
                  </select>
                </div>

                {configForm.dastAuthMode !== "none" && (
                  <div className="grid gap-2 md:grid-cols-2">
                    {configForm.dastAuthMode === "creds" && (
                      <>
                        <div>
                          <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Username env var</label>
                          <input
                            type="text"
                            placeholder="APP_USER"
                            value={configForm.dastUserEnv}
                            onChange={(e) => setConfigForm({ ...configForm, dastUserEnv: e.target.value })}
                            className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs font-mono dark:border-gray-600 dark:bg-gray-800"
                          />
                        </div>
                        <div>
                          <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Password env var</label>
                          <input
                            type="text"
                            placeholder="APP_PASS"
                            value={configForm.dastPassEnv}
                            onChange={(e) => setConfigForm({ ...configForm, dastPassEnv: e.target.value })}
                            className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs font-mono dark:border-gray-600 dark:bg-gray-800"
                          />
                        </div>
                      </>
                    )}
                    <div className="md:col-span-2">
                      <label className="mb-1 block text-[10px] font-medium text-gray-600 dark:text-gray-400">Login URL (optional)</label>
                      <input
                        type="text"
                        placeholder="defaults to the target URL"
                        value={configForm.dastLoginUrl}
                        onChange={(e) => setConfigForm({ ...configForm, dastLoginUrl: e.target.value })}
                        className="w-full rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800"
                      />
                    </div>
                  </div>
                )}

                <p className="mt-2 text-[10px] text-gray-500">
                  Credentials are read from the named environment variables on the serve host at scan time and are never stored. The obtained session is never written to a finding or log.
                </p>
              </div>
            )}

            <button
              onClick={() => handleSaveConfig(configuringTargetId)}
              className="rounded bg-accent-600 px-3 py-1 text-xs font-medium text-white hover:bg-accent-700"
            >
              Save Configuration
            </button>
          </div>
        )}
      </Panel>
      )}

      {subtab === "audit" && (
      <Panel title="Audit log" right={<span className="text-xs text-gray-500 dark:text-gray-400">{audit.length} entries</span>}>
        {audit.length === 0 ? (
          <EmptyState title="No audit entries" hint="Logins, user/target changes and scan launches land here." />
        ) : (
          <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[600px] text-left text-sm">
            <thead className="text-xs uppercase text-gray-500">
              <tr>
                <th className="py-2 pr-3">Time</th>
                <th className="py-2 pr-3">Event</th>
                <th className="py-2 pr-3">Actor</th>
                <th className="py-2 pr-3">Details</th>
              </tr>
            </thead>
            <tbody>
              {[...audit].reverse().map((entry, idx) => (
                <tr key={idx} className="border-t border-gray-100 dark:border-gray-800">
                  <td className="py-2 pr-3 text-xs">{fmtTime(entry.time)}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{entry.event}</td>
                  <td className="py-2 pr-3 text-xs">{entry.actor || "-"}</td>
                  <td className="py-2 pr-3">
                    {entry.details ? (
                      <span className="font-mono text-[11px] text-gray-500">
                        {Object.entries(entry.details)
                          .map(([k, v]) => `${k}=${v}`)
                          .join(" ")}
                      </span>
                    ) : (
                      "-"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}
      </Panel>
      )}
    </div>
  );

  // --- Handlers ---

  async function handleUserRoleChange(userId: string, newRole: string) {
    setUserError(null);
    try {
      await opsApi.updateUserRole(userId, newRole);
      await reload();
    } catch (err) {
      setUserError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleUserPasswordReset(userId: string, password: string) {
    setUserError(null);
    try {
      await opsApi.updateUserPassword(userId, password);
      await reload();
    } catch (err) {
      setUserError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleUserRemove(userId: string, username: string) {
    if (!(await confirm({ title: `Remove ${username}?`, message: "This user will lose console access.", confirmLabel: "Remove", danger: true }))) return;
    setUserError(null);
    try {
      await opsApi.deleteUser(userId);
      await reload();
    } catch (err) {
      setUserError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleAddUser() {
    if (!newUser.username || !newUser.password) return;
    setUserError(null);
    try {
      await opsApi.createUser(newUser.username, newUser.password, newUser.role);
      setNewUser({ username: "", password: "", role: "viewer" });
      await reload();
    } catch (err) {
      setUserError(err instanceof ApiError ? err.message : String(err));
    }
  }

  // loadCloudProfiles fetches the server-discovered closed list of profile
  // names for the chosen provider. Names only — no key material crosses.
  async function loadCloudProfiles() {
    setCloudProfileError(null);
    try {
      const resp = await opsApi.cloudProfiles();
      const aws = resp.providers.find((p) => p.provider === cloudProvider);
      const names = aws?.profiles ?? [];
      setCloudProfileChoices(names);
      if (names.length === 0) {
        setCloudProfileError("No local cloud profiles found on the console host.");
      }
    } catch (err) {
      setCloudProfileError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleAddTarget() {
    if (!newTargetName) return;
    setTargetError(null);
    try {
      const selected = Array.from(newTargetScanners);

      if (newTargetType === "dast") {
        if (!newTargetUrl) return;
        await opsApi.createTarget({ name: newTargetName, type: "dast", url: newTargetUrl });
      } else if (newTargetType === "image") {
        if (!newTargetImageRef) return;
        await opsApi.createTarget({ name: newTargetName, type: "image", ref: newTargetImageRef.trim() });
      } else if (newTargetType === "git") {
        if (!newTargetUrl) return;
        await opsApi.createTarget({
          name: newTargetName,
          url: newTargetUrl,
          branch: newTargetBranch || undefined,
          scanners: selected.length > 0 ? selected : undefined,
          profile: newTargetProfile || undefined,
        });
      } else if (newTargetType === "cloud") {
        if (cloudProvider === "aws" ? !cloudProfileName : !cloudAccount) return;
        const regions = cloudRegions.split(",").map((r) => r.trim()).filter(Boolean);
        await opsApi.createTarget({
          name: newTargetName,
          provider: cloudProvider,
          profileName: cloudProvider === "aws" ? cloudProfileName : undefined,
          account: cloudProvider === "aws" ? undefined : cloudAccount.trim(),
          regions: cloudProvider === "aws" && regions.length > 0 ? regions : undefined,
        });
      } else {
        if (!newTargetPath) return;
        await opsApi.createTarget({
          name: newTargetName,
          path: newTargetPath,
          scanners: selected.length > 0 ? selected : undefined,
          profile: newTargetProfile || undefined,
        });
      }

      setNewTargetName("");
      setNewTargetPath("");
      setNewTargetUrl("");
      setNewTargetBranch("");
      setNewTargetImageRef("");
      setNewTargetProfile("");
      setNewTargetScanners(new Set());
      setCloudProfileName("");
      setCloudRegions("");
      await reload();
    } catch (err) {
      setTargetError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleRemoveTarget(targetId: string) {
    if (!(await confirm({ title: "Remove this target?", message: "Its scan history stays on disk but the target is unregistered.", confirmLabel: "Remove", danger: true }))) return;
    setTargetError(null);
    try {
      await opsApi.deleteTarget(targetId);
      await reload();
    } catch (err) {
      setTargetError(err instanceof ApiError ? err.message : String(err));
    }
  }

  function handleConfigureTarget(t: Target) {
    setConfiguringTargetId(t.id);
    setConfigTargetType(t.type || "dir");
    setConfigError(null);

    // Initialize form with current target values
    const initialScanners = t.scanners && t.scanners.length > 0
      ? t.scanners
      : [];
    const d = t.config?.dast;
    const auth = d?.auth;
    const authMode: "none" | "auto" | "creds" =
      auth?.usernameEnv || auth?.passwordEnv ? "creds" : auth?.tryDefaults ? "auto" : "none";

    setConfigForm({
      scanners: initialScanners,
      profile: t.profile || "",
      timeoutSec: t.config?.timeoutSec,
      triage: t.config?.triage === true ? "on" : t.config?.triage === false ? "off" : "default",
      ignorePaths: t.config?.ignorePaths?.join("\n") || "",
      ignoreRules: t.config?.ignoreRules?.join("\n") || "",
      dastFuzzing: d?.fuzzing ?? false,
      dastTags: d?.tags?.join(", ") || "",
      dastSeverities: d?.severities?.join(", ") || "",
      dastRateLimit: d?.rateLimit,
      dastAuthMode: authMode,
      dastLoginUrl: auth?.loginUrl || "",
      dastUserEnv: auth?.usernameEnv || "",
      dastPassEnv: auth?.passwordEnv || "",
    });
  }

  async function handleSaveConfig(targetId: string) {
    setConfigError(null);
    try {
      // The PATCH semantics are pointer-based server-side: a key that is
      // PRESENT is applied (an empty array/string clears), a key that is
      // absent is unchanged. The drawer always shows the full state, so it
      // always sends scanners, profile, and the full config block.
      const ignorePaths = configForm.ignorePaths.split("\n").map((s) => s.trim()).filter(Boolean);
      const ignoreRules = configForm.ignoreRules.split("\n").map((s) => s.trim()).filter(Boolean);
      const config: TargetConfig = {};
      if (configForm.timeoutSec !== undefined) config.timeoutSec = configForm.timeoutSec;
      if (configForm.triage !== "default") config.triage = configForm.triage === "on";
      if (ignorePaths.length > 0) config.ignorePaths = ignorePaths;
      if (ignoreRules.length > 0) config.ignoreRules = ignoreRules;

      if (configTargetType === "dast") {
        const splitList = (s: string) => s.split(/[,\n]/).map((x) => x.trim()).filter(Boolean);
        const dast: DastConfig = {};
        if (configForm.dastFuzzing) dast.fuzzing = true;
        const tags = splitList(configForm.dastTags);
        const sevs = splitList(configForm.dastSeverities);
        if (tags.length > 0) dast.tags = tags;
        if (sevs.length > 0) dast.severities = sevs;
        if (configForm.dastRateLimit !== undefined) dast.rateLimit = configForm.dastRateLimit;
        if (configForm.dastAuthMode === "auto") {
          dast.auth = { tryDefaults: true, loginUrl: configForm.dastLoginUrl.trim() || undefined };
        } else if (configForm.dastAuthMode === "creds") {
          dast.auth = {
            usernameEnv: configForm.dastUserEnv.trim() || undefined,
            passwordEnv: configForm.dastPassEnv.trim() || undefined,
            loginUrl: configForm.dastLoginUrl.trim() || undefined,
          };
        }
        if (Object.keys(dast).length > 0) config.dast = dast;
      }

      await opsApi.updateTarget(targetId, {
        scanners: configForm.scanners,
        profile: configForm.profile,
        config,
      });
      setConfiguringTargetId(null);
      await reload();
    } catch (err) {
      setConfigError(err instanceof ApiError ? err.message : String(err));
    }
  }
}

function UserRow({
  user,
  selfUsername,
  onRoleChange,
  onPasswordReset,
  onRemove,
}: {
  user: UserInfo;
  selfUsername: string;
  onRoleChange: (role: string) => void;
  onPasswordReset: (pw: string) => void;
  onRemove: () => void;
}) {
  const [showPwInput, setShowPwInput] = useState(false);
  const [pwValue, setPwValue] = useState("");

  const isSelf = user.username === selfUsername;

  return (
    <tr className="border-t border-gray-100 dark:border-gray-800">
      <td className="py-2 pr-3 font-medium">{user.username}</td>
      <td className="py-2 pr-3">
        <select
          value={user.role}
          onChange={(e) => onRoleChange(e.target.value)}
          disabled={isSelf}
          className="rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
        >
          <option value="viewer">viewer</option>
          <option value="operator">operator</option>
          <option value="admin">admin</option>
        </select>
      </td>
      <td className="py-2 pr-3 text-xs text-gray-500">{fmtTime(user.createdAt)}</td>
      <td className="py-2 pr-3">
        <div className="flex gap-2">
          {isSelf ? (
            <span className="text-xs text-gray-400">self</span>
          ) : (
            <>
              <button
                onClick={() => setShowPwInput(!showPwInput)}
                className="text-xs text-accent-600 hover:underline dark:text-accent-400"
              >
                reset password
              </button>
              <button
                onClick={onRemove}
                className="text-xs text-red-600 hover:underline dark:text-red-400"
              >
                remove
              </button>
            </>
          )}
        </div>
        {showPwInput && (
          <div className="mt-1 flex gap-2">
            <input
              type="password"
              placeholder="new password (min 8)"
              value={pwValue}
              onChange={(e) => setPwValue(e.target.value)}
              className="rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
            />
            <button
              onClick={() => {
                if (pwValue) onPasswordReset(pwValue);
                setShowPwInput(false);
                setPwValue("");
              }}
              className="rounded bg-accent-600 px-2 py-1 text-xs text-white hover:bg-accent-700"
            >
              confirm
            </button>
          </div>
        )}
      </td>
    </tr>
  );
}

