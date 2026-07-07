import { useState } from "react";
import { opsApi, UserInfo, ApiError } from "../api";
import { Wordmark } from "../components";

export function Login({ onLogin, ssoEnabled, ssoError }: { onLogin: (user: UserInfo, csrfToken: string) => void; ssoEnabled?: boolean; ssoError?: boolean }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  // ssoError is captured by App before its URL-sync strips the query, so it
  // survives to here; a later password-login error overrides it.
  const [error, setError] = useState<string | null>(
    ssoError ? "Single sign-on didn't complete. Try again, or use a password." : null,
  );

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const resp = await opsApi.login(username, password);
      onLogin(resp.user, resp.csrfToken);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError(String(err));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-50 dark:bg-gray-950">
      <div className="w-full max-w-sm rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-800 dark:bg-gray-900">
        <div className="mb-6 text-center">
          <h1 className="flex items-center justify-center text-xl tracking-tight text-gray-900 dark:text-white">
            <Wordmark size={34} />
            <span className="ml-2 rounded bg-gray-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-gray-600 dark:bg-gray-800 dark:text-gray-400">console</span>
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">AppSec + cloud posture, one wall</p>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
              Username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              autoFocus
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800 focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            />
          </div>

          <div>
            <label htmlFor="password" className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800 focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
            />
          </div>

          <button
            type="submit"
            disabled={busy || !username || !password}
            className="w-full rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>

        {ssoEnabled && (
          <div className="mt-4">
            <div className="mb-3 flex items-center gap-3 text-[11px] uppercase tracking-wide text-gray-400">
              <span className="h-px flex-1 bg-gray-200 dark:bg-gray-800" />
              or
              <span className="h-px flex-1 bg-gray-200 dark:bg-gray-800" />
            </div>
            <a
              href="api/auth/oidc/start"
              className="block w-full rounded-lg border border-gray-300 px-3 py-1.5 text-center text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-accent-500 focus:ring-offset-2 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800 dark:focus:ring-offset-gray-900"
            >
              Sign in with SSO
            </a>
          </div>
        )}
      </div>

      <p className="mt-4 text-[11px] text-gray-400 text-center">Local-first console · sessions expire after 2h idle</p>
    </div>
  );
}
