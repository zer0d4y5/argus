# Console Ops — authenticated scan execution & user management

This document is the **spec** for the operational console: it was written
before the code, the code is required to match it, and the tests pin both.
It covers the threat model, the API surface, the authorization matrix, the
session/CSRF design, the bootstrap flow, and the deployment posture.

Scope shipped in the Console Ops phase: login + sessions, three roles,
registered-target scan launching through a strictly serial job queue,
user/target CRUD, and an append-only audit log. The pipeline itself was
extracted to `internal/pipeline` so the CLI and the server run the *same*
code path.

Scope shipped in the Scan Studio phase (threat rows S1–S6, §12): remote git
targets cloned into a server-owned workspace, per-launch scan scope
(subpath/file) and compliance-framework focus, console-managed per-target
scan configuration, captured code snippets in run files (schema 1.4.0), and
an on-demand, never-persisted AI explanation per finding.

---

## 1. Posture summary (honest version)

- **Zero users on disk ⇒ the console is exactly what it was before this
  phase**: a read-only, loopback-bound viewer over `.appsec/runs`. No login
  page, no session checks on read routes; every operational endpoint answers
  `403` with a message naming the bootstrap command
  (`bulwark user add --role admin`). Nothing to configure, nothing new to
  trust.
- **One or more users on disk ⇒ every `/api/*` route requires a session**,
  reads included. Mixed anonymous-read/authenticated-write is a footgun once
  the server can execute scanners, so the switch is all-or-nothing. The only
  exemptions are `POST /api/auth/login` (you cannot log in behind a login
  wall), `GET /api/auth/me` (the UI's "do I need to log in?" probe; returns
  auth state only), and `GET /api/health` (liveness: `{ok, time}`, nothing
  else). Static UI assets are served without a session — the login page is
  part of the SPA bundle.
- **The console still ships no TLS.** A login over plaintext HTTP is a
  credential disclosure to the network path. The supported way to leave
  loopback is a TLS-terminating reverse proxy in front (§8) — `bulwark serve`
  itself refuses to pretend otherwise, and the non-loopback warning says so.
- **The browser can never supply a filesystem path or a scanner argument.**
  Scans launch against pre-registered target IDs with closed-enum options,
  validated server-side against the registry entry. Path validation happens
  once, at registration time, by an admin.

## 2. Threat model

Each row is an attack the new surface invites, and the design decision that
closes it. Tests referenced in §9 pin every row.

| # | Surface | Attack | Countermeasure |
|---|---------|--------|----------------|
| T1 | `POST /api/scans` | Free-text target path: scan `/etc`, another user's home, or a path crafted to hit adapter bugs | The scan API accepts an **opaque registry ID only**. The server never joins request input into a filesystem path. Unknown ID → 404. Registration (admin-only) validates: absolute, exists, is a directory, not `/`, no `..` after cleaning. |
| T2 | Scan options | Flag/argument smuggling into scanner binaries (`--config`, `-o`, shell metacharacters) | No CLI strings cross the API. Options are a **closed enum**: scanner subset (validated against the target's allowed list), profile (`fast\|standard\|max`), triage on/off. Adapters keep their fixed argv; nothing from the request reaches `exec.Command`. |
| T3 | Session cookies | CSRF on any mutating route | Every non-GET route requires `X-CSRF-Token` matching a per-session random token (constant-time compare). Cookie is `HttpOnly`, `SameSite=Strict`, `Secure` when the login arrived over TLS. Missing/wrong token → 403. |
| T4 | Login | Credential stuffing, username/timing oracles, plaintext at rest | Passwords stored as **argon2id** (m=64MiB, t=1, p=4, 16B salt, 32B key). Unknown usernames verify against a dummy hash so timing does not distinguish "no such user" from "wrong password", and both return the same 401 body. Login is rate-limited per-IP **and** per-username (5 failures/min, then locked for 5 min). |
| T5 | User CRUD | Privilege escalation, self-demotion lockout, IDOR | Role checks live in one server-side middleware table (§5); UI hiding is cosmetic. Deleting or demoting the **last admin is refused (409)**. User IDs are random; the list endpoint is admin-only anyway. |
| T6 | Password hashes | Hash disclosure via API/logs/audit | API responses use dedicated DTOs that have **no hash field** — the storage struct is never serialized outward (test asserts on raw JSON bytes). Hashes and session tokens never appear in logs or audit lines. |
| T7 | Concurrent scans | Overlapping Ollama triage calls (single serial queue), runstore write races, resource exhaustion | **One job executes at a time**, strictly serial worker. The pending queue is bounded (10); an 11th submission is rejected with 429, never buffered. Triage stays "enrichment, never a dependency". |
| T8 | Existing users | Breaking the local-first read-only workflow | Zero-config behavior byte-identical to the previous release (see §1). The pre-auth server tests still pass unmodified against the zero-users mode. |
| T9 | Session theft | Stolen/undying sessions | Opaque 256-bit random tokens (no JWT — revocable by deletion), server-side table, **idle expiry 2h, absolute expiry 24h**, session destroyed on logout, all sessions for a user destroyed on password change or delete. |
| T10 | Audit log | Log forging / secret leakage | Audit lines are structured JSONL written server-side only (append-only file, 0600). User-controlled strings appear only as JSON string values. No password material, no tokens, no finding content. |
| S1 | Remote git targets | SSRF via crafted URLs (internal hosts, cloud metadata IPs); `file://`/`ext::`/`ssh -oProxyCommand` transport tricks; argument injection via URL into git argv; disk exhaustion from huge repos | URLs are parsed with `net/url` at registration (admin-only, same gate as dir targets) and must be `https://` with a host and **no userinfo** — `ssh://`, `git://`, `file://`, and scp-style syntax are rejected outright. `git` runs with a **fixed argv** (`--` separator before the URL; the URL is never string-concatenated), `-c protocol.file.allow=never -c protocol.ext.allow=never` plus `GIT_ALLOW_PROTOCOL=https` (belt and braces), `--depth 1 --single-branch --no-tags`, a hard clone/refresh time budget, and a post-clone workspace size cap. Clones land ONLY in the server-owned `.appsec/workspace/<targetID>`. No credentials ever come from the browser: private repos authenticate via the host's ambient git credential helper over https, or are out of scope. Residual: an admin can still point the server at an internal https host — registration is an admin action and is audited, same trust as registering a directory. |
| S2 | Scan scope (subpath/file) | Path traversal (`../`, absolute paths), symlink escape out of the target root, scoping into `.git/` or `.appsec/` bookkeeping | Scope is a **relative** path in the launch request, rejected at the API if absolute or containing `..` after `filepath.Clean`. It is joined server-side to the registered root and verified inside that root **after `EvalSymlinks`**, must exist, and must not enter `.git/` or `.appsec/`. Validated at enqueue AND re-validated at execution (the tree may change in between — always, for git targets, where the tree is refreshed per scan). The scanners receive the joined path exactly as the CLI's `[path]` argument works; no new argv shapes. |
| S3 | Console-managed scan config | Config fields ARE code execution: rulesets reach scanner argv, triage endpoints are SSRF, `ignore_paths`/`ignore_rules` silently suppress findings, timeout/concurrency are resource abuse | The console edits a **structured, closed subset** stored on the registry entry (never written into the target repo): allowed scanners (known set), default profile (enum), per-scanner timeout (bounded 10–3600 s), triage on/off, and ignore rules/paths (admin-only; every change is an audit event carrying the pattern/rule text, because suppression is the finding-killing knob). Triage provider/model/endpoint/API keys and `semgrep_rulesets` are **never** console-editable — they come from the target repo's `appsec.yml` and the environment only. Precedence is fixed and table-tested: repo `appsec.yml` < registry overrides < per-launch options (§12.3). |
| S4 | Code snippets in run files | Secret material persisted into `runs/*.json` (the gitleaks payload scrub exists precisely to prevent this); unbounded snippet size; hostile file content | Snippets are captured server-side at scan time by `internal/snippet` (the same symlink-confined reader triage uses — extracted, not re-derived), bounded per finding (≤10 lines, ≤2 KB) and per run (≤1 MiB total). **SECRET-category findings get NO snippet, ever** — metadata only, the same rule triage applies to prompts. Files that look binary (NUL in window) or minified (extreme line length) are skipped. A snippet is hostile data like any finding text: rendered as escaped text only, never HTML. |
| S5 | On-demand AI explain | Prompt injection from hostile code; token/compute abuse from the browser; secret material sent to a cloud provider | Reuses the triage boundary machinery verbatim: CSPRNG boundary markers, sanitized length-capped inputs, strict output validation, snippet confinement, and the SECRET-never-to-cloud gate (metadata-only prompt for secrets; cloud providers refused unless the repo config opted in). Operator+ role, single-flight per finding, in-memory LRU cache, hard `MaxTokens` cap. Explanations are ephemeral enrichment returned to the browser — **never written into run files or the audit log** (the audit line records that an explanation was requested, not its content). Provider/model/endpoint come from the target repo's `appsec.yml` only. |
| S6 | Compliance-scoped scans | Pretending a framework filter is an audit ("we scanned for PCI") when mapping is enrichment over whatever the scanners found | Frameworks are a **closed enum from the embedded compliance data**. Selecting them (a) filters reporting emphasis in the run detail view and (b) narrows scanner selection through a hand-curated framework→scanner-relevance table (§12.5) — it never changes mapping logic, and an empty intersection with the chosen scanners is a 400, not a silent no-op. The frameworks requested are recorded on the job and in the audit line — the run file shape is unchanged, and nothing anywhere claims "PCI-certified": a framework-scoped scan is the same scan with relevant scanners and a filtered lens. |
| C1 | Cloud target registration | **Credential exfiltration**: an admin (or a compromised admin session) submits a raw access key / secret, which the platform then stores in `targets.json`, logs, or a run file — turning the tool into a credential store to be looted | **Credentials are referenced, never collected** (the locked decision). The registration API accepts a `{provider, profileName, regions}` shape with NO key field. `profileName` is validated against the **closed list discovered from the console host's own cloud config** (`cloudscan.ListAWSProfiles`, which reads section headers ONLY — credential values are never parsed). A name outside that list → 400. Nothing key-shaped is accepted, so nothing key-shaped can be stored; the platform runs with whatever the host is already authenticated as. Residual: the console host must be pre-authenticated to the cloud (fine for local-first; a hosted deployment needs a real secrets design, explicitly deferred). |
| C2 | Profile name → child env | **Injection into `AWS_PROFILE`**: a crafted profile name (`default; rm -rf /`, `$(whoami)`, a newline injecting a second env var) reaching the prowler child environment | The chosen name is re-validated at scan time against the same discovered closed list (`cloudscan.Validate`) — a value that is not literally a section of `~/.aws` never reaches an env var, whatever surface supplied it (console form OR CLI flag). It is passed as a single `AWS_PROFILE=<name>` entry in the child's env slice (never a shell, never string-concatenated), and dies with the process. Regions match a closed `^[a-z0-9-]{1,32}$` grammar and are exec args, never shell. |
| C3 | Account data in logs/audit | **Sensitive account identifiers** (account IDs, ARNs, prowler's stderr which echoes them) leaking into progress output, the audit log, or an error message | Prowler's stderr is **never raw-streamed** — the platform emits its own summarized progress lines. The error path surfaces only a bounded, ANSI-stripped, **account-ID-masked** tail of stderr (`tailBuffer.Summary`). Account IDs/ARNs appear only where prowler's own JSON already places them inside a finding (they are the finding's identity). The audit line records that a cloud scan ran (target ID, run ID) — never a credential, never raw account data. |
| C4 | Cloud findings to the LLM | A cloud finding carries account IDs/ARNs (mildly sensitive) into a triage/explain/posture-summary prompt, or a "posture agent" is given tool access / a credential | The LLM stays at the **existing seams only** (triage verdict, on-demand explain, on-demand posture summary) — no agent loop, no tool use, no credential ever in context (a cloud finding has no secret value to carry). Prompts are metadata-only (there is no source file), through the same CSPRNG-marker boundary and output validation as every other category. Cloud findings are metadata, not secrets, so they follow the normal (non-SECRET) provider rules: local-LLM by default; a cloud provider only if the repo already opted in via `triage.allow_cloud`-style config. The posture summary is on-demand, never persisted, and labeled AI-generated in the UI. |

Residual risk, stated plainly: no TLS in-process (§8); job/queue state is
in-memory (a restart forgets queue history — completed runs and the audit
file are the durable records); the users/targets/audit files are protected
by file permissions (0600), not encryption — an attacker with local file
access already owns the host.

## 3. On-disk layout

Everything lives under the served repo's `.appsec/` directory, which is
already `.gitignore`d wholesale (the existing rule that keeps `runs/` out of
version control covers these too):

| File | Contents | Mode |
|------|----------|------|
| `.appsec/users.json` | `{schema, users: [{id, username, hash, role, createdAt}]}` — argon2id encoded hashes | 0600 |
| `.appsec/targets.json` | `{schema, targets: [{id, name, type, path?, url?, branch?, scanners, profile, config?, createdAt}]}` | 0600 |
| `.appsec/audit.jsonl` | append-only, one JSON object per line | 0600 |
| `.appsec/runs/*.json` | additive schema 1.4.0 (optional `location.snippet`); shape otherwise frozen | 0644 |
| `.appsec/workspace/<targetID>/` | server-owned working copy of a git target (shallow clone, refreshed per scan); its own `.appsec/runs` holds that target's run history | 0755 |

Decision: the file is named `users.json` (not `console-users.json`) — it sits
inside an already-ignored directory and there is only one kind of user.

Decision: **run provenance lives in the audit log, not the run file.** The
runstore JSON shape is a frozen contract (it is `report.Document`, shared
with the `--format json` report); adding `launchedBy` would leak a console
concern into every CLI report. The `scan.launch`/`scan.finish` audit pair
carries who/target/options/runID and is the durable provenance record.

## 4. Roles

Three roles, strictly ordered: `viewer < operator < admin`.

| Role | May |
|------|-----|
| `viewer` | Read everything a logged-in user can see: summary, runs, findings, targets, job list/status |
| `operator` | Viewer + launch scans (`POST /api/scans`) |
| `admin` | Operator + user CRUD, target CRUD, read the audit log |

## 5. Authorization matrix

Authorization is **one table in one file** (`internal/server/authz.go`),
route pattern + method → minimum role, checked in middleware before any
handler runs. The UI hides what you cannot do; the server refuses it.

Legend for the zero-users column: `open` = behaves exactly as the pre-auth
console; `403+hint` = refused with a body naming `bulwark user add`.

| Method | Route | Min role (users exist) | Zero users |
|--------|-------|------------------------|------------|
| GET | `/api/health` | none (exempt) | open |
| GET | `/api/auth/me` | none (exempt) | open |
| POST | `/api/auth/login` | none (exempt; rate-limited) | 403+hint |
| POST | `/api/auth/logout` | viewer | 403+hint |
| GET | `/api/summary` | viewer | open |
| GET | `/api/runs` (`?target=<id>` reads a registered target's own history) | viewer | open |
| GET | `/api/runs/{id}` (`?target=<id>` as above) | viewer | open |
| GET | `/api/frameworks` | viewer | open |
| GET | `/api/targets` | viewer | open |
| POST | `/api/targets` | admin | 403+hint |
| PATCH | `/api/targets/{id}` | admin | 403+hint |
| DELETE | `/api/targets/{id}` | admin | 403+hint |
| GET | `/api/scans` | viewer | open |
| GET | `/api/scans/{id}` | viewer | open |
| POST | `/api/scans` | operator | 403+hint |
| POST | `/api/explain` | operator | 403+hint |
| GET | `/api/users` | admin | 403+hint |
| POST | `/api/users` | admin | 403+hint |
| PATCH | `/api/users/{id}` | admin | 403+hint |
| DELETE | `/api/users/{id}` | admin | 403+hint |
| GET | `/api/audit` | admin | 403+hint |
| GET | `/` + static assets | none (SPA shell, includes login page) | open |

Notes:
- "Zero users / open" read routes exist so the local read-only workflow needs
  no setup. `GET /api/targets` and `GET /api/scans` return empty-but-valid
  payloads in that mode; they are listed `open` because they are reads with
  nothing sensitive in them, keeping the mode rule simple: *reads open,
  everything else 403+hint*.
- Unauthenticated request to a protected route → **401** (UI shows login).
  Authenticated but under-privileged → **403**. No-session on a mutating
  route fails authz (401) before CSRF is even considered.
- Status codes used by ops routes: `202` scan accepted, `429` queue full,
  `404` unknown target/job/user ID, `409` last-admin protection and duplicate
  username, `400` closed-enum violation.

## 6. Session & CSRF design

- **Login**: `POST /api/auth/login {username, password}`. On success the
  server issues an opaque token — 32 bytes from `crypto/rand`,
  base64url — stored server-side (keyed by SHA-256 of the token) with
  `{userID, role, csrfToken, createdAt, lastSeen}`. The response sets
  `appsec_session` (`HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` if the
  request arrived over TLS or `X-Forwarded-Proto: https`) and returns
  `{user: {username, role}, csrfToken}`.
- **CSRF**: the per-session CSRF token is returned by login and by
  `GET /api/auth/me`; the SPA sends it as `X-CSRF-Token` on every non-GET
  request. The middleware rejects any non-GET API request whose header does
  not match the session's token (constant-time compare) with 403.
  `SameSite=Strict` is the first layer; the token check is the second —
  both are enforced, and both are tested.
- **Expiry**: idle 2 hours (sliding on authenticated requests), absolute 24
  hours. Expired sessions are deleted on touch and swept opportunistically.
- **Revocation**: logout deletes the session; password change and user
  deletion delete all of that user's sessions. Opaque tokens make this exact
  (this is why there is no JWT).
- **Rate limiting** (login only): fixed 1-minute window, 5 failures per IP
  and 5 per username → that key is locked for 5 minutes; the limiter answers
  429 before credentials are checked. Success resets the counters.
- Passwords: argon2id via `golang.org/x/crypto/argon2`, parameters
  `m=65536 KiB, t=1, p=4`, 16-byte salt, 32-byte key, stored in the standard
  `$argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>` encoding (parameters are
  read back from the stored string, so they can be raised later without
  invalidating existing users). Minimum password length 8; no other
  composition rules.

## 7. Scan execution model

- **Registry**: targets are registered by an admin (CLI `bulwark target
  add|list|remove` or the admin API) as
  `{id, name, path, scanners, profile}`. `id` is random hex, assigned by the
  server — the browser only ever echoes it back. Path validation at
  registration: absolute, `filepath.Clean`-stable, exists, is a directory,
  not `/`. Nothing else about the path is ever derived from request data.
- **Launch**: `POST /api/scans {targetId, options: {scanners?, profile?,
  triage?}}` (operator+). Options are validated against the registry entry:
  requested scanners must be a subset of the target's allowed scanners;
  profile must be one of the target's profile or `fast|standard|max`; triage
  is a boolean that flips `triage.enabled` — the provider, model, endpoint
  and every other triage setting come from the target repo's `appsec.yml`,
  never from the request. Accepted → `202 {job}`.
- **Queue**: strictly serial — one worker goroutine, one job running at any
  moment (this also protects the single-queue Ollama instance during
  triage). Pending queue is bounded at 10; beyond that submissions are
  rejected with 429 ("reject, don't buffer"). Job state
  (`queued|running|done|failed`, progress lines from the pipeline callback,
  run ID on success) is **in-memory**; `GET /api/scans` lists recent jobs,
  `GET /api/scans/{id}` is polled by the UI (no WebSockets by design).
- **Execution**: the worker calls `pipeline.Run` — the same function the CLI
  `scan` command now wraps — with the target repo's own `appsec.yml` as the
  config base. Findings are saved through the existing `runstore.Save` path
  **into the scanned target's own `.appsec/runs`**, exactly where
  `bulwark scan --save` would put them. When the target is the served repo
  (the primary workflow: register the repo you're serving), the run appears
  in the console's runs list with no new read API. A target pointing at a
  different repo still scans and saves correctly, but its history lives with
  that repo — serve it to browse it. Mixing several repos' runs into one
  history would corrupt the delta/trend semantics, so we don't.
  Report writing to stdout/files is a CLI concern and does not happen for
  console-launched scans.
- **Audit**: `scan.launch` (actor, target ID, options) on acceptance,
  `scan.finish` (job ID, run ID or error class) on completion.

### `internal/pipeline` extraction

`pipeline.Run(ctx, Options{Target, Config}, progress)` owns: adapter
selection, parallel scanner execution with per-adapter timeouts, normalize →
ignore-filter → correlate → triage (enrichment-only) → risk → compliance →
optional false-positive exclusion. `progress` receives the exact
pre-formatted lines the CLI used to print — the CLI writes them verbatim to
stderr (byte-identical output, verified against a golden capture), the
server appends them to job progress. Report writing, run saving, the summary
line and the severity gate stay with the caller: the CLI must write the
report *before* saving (a failed report write must not leave a saved run),
and the server saves but never writes reports.

## 8. Deployment: leaving loopback

`bulwark serve` binds `127.0.0.1:8080` and terminates no TLS. That is a
feature: TLS config is deployment-specific and doing it badly is worse than
not doing it. **The supported way to expose the console is a
TLS-terminating reverse proxy** (Caddy, nginx, Traefik) on the same host:

```
caddy reverse-proxy --from console.example.internal --to 127.0.0.1:8080
```

The proxy must pass `X-Forwarded-Proto: https` so the session cookie is
marked `Secure`. Widening `--addr` directly still prints a warning: with
zero users it is the old NO-AUTH warning; with users it warns that
credentials will cross the network in cleartext without a TLS proxy.

## 9. Test map (security first)

| Pin | Test |
|-----|------|
| Authz matrix (§5) | table-driven: every route × {no session, viewer, operator, admin} × {zero-users, users-exist} → expected status |
| CSRF | non-GET with missing/wrong token → 403; correct token → 2xx |
| Login rate limit | 6th failure in window → 429; correct password while locked → 429 |
| Timing/oracle | unknown user and wrong password return identical status+body |
| Last admin | delete/demote sole admin → 409; works once a second admin exists |
| Hash leakage | raw JSON of every user-bearing response asserted to contain no `$argon2` / `hash` material |
| Target registry | unknown target ID → 404; `target add` with relative / `..` / file / `/` → rejected |
| Serial queue | two POSTed scans: second stays `queued` until first finishes; 11th pending → 429 |
| Zero-users mode | pre-existing server tests unchanged; ops routes → 403 naming the bootstrap command |
| Pipeline | golden capture: `bulwark scan` stdout/stderr/exit codes byte-identical pre/post extraction |
| Git URL policy (S1) | table-driven: `http://`, `ssh://`, `git://`, `file://`, scp-style, userinfo, no host, argument-injection shapes (`--upload-pack=…`) → rejected; plain https accepted |
| Git executor (S1) | local bare-repo fixtures (`git init --bare` in tempdir; `file://` clones allowed ONLY via explicit test hook, never in production config); clone→scan→commit-SHA recorded; refresh preserves workspace `.appsec/runs`; no network in tests |
| Scope confinement (S2) | table-driven: `../`, absolute, `.git/…`, `.appsec/…`, nonexistent, symlink-escape via a real symlink fixture → 400/failed; valid subdir and single file → scanned path = joined path |
| Config merge (S3) | precedence table: repo yaml vs registry vs launch for every field; bounds (timeout, pattern count/length) rejected at API; `target.update` audit carries pattern text |
| Snippets (S4) | SECRET finding has NO snippet asserted on the RAW run file bytes; per-finding and per-run caps; binary/minified skip; symlink escape yields no snippet |
| Explain (S5) | authz (viewer 403); response never appears in run files (raw bytes asserted); single-flight and cache behavior; SECRET+cloud refused without opt-in |
| Frameworks (S6) | unknown framework → 400; narrowing table intersection incl. empty → 400; framework list endpoint matches embedded data |
| Cloud credentials (C1–C4) | profile discovery reads section headers only (secret value not in output); registration/validate reject unknown & injection-shaped names; `childEnv` carries exactly `AWS_PROFILE=<name>`; grep the whole `.appsec` tree (run file, targets.json, audit) → no key material; cloud launch rejects filesystem options |
| Authz extension | every new route × every role × zero-users appended to the existing matrix test (extended, not forked) |

## 10. Bootstrap walkthrough

```bash
# 1. Create the first admin (CLI only — there is no open registration API).
cd /path/to/repo
bulwark user add alice --role admin            # prompts for password (no echo)
# or, for scripting:
echo -n 's3cret-passphrase' | bulwark user add alice --role admin --password-stdin

# 2. Register what may be scanned (admin).
bulwark target add /abs/path/to/repo --name "payments-api" --scanners semgrep,gitleaks

# 3. Serve and log in.
bulwark serve            # http://127.0.0.1:8080 now shows a login page

# 4. Onboard teammates from the console (admin → Users) or the CLI:
bulwark user add bob --role viewer
bulwark user add carol --role operator

# 5. Operate: pick a target, choose scanners/profile/triage, Launch.
#    Watch the job progress; the finished run lands in Runs as usual.
#    Admins can review every action under Audit.
```

`bulwark user list|passwd|remove` and `bulwark target list|remove` complete
the lifecycle. All user/target commands take `--dir` like `serve` does.

## 11. Explicit non-goals

No OIDC/SSO/LDAP/passkeys (the session layer is deliberately swappable), no
in-process TLS, no scheduling, no multi-tenancy, no per-target permissions,
no WebSockets.

Scan Studio additions: no credentials for private repos from the browser
(ambient host git auth only); no YAML upload/download or raw config text
editing; no parallel scan execution; no writing anything into scanned repos
(the workspace is server-owned; dir targets are read-only to the platform);
no editing/suppressing individual findings from the console (ignore rules
via target config are the only suppression path — admin-gated and audited);
no PDF/exports.

## 12. Scan Studio: versatile scan jobs & deep finding context

### 12.1 Target types: `dir` and `git`

One registry, one additive `type` field (`"dir"` | `"git"`; absent = `dir`,
so existing files parse unchanged). A git target stores the validated URL
and an optional branch instead of a path:

- **URL policy (S1)**: parsed with `net/url`; scheme MUST be `https`, host
  MUST be present, userinfo MUST be absent (a token in a URL would persist
  into `targets.json` and argv). Everything else — `ssh://`, `git://`,
  `file://`, scp-style `host:path` — is rejected at registration. Private
  repos work through the host's ambient git credential helper (documented
  here, deliberately not configurable from the console).
- **Workspace**: the working copy lives at `.appsec/workspace/<targetID>`
  under the SERVED repo (inside the already-gitignored `.appsec/`). The job
  executor creates it with `git clone --depth 1 --single-branch --no-tags`
  (plus `--branch <b>` when registered) and refreshes an existing one with
  `git fetch --depth 1` + `git reset --hard FETCH_HEAD` — reset, not
  `clean -fdx`, so the workspace's own untracked `.appsec/runs` history
  survives refreshes. Fixed argv with a `--` separator; transport locked
  with `-c protocol.file.allow=never -c protocol.ext.allow=never` and
  `GIT_ALLOW_PROTOCOL=https`; hard time budget (10 min) on clone/refresh and
  a post-clone size cap (1 GiB) that fails the job loudly.
- **Commit provenance**: after refresh the executor records the scanned
  commit (`git rev-parse HEAD`) in the job state (`commit`), a progress line
  (`==> at commit <sha>`), and the `scan.finish` audit entry. A remote-repo
  scan is a scan of a shallow clone at one commit — the record says exactly
  that.
- **Registration stays admin-only for BOTH types**: a remote clone is still
  server-side code-adjacent activity. "Launch against any repo" is satisfied
  by registration being a 10-second admin action in the same UI.
- **Run history per target**: console-launched runs save into the scanned
  target's own `.appsec/runs` (workspace for git targets). The read API
  accepts `?target=<registryID>` on `GET /api/runs` and `GET /api/runs/{id}`
  to browse a registered target's history — the target ID resolves through
  the registry server-side, so no path ever comes from the browser. Without
  the parameter the routes serve the served repo's history exactly as
  before. Delta/trend semantics stay per-repo because each store is
  separate.

### 12.2 Scan scope (S2)

`POST /api/scans` gains `options.scope`: a **relative** subpath or single
file inside the target, validated per threat row S2 (relative, cleaned, no
`..`, exists, inside root after `EvalSymlinks`, not into `.git/` or
`.appsec/`) at enqueue and re-validated at execution. The pipeline receives
the joined path the same way `bulwark scan <path>` does. Scope is recorded on
the job and in the `scan.launch` audit line. The run is saved to the
TARGET's run store (not the scope subdirectory) — a scoped run is part of
the target's history, labeled by its job. No CLI change: `bulwark scan
<path>` already is scope.

### 12.3 Config layering (S3)

Registry entries gain a structured `config` block, editable only via
`PATCH /api/targets/{id}` (admin) or `bulwark target` CLI:

```
config: {
  timeoutSec:  int      // per-scanner timeout, 10–3600
  triage:      bool?    // default triage on/off for this target
  ignorePaths: []string // glob patterns, ≤50 entries, ≤200 chars each
  ignoreRules: []string // exact rule IDs, same bounds
}
```

Allowed scanners and default profile remain the existing top-level target
fields, editable through the same PATCH. Everything else in `appsec.yml` —
triage provider/model/endpoint, semgrep rulesets, fail severity, format —
is NOT reachable from the console.

Precedence, owned by ONE merge function and table-tested:

```
repo appsec.yml  <  registry entry (scanners/profile/config)  <  per-launch options
```

One deliberate exception to "later layer wins": **ignore lists are
additive** — registry `ignorePaths`/`ignoreRules` APPEND to whatever the
repo's `appsec.yml` declares. Console config can add suppressions; it can
never silently undo the repo's own.

Every config change writes a `target.update` audit event listing the changed
fields; ignore-rule/path changes include the pattern text in the audit line
(suppression must be reviewable). Git targets always scan with a
`<scan-root>/.appsec/**` ignore appended (anchored to the root exactly as
scanners report paths — a bare `.appsec/**` would match the workspace's own
path prefix under a relative serve dir and suppress everything) so a
workspace's run history never feeds back into findings.

### 12.4 Snippets in run files (S4)

`internal/snippet` captures a bounded code frame per finding after the
pipeline completes and before the run is saved (both the console executor
and CLI `--save` do this, so run files are consistent; report stdout is
unchanged). Schema 1.4.0, additive: `location.snippet: {startLine, lines}`.
Rules: SECRET findings are always metadata-only; ≤10 lines / ≤2 KB per
finding; ≤1 MiB per run (capture stops, remaining findings stay
snippet-less); binary and minified files skipped; confinement by the same
symlink-resolving reader triage uses. Old runs render fine without snippets
(feature detection, no migration). See docs/findings-model.md.

### 12.5 Compliance focus (S6)

`options.frameworks: []string` on `POST /api/scans`, validated against the
closed enum from the embedded compliance data (`GET /api/frameworks` lists
it). Effect: (a) the run detail view gains a per-framework filter lens, and
(b) scanner selection narrows through this hand-curated relevance table
(intersection with the chosen/allowed scanners; empty intersection → 400):

| Framework | Relevant scanners | Why |
|---|---|---|
| ASVS | semgrep, gitleaks, trivy | scope SAST/SECRET/SCA — code, secrets, dependencies |
| PCI-DSS | semgrep, gitleaks, trivy, checkov, trivy-config | scope covers all four categories |
| CIS-AWS | checkov, trivy-config | IAC-only scope, AWS rule families |
| CIS-DOCKER | checkov, trivy-config | IAC-only scope, Docker rule families |
| CIS-K8S | checkov, trivy-config | IAC-only scope, Kubernetes rule families |

The table lives next to the compliance data and must be updated when a
framework file is added (a loader test pins the correspondence). Frameworks
are recorded on the job and audit line, NOT in the run file (same rule as
`launchedBy`: run files are the frozen `report.Document`). CLI parity:
`bulwark scan --frameworks PCI-DSS` validates and narrows identically, with a
NOTE progress line naming the narrowed scanner set.

### 12.6 On-demand explain (S5)

`POST /api/explain {targetId?, runId, findingId}` (operator+; no `targetId`
= the served repo's history): loads the finding from the named run and asks
the target repo's configured triage LLM for a structured explanation. The
code context is the snippet already captured IN the run file (schema 1.4.0,
bounded and confined at scan time) — explain performs no new filesystem
reads on behalf of a browser request; findings without a stored snippet get
a metadata-only explanation. The boundary is the triage machinery
reused verbatim: CSPRNG delimiters, sanitized bounded inputs, strict JSON
output validation, sanitized length-capped output text, SECRET metadata-only
+ never-to-cloud gate. Single-flight per (target,run,finding), bounded
in-memory cache, `MaxTokens` hard cap. The response
`{explanation, model, cached}` is ephemeral — never persisted to run files;
the `scan.explain` audit event records actor/target/run/finding, never
content. No configured/reachable provider → 503 with an honest message.

### 12.7 Deep-scan session deltas (schema 2.0.0)

- **Severity is banded deterministic risk** (docs/risk-scoring.md "Severity
  banding"). Console severity badges/filters are unchanged in look; the
  finding drawer adds a muted "tool said: …" chip when `toolSeverity`
  differs from the banded value. The Overview histogram counts severities,
  so it agrees with the badges by construction (plus an `info` bar).
- **Git-history secrets** (locked decision 5): SECRET findings with
  `meta.gitHistory` get an amber "GIT HISTORY" badge (tooltip: rotate,
  don't just delete) and a "Commit" row in the drawer. The S4 rule is
  unchanged and re-proven: history findings are SECRET findings — no
  snippet, ever, and the same payload scrub applies to the history pass.
- **Skip accounting**: run detail shows the `coverage` block from the run
  file (schema 2.0.0) — SAST-covered / IaC-config / secrets-only /
  unsupported-source / binary / oversize counts with sample paths, plus
  git-repo/shallow facts. Absent on pre-2.0.0 runs; the UI feature-detects.
  Accounting is computed at save time from the scanned path (the scope
  subdirectory when a scope is set), read-only, inside the workspace root.

### 12.8 New audit events

| Event | When | Details carried |
|---|---|---|
| `target.update` | PATCH target (config/scanners/profile/name) | target ID, changed fields; ignore patterns verbatim |
| `scan.explain` | explain requested (cache miss or hit) | target, run, finding ID, cached flag |
| `scan.launch` / `scan.finish` | unchanged | + `scope`, `frameworks` on launch; + `commit` on finish for git targets |

## 13. Cloud posture targets (schema 2.1.0)

The cloud-posture session adds a third target kind, `cloud`, and a new finding
category, `CLOUD`. A cloud target scans an ACCOUNT through prowler, not a
filesystem path — so it gets its own registration shape, execution branch, and
run storage, while everything downstream (banding, risk, compliance, triage,
console) is the SAME pipeline every other category flows through.

### 13.1 Registration and the credential contract (C1/C2)

A cloud target is `{provider, profileName, regions?}` — a **NAME**, never a
key. The console form offers profile names discovered server-side from the
console host's own cloud config (`GET /api/cloud/profiles`, admin-only;
`cloudscan.ListAWSProfiles` reads INI **section headers only** — credential
values are never parsed). Registration (`AddCloud`) and every scan
(`cloudscan.Validate`) re-check the chosen name against that closed list, so a
free-form or injection-shaped name never reaches an env var. The one place a
credential-adjacent value enters a child process is `childEnv`, which appends
exactly `AWS_PROFILE=<validated-name>` — proven by grep-tests that no key
material reaches `targets.json`, the audit log, a run file, progress output, or
a prompt (threat rows C1–C4). The console host must be pre-authenticated to
the cloud; a hosted deployment would need a real secrets design, explicitly
deferred.

### 13.2 Execution and run storage

Cloud scans run through the same serial job queue. The executor branches on
`TypeCloud` to `execCloudScan`, which calls `pipeline.RunCloud` (prowler →
`Enrich`: normalize → correlate → triage seam → risk+band → compliance) under
a generous per-provider timeout (config `cloud.timeout`, default 1800 s).
Prowler's stderr is never raw-streamed — summarized progress lines only; the
error path masks account IDs (C3).

**Run storage is a conscious design choice:** a cloud target has no filesystem
to own its history, so its runs live at `.appsec/cloud/<targetID>/runs` under
the served repo (`Registry.CloudRunStore`), reusing the exact runstore
machinery (list, load, deltas) code targets use. The resource-slot fingerprint
(schema 2.1.0) gives the same check on the same resource a stable identity
across runs, so run-to-run deltas work for cloud runs with no new machinery.
`runStoreFor` and the aggregated Runs tab resolve the cloud store by target ID.

### 13.3 Console surface

Cloud runs appear in the aggregated Runs tab tagged by target. The Findings
drawer feature-detects location: `location.resource` (the ARN/UID) replaces
`file:line`, and the snippet/git-blob/explain-from-source paths hide gracefully
(a cloud finding has no source file). One optional new surface: an on-demand,
never-persisted **posture summary** (`POST /api/cloud/posture-summary`,
operator+) over one run's rollup — counts, top risk signals, top CIS control
gaps — clearly labeled AI-generated. Scan launch rejects the filesystem knobs
(scanner/profile/scope/framework) for cloud targets rather than silently
ignoring them; only the triage toggle applies.
