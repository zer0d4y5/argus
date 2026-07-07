# Platform evolution: for everyone

Argus today is a single local binary: a student scans a class project on a
laptop with no account, no cloud, no telemetry. That stays true forever — it's
the floor, not a trial. This document plans the ceiling: the opt-in layers that
let the same tool serve an IT shop, a startup, and an enterprise without
forking the product or betraying its invariants.

The through-line: **local-first and free at the core; enterprise controls are
layers you switch on, never a different edition.** Three initiatives, in the
order they should land.

- [1. SSO sign-in (OIDC)](#1-sso-sign-in-oidc)
- [2. Approved cloud remediation](#2-approved-cloud-remediation)
- [3. Brand: one tool, every scale](#3-brand-one-tool-every-scale)

Nothing here is built yet. Each section ends with the **decisions** that are
genuinely yours to make before code starts.

---

## 1. SSO sign-in (OIDC)

**Why:** the file-based user store (`argus user add`) is right for one person
or a small team, but an enterprise wants people to sign in with the identity
they already have — Google Workspace, Microsoft Entra ID (Microsoft 365), Okta,
Auth0. All four speak **OpenID Connect**, so one OIDC implementation covers them.
SAML is the legacy holdout; it can come later if a specific enterprise blocks on
it, but it earns nothing the named providers don't.

**How it grafts onto what exists.** The current model (`internal/server/auth`)
is: users in a file with an argon2id hash, in-memory sessions keyed by the
SHA-256 of an opaque cookie, roles `viewer`/`operator`/`admin`, and one authz
table (`authz.go`) that every route is matched against. SSO changes exactly one
thing — *how a session gets minted* — and nothing about *what a session may do*.
The authz table, the audit log, the matrix test, and the CSP all stand.

Concretely:

- **Login flow:** OIDC Authorization Code + PKCE. On `GET /api/auth/oidc/start`
  the server redirects to the provider; on `GET /api/auth/oidc/callback` it
  verifies the ID token against the provider's JWKS (`iss`, `aud`, `exp`,
  `nonce`) and reads the stable `sub` and email. A verified token mints a
  session exactly like a password login does from that point on.
- **The client secret is referenced, never stored** — env-var name in config,
  read at flow time, the same pattern the GitHub-sync token already uses.
- **User record grows two fields:** `Provider` (`local` | `oidc`) and `Subject`
  (the IdP `sub`). Local users keep their `Hash`; OIDC users have none.
- **Session invalidation, generalized.** Today `HashAtLogin` invalidates a
  session the instant a password changes. SSO users have no password, so this
  becomes a provider-agnostic `AuthEpoch` integer on the user: bumped on a
  password change *or* a role change *or* a deprovision, and compared on every
  request. One mechanism, both kinds of user, same instant-revocation guarantee.
- **Provisioning:** just-in-time on first login, gated by an **allowed-domains**
  list so only your org's identities auto-create, landing at a configurable
  default role (`viewer`). An admin promotes from there, or an optional
  group-claim → role map does it automatically.
- **Local-first is untouched:** OIDC is absent unless configured; zero-config
  still boots the open read-only console, and `argus user add` still works for
  air-gapped installs.

Config shape (mirrors the established `ticketing.github` block):

```yaml
auth:
  oidc:
    issuer: https://accounts.google.com     # or your Okta / Entra issuer URL
    client_id: <public>
    client_secret_env: ARGUS_OIDC_SECRET     # referenced, never stored
    redirect_url: http://127.0.0.1:8080/api/auth/oidc/callback
    allowed_domains: [example.com]           # JIT guard; empty = pre-provisioned only
    default_role: viewer
    group_claim: groups                       # optional
    role_map:                                 # optional: IdP group → console role
      argus-admins: admin
      security-eng: operator
```

**Decisions for you:**

1. **OIDC only to start, or SAML too?** OIDC covers Google/Entra/Okta/Auth0;
   SAML is real work for the enterprise long tail. Recommend OIDC first.
2. **JIT provisioning with a domain allowlist, or pre-provision only?** JIT
   scales to "everyone in the org" with no admin toil; pre-provision is tighter
   but manual. Recommend JIT + allowlist + `default_role: viewer`.
3. **Map IdP groups to roles now, or assign in-app after first login?** Group
   mapping is what enterprises expect; it's a small addition on top of JIT.

---

## 2. Approved cloud remediation — SHIPPED

> Shipped as designed below: a curated catalog (`internal/cloudremediate`), an
> injectable profile-scoped runner, admin-only execution gated by
> `remediation.enabled`, a per-finding panel with dry-run + apply, and an audit
> trail. The LLM authors nothing that runs; a fix never marks a finding fixed.


**Why:** finding a public S3 bucket and handing back a script the user pastes
themselves is honest, but at scale people want the fix *applied* — with a human
saying yes. The catch: the product's spine is that it **never executes anything
and never holds a write credential** (`internal/triage/remediate_safety.go`).
Auto-apply can't erase that; it has to *evolve* it without becoming "the AI
changed prod while you were at lunch."

**The design that keeps the soul.** The LLM does **not** author commands that
then run. Execution is limited to a **curated catalog of vetted, parameterized,
reversible remediations** — the same philosophy as the STRIDE library and the
mitigation library: deterministic where it matters, assistive where it's safe.
The model's only job is to *suggest which catalog entry fits a finding and
explain it*; the command that runs comes from a reviewed template with the
resource id filled in. An arbitrary LLM-authored `aws` line never touches a
credential.

Layered guardrails, all of which must hold:

- **The safety linter stays a hard gate.** Destructive verbs (`delete`,
  `terminate`, `drop`, `rm -rf`, allow-all) are refused *even with approval* —
  they are never in the catalog and never executable. You cannot approve your
  way to an irreversible action; those stay manual, forever.
- **Curated + reversible only, to start:** block S3 public access, enable
  default encryption, enable bucket/flow logging, enforce TLS-only policies, tag
  a resource. Every entry is idempotent and reversible, with the inverse
  recorded for rollback where the provider supports it.
- **Explicit per-change approval:** the console shows the exact resource, the
  exact command, and a **dry-run / plan preview** of the predicted effect. One
  finding, one approval, before anything runs.
- **A separate, opt-in write credential.** The read path stays read-only
  (`SecurityAudit` + `ViewOnlyAccess`). Applying uses a *distinct*,
  least-privilege remediation profile the operator provisions and names — off by
  default, referenced not stored, resolved inside the child process exactly like
  `cloudscan` resolves the audit profile. No write credential ever enters
  Argus's memory, config, or logs.
- **Approval is a privileged action:** gated to a role (admin, or a new
  `remediator`), CSRF-protected, and every apply is audited with the finding,
  actor, resource, command, dry-run result, and outcome.
- **A fix never marks itself fixed.** Only a re-scan clears a finding — the
  existing rule holds, so every applied remediation ends with a verification
  scan, not a trust-me.

This makes "auto-apply with approval" a controlled, reviewable, reversible
action over a vetted catalog — not an agent with a shell.

**Decisions for you:**

1. **Curated catalog only (recommended), or also execute LLM-authored
   commands?** The catalog preserves every invariant; executing model output
   does not. Strong recommendation: catalog only.
2. **What's in the first safe catalog?** Propose the S3 / encryption / logging /
   TLS set above; you pick the initial scope.
3. **Who may approve an apply?** Admin only, or a dedicated `remediator` role?
4. **Same-account write profile, or a break-glass step** (e.g. approval + a
   time-boxed elevated profile) for regulated environments?

---

## 3. Brand: one tool, every scale

Argus isn't a small-business tool or an enterprise tool — it's **one tool that
grows with you**. The same binary serves:

- **Students & learners** — scan a project on a laptop, free, local, no account,
  see real findings mapped to real weakness classes. A way to learn AppSec by
  doing.
- **IT shops & solo builders** — one command in CI, a severity gate, a console
  anyone can read. No platform to run, no per-seat bill.
- **Startups** — code and cloud in one view, compliance evidence for the first
  SOC 2 conversation, triage that keeps the noise survivable.
- **Enterprises** — SSO, role-based access, an audit trail, approved
  remediation, and gap reports a GRC lead hands to an auditor.

The promise underneath all four: **local-first and free at the core; the
controls a larger team needs are layers you turn on, never a paywall you hit.**

Concretely this means the README and site lead with the range, a "who it's for"
framing near the top, and the enterprise layers (SSO, approved remediation)
presented as opt-in capabilities rather than a separate tier.

---

## Sequencing

1. **SSO (OIDC)** — highest enterprise unlock, self-contained, evolves the auth
   package cleanly (the `AuthEpoch` generalization is worth doing regardless).
2. **Approved cloud remediation** — depends on nothing above, but is the most
   sensitive design; build the curated catalog + approval + audit before any
   execution path exists.
3. **Brand** — the reposition ships continuously; the concrete README change
   lands now, the rest follows the features it describes.
