# Engagements: the authorization spine of dynamic testing

Argus's dynamic testing is offensive: it sends payloads to a running target. That
is only legitimate inside an explicit authorization. The **engagement** is how
Argus makes that authorization a first-class, enforced object rather than a
promise. No active DAST module sends a single request without one.

An engagement declares:

- **Scope**: the in-scope hosts, CIDRs, and URL-prefixes, plus out-of-scope
  exclusions. Every request is checked against it.
- **Authorization reference**: the CVP ticket or rules-of-engagement id that
  makes the testing lawful. Required.
- **Testing window**: an optional start/end outside which the gate refuses.
- **Intensity ceiling**: a global request rate, a per-host concurrency cap, and a
  total request budget. The "considerate guest" setting, dialed by the operator.
- **Destructive latch**: off by default. A destructive action needs this AND a
  per-run confirmation, and the platform hard limits refuse regardless.

Engagements live under `.appsec/engagements` in the working directory (and, for a
console-launched scan, under the served repo's `.appsec/engagements`).

## The gate: `InScope`

Every active module routes through one predicate, `engagement.InScope(url)`. It
returns true only when the URL is affirmatively in scope AND not excluded:

- Out-of-scope entries always win over in-scope ones.
- An unparseable URL, a host-less URL, or a non-http(s) scheme is refused.
- A URL matching nothing in scope is refused.

Scope entries may be a bare host (`staging.acme.com`, any port), a `host:port`, a
CIDR (`10.0.0.0/24`, matched only against IP-literal targets), a URL-prefix
(`https://acme.com/app/`, segment-aware), or a `*.domain` subdomain wildcard.

This is the generalization of the crawler's existing logout/login self-preservation
guard: one predicate, consulted at one choke point, deciding whether a packet may
leave. A discovered link or a redirect that leaves scope is dropped and recorded.

## The governor: two enforcement planes

The intensity ceiling and the gate are enforced by a **Governor** with two planes,
one for each kind of module:

- **In-process HTTP** (the crawler, the authentication flow, the native
  command-injection detector) runs through a governed `http.Client`. Its
  transport checks scope, waits on the rate limiter, holds a per-host concurrency
  slot, spends one unit of request budget, and audits, on **every request**. An
  out-of-scope or over-budget request never reaches the network.
- **Subprocess tools** (nuclei, sqlmap, dalfox) send their HTTP out of our
  process, so they are gated at **dispatch**: every endpoint URL is scope- and
  budget-checked before the tool is handed it, out-of-scope endpoints are dropped
  and audited, and the tool's own rate/concurrency flags are set from the ceiling
  (nuclei `-rate-limit`, dalfox `--workers`).

The metering is honest about this asymmetry: in-process requests are counted
individually; subprocess dispatch is counted per endpoint, because the tool's
per-request traffic is not observable from Argus.

## The audit trail: tamper-evident

Each engagement has an append-only audit log at
`.appsec/engagements/<id>/audit.jsonl`. It is **hash-chained**: each entry carries
`prevHash` and `hash = SHA-256(prevHash || canonical(entry))`, so any edit,
reordering, or truncation of a prior line breaks the chain. `argus engagement
verify-audit` walks the chain and reports the first break.

The trail records the permitted requests, the refusals (out-of-scope, budget
exhausted, window closed, destructive blocked), the authentication result, and
tool dispatches. It never stores a credential value, a session token, or a
response body: only request metadata (method, URL) and the authenticated
username, mirroring the finding-metadata discipline used elsewhere in Argus. It is
the operator's evidence that testing stayed in bounds, so it protects the operator
as much as the target.

## Non-destructive by default; the double interlock

Confirmation over exploitation is the default posture: Argus proves a
vulnerability exists, it does not cause harm. Anything that writes, deletes,
persists, or degrades service is off unless the operator sets **both**:

1. the engagement's destructive latch (`--allow-destructive` at create time), and
2. a per-run confirmation (`argus dast ... --i-have-authorization`).

Even with both set, a set of action classes is refused unconditionally: denial of
service and resource exhaustion, data destruction, persistence and implants, and
bulk exfiltration. These keep Argus a sanctioned testing tool. No current engine
performs a destructive action; the interlock is the gate a future one must pass.

## CLI

```
# Create and activate an engagement
argus engagement create --name "Acme staging" \
  --scope staging.acme.com --scope '*.staging.acme.com' \
  --exclude admin.staging.acme.com \
  --auth-ref CVP-2026-0412 --contact you@acme.com \
  --rate 8 --concurrency 3 --budget 15000

argus engagement list                 # the active one is marked
argus engagement show [id]            # scope, window, intensity (default: active)
argus engagement activate <id>        # switch the active engagement
argus engagement verify-audit [id]    # confirm the audit chain is intact
```

A DAST scan runs under the active engagement by default, or a named one with
`--engagement <id>`:

```
argus dast https://staging.acme.com --dast --crawl
```

Without an engagement, an active scan refuses and says why. The console resolves
the served repo's active engagement the same way, and fails a DAST job closed if
none is set.
