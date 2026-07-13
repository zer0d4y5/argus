# DAST (dynamic scanning)

`argus dast <url>` scans a **running** web target with
[nuclei](https://github.com/projectdiscovery/nuclei) and maps the results
into the same findings model as code, IaC, and cloud scans: category `DAST`,
banded severity, risk scoring, compliance mapping, and the same severity
gate. It is the running-app view that SAST cannot provide: misconfigured
headers, exposed panels, known-CVE fingerprints, and template-detectable
weaknesses on the live surface.

```bash
argus dast https://staging.example.com
argus dast https://staging.example.com --tags misconfig,exposure --severity medium,high,critical
argus dast https://staging.example.com --templates cves/ --rate-limit 50 --fail-severity high
```

Only scan targets you are authorized to test. That authorization is enforced,
not assumed: `argus dast` runs under an **[engagement](engagement.md)** that
declares the in-scope hosts, the authorization reference, an intensity ceiling,
and a tamper-evident audit trail. Without an active engagement, an active scan
refuses and says why. Create one first:

```bash
argus engagement create --name "Staging" --scope staging.example.com --auth-ref CVP-1234
```

## What a finding looks like

Each nuclei match becomes one finding. The identity is the template id plus
the nuclei matcher name when present, at the matched URL. That matters for
multi-matcher templates: `http-missing-security-headers` fires once per
missing header, and each becomes a distinct finding
(`http-missing-security-headers:content-security-policy`,
`...:x-frame-options`, and so on) rather than collapsing into one. The
`location.url` is the matched URL, so two hits of one template on different
paths are distinct findings across runs (stable fingerprints).

Severity is nuclei's own template rating, banded like every other tool:
`critical/high/medium/low` verbatim, and nuclei's `info` tier (tech-detect,
exposure surface) stays honest `info`, never inflated to a gate-tripping
medium.

## Proof of concept and bounded confirmation

A confirmed dynamic finding carries a **proof of concept**: the raw HTTP
request, a copy-paste `curl`, the observed proof, and a plain-English reason the
finding is real. It is built from what the engine already saw and sends no extra
traffic. The `curl` renders the session cookie as a `$ARGUS_SESSION` placeholder,
so a shared PoC never carries a live credential.

Add `--confirm-impact` to go one step further and **confirm impact** with the
minimum identifying probe: a database banner and current user for SQL injection,
one benign `id` for command injection. It proves the finding's severity and
takes nothing more, and it runs only behind its own double interlock (see
[Engagements](engagement.md#bounded-impact-confirmation-a-second-separate-interlock)):
the engagement's `--allow-confirmation` latch and the per-run `--confirm-impact`.
It never dumps data, opens a shell, or changes target state.

```bash
# Reproduction PoC is automatic; add --confirm-impact for bounded confirmation.
argus dast http://target/ --auth-auto --crawl --sqlmap --cmdi --confirm-impact
```

## Request/response evidence

By default a DAST finding is metadata only (see below). Add `--evidence`
(CLI) or enable it per target in the console to also capture the **request and
response** that produced each finding, so an engineer can validate it at a
glance: the fuzzed request line and the response that matched (a SQL error, a
reflected payload, an included file).

```bash
argus dast http://target/ --auth-auto --crawl --dast --evidence
```

Capture is opt-in because it relaxes the metadata-only default: the request's
auth headers (`Cookie`, `Authorization`, and the like) are **redacted** and the
content is size-bounded, but a captured response body can still hold data from
the scanned app. Enable it against targets you own; leave it off when that is a
concern.

## Findings never carry the response (by default)

A DAST finding is metadata about a weakness, not a copy of the target's
traffic. nuclei's JSONL includes the full request, the full response body,
a reproduction `curl` command, and any values extracted from the live
response, all of which can hold session tokens, PII, or secrets from the
scanned app. The adapter **drops every one of them**: the stored finding
carries the template identity, the matched URL, CWE/CVE classification, and
tags, and nothing else. This mirrors the discipline that keeps `SECRET`
findings metadata-only.

nuclei also runs with its OOB interaction server and its update check
disabled, so a scan performs no network callouts beyond the requests to the
target itself.

## Active fuzzing

By default nuclei runs its known-issue templates (CVEs, misconfigurations,
exposures, tech detection): it confirms things that are *present*, but it does
not probe parameters for injection. `--dast` turns on nuclei's active fuzzing
templates, which mutate request parameters and diff the responses to surface
SQL injection, reflected XSS, and similar input-driven weaknesses on the live
surface.

```bash
argus dast "https://staging.example.com/item?id=1" --dast --fail-severity high
```

Fuzzing needs parameterized endpoints to work on. Either point `--dast` at a URL
that already carries parameters, or add `--crawl` (below) to discover them
automatically.

## Automatic discovery (crawl)

`--crawl` walks the target first, discovers every endpoint and form, and fuzzes
all of them: point it at a base URL and it finds injection across the whole app
instead of only the one page you named.

```bash
argus dast http://target/ --auth-auto --crawl --dast --fail-severity high
```

The crawl is a bounded, same-host, breadth-first walk (default depth 3, 150
pages; tune with `--crawl-depth` / `--crawl-pages`). It runs with the
authenticated session, so it reaches pages behind the login. It reads HTML
only, synthesizes fuzzable URLs from GET forms, and deliberately never follows
logout/login pages (which would drop the session) and never synthesizes a
password-change form (which would lock the scan out of its own account).

Combined, `--auth-auto --crawl --dast` is the full loop: log in, map the app,
and actively fuzz every discovered parameter for SQL injection, XSS, file
inclusion (LFI/RFI), and the rest of nuclei's fuzzing coverage.

## Deeper engines: sqlmap and dalfox

nuclei's URL fuzzing covers GET parameters. Two dedicated engines go further,
including POST forms and detection classes fuzzing cannot see. They run over the
same crawl-discovered endpoints and merge into the same findings.

- `--sqlmap` runs **sqlmap** to confirm SQL injection, including boolean- and
  time-based **blind** injection that error-signature fuzzing misses, on GET and
  POST forms. It is run non-interactively (`--batch`) and is never given
  data-exfiltration flags: it only answers "is this parameter injectable?".
- `--dalfox` runs **dalfox** to actively test for XSS (reflected, stored, and
  DOM) on GET and POST forms, confirming by DOM execution.
- `--cmdi` runs Argus's built-in **OS command-injection** detector on GET and
  POST parameters. It confirms injection with benign, self-verifying probes
  only: an arithmetic expression whose product (absent from the payload) must
  appear in the response, plus a differential-timing check. It never runs an
  attacker-controlled command or writes to the target.

```bash
argus dast http://target/ --auth-auto --crawl --dast --sqlmap --dalfox --cmdi
```

These engines are opt-in and slower than nuclei (sqlmap especially tests each
endpoint thoroughly), so enable them when you want depth. File upload is the
remaining class no engine covers yet.

## Server-side request forgery (`--ssrf`)

`--ssrf` tests each parameter for server-side request forgery by injecting a
callback URL that points at a listener Argus runs itself on `127.0.0.1`. There
is no third-party out-of-band service: the only callback endpoint is local, so
the network-free discipline holds. A parameter is flagged when the target's
server connects back to the listener (blind, out-of-band), when the response
reflects the listener's per-probe marker (in-band), or when it can reach the
cloud instance metadata service at `169.254.169.254` (the canonical escalation).
The metadata probe confirms reachability by a signature in the response and
never requests a credential path. Each finding carries the request and, where
applicable, the response, plus the callback source as proof.

```bash
argus dast https://target/ --auth-auto --crawl --ssrf
```

## Server-side template injection (`--ssti`)

`--ssti` tests each parameter for server-side template injection using the same
arithmetic-marker discipline as command injection: it injects a template
expression that multiplies two random numbers, per template engine (Jinja2/Twig,
Freemarker/Velocity, Thymeleaf/Spring, ERB, Smarty), and confirms only when the
response contains the product, which the payload never contains. A template that
merely echoes the payload cannot produce a false positive. Each finding names
the engine family it matched and is CWE-1336.

```bash
argus dast https://target/ --auth-auto --crawl --ssti
```

## Unrestricted file upload (`--file-upload`)

`--file-upload` tests the upload forms the crawl discovers. It uploads a benign
marker file whose type should be rejected (a `.php` name sent with an image
content-type, the classic content-type bypass), refreshing any per-request CSRF
token first, then tries to fetch the file back from the path the response
reveals or from common upload directories. A file that is both accepted and
retrievable proves the type restriction can be bypassed. The marker file
contains no executable code, so this confirms the weakness (CWE-434) without
planting a web shell. Needs `--crawl` to find the forms.

```bash
argus dast https://target/ --auth-auto --crawl --file-upload
```

## IDOR / BOLA (`--idor`)

`--idor` tests for insecure direct object references by replaying one identity's
object references as a second identity. It needs a second set of credentials
(referenced by env-var name, never stored) and `--crawl` to find the endpoints.
For each parameter that looks like an object reference, identity A fetches its
own object, identity B replays A's id, and B also fetches a different id as a
control. Only when B receives the same object A did (broken ownership check) and
a different id returns different content (so the endpoint actually varies by id,
not a public page) is a finding raised. The cross-read body is never stored: the
proof records that access succeeded and how many bytes matched, not the other
user's data. Findings are CWE-639.

```bash
APP_USER=alice APP_PASS=... APP_USER2=bob APP_PASS2=... \
  argus dast https://target/ --crawl --idor \
  --auth-user-env APP_USER --auth-pass-env APP_PASS \
  --auth2-user-env APP_USER2 --auth2-pass-env APP_PASS2
```

## Client-side reverse-engineering (`--js-recon`)

Link-following only finds the surface the app links to. Most of a modern app's
real attack surface lives in its JavaScript: `fetch`/XHR routes, API paths,
feature flags, and admin screens that are never linked from a page. `--js-recon`
recovers it.

```bash
argus dast http://target/ --auth-auto --js-recon --dast --sqlmap --dalfox
```

It fetches the target's HTML, pulls the referenced same-host script bundles (and
their sourcemaps, whose original sources reveal more than the minified code), and
extracts:

- **Endpoints and API routes**, which are scope-filtered and merged into the fuzz
  set, so the active engines test surface the crawler never saw. This alone
  typically expands discovered surface substantially.
- **Exposed secrets**: high-confidence provider credentials (AWS, Google, Slack,
  Stripe, GitHub, JWTs) hardcoded into bundles served to the browser. A finding
  carries a redacted preview only, never the raw value.
- **Sensitive surfaces** (admin, debug, actuator, GraphQL, API docs) referenced in
  the client code, reported for the operator to confirm they enforce authorization.

Recon fetches through the engagement's governed client, so it is scope-gated,
budgeted, and audited exactly like the crawl: a third-party CDN bundle is off-scope
and is never fetched.

## Stack fingerprinting (`--fingerprint`)

Understand the target before attacking it. `--fingerprint` identifies the
technology stack from what the target itself discloses, in a single governed
request.

```bash
argus dast http://target/ --fingerprint
```

It reads the response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`,
`X-Generator`), the session-cookie names (`PHPSESSID`, `JSESSIONID`,
`laravel_session`, ...), the HTML `generator` meta tag, and versioned library
banners, and produces:

- **Version-disclosure findings** for each component whose exact version is
  exposed. Leaking precise versions to anonymous clients lets an attacker match
  your stack to known vulnerabilities, so it is reported (informational) with the
  disclosing source.
- **Known-exploited correlation**: for CMS families that CISA's Known Exploited
  Vulnerabilities catalog tracks (WordPress, Drupal, Joomla), a finding noting how
  many KEV-listed vulnerabilities affect that product, with example CVEs. The KEV
  catalog carries no version ranges, so this is a product-level flag to verify,
  never a claim that your version is vulnerable, and it never inflates its own
  score by asserting a CVE it cannot confirm.

The identified stack is also printed to the scan log, and it is the recon profile
the reporting and (future) attack-path reasoning build on.

> Active fuzzing sends real payloads and will exercise state-changing
> endpoints. Run it against targets you own and treat as disposable (a test or
> staging instance), never production.

## API schema reconstruction (`--api-recon`)

Link-following finds the pages a user clicks; an API's real surface usually
lives in the schema the app serves. `--api-recon` probes well-known locations
for an OpenAPI/Swagger document (`/openapi.json`, `/swagger.json`,
`/v3/api-docs`, and similar) and for GraphQL introspection (`/graphql`), parses
what it finds into fuzzable operations, and merges them into the scan so the
active engines test the whole API, not just the crawled pages.

```bash
argus dast https://api.example.com/ --api-recon --sqlmap --cmdi
```

It reports the exposure itself (an exposed schema document, and GraphQL
introspection left enabled), both as information disclosure. Recovered
operations pass through the same guards as crawled ones: an operation on an
auth path (login, logout) or one whose parameters look like a credential change
is never fuzzed, path templates are filled with a benign value, and DELETE
operations are left alone. Every fetch goes through the engagement's governed
client, so it is scope-gated, budgeted, and audited.

## Authenticated scanning

Most of an app lives behind a login, and an unauthenticated scan only ever
sees the front door. `argus dast` can log in first, then scan with that
session:

```bash
# Detect the login form and try a short list of well-known default credentials:
argus dast http://target/ --auth-auto --dast

# Supply your own credentials by ENV-VAR NAME (never as a literal flag):
APP_USER=admin APP_PASS='s3cret' \
  argus dast http://target/ --auth-user-env APP_USER --auth-pass-env APP_PASS --dast

# Point at an explicit login page if it is not the scan URL:
argus dast http://target/app/ --auth-auto --login-url http://target/login
```

How it works: Argus fetches the login page, finds the form, carries any CSRF
token, submits the credentials, and verifies the resulting session is
authenticated before scanning. The session is then sent on every scan request.

Credential handling follows the same rule as every other secret in Argus:
**credentials are referenced, never stored.** Your username and password are
read from the environment variables you name (`--auth-user-env` /
`--auth-pass-env`), never taken as literal flag values (which would land in
shell history and the process table). The `--auth-auto` default-credential
list is public vendor-default knowledge, not secrets; it is a bounded
first-guess convenience for authorized testing of your own target, not a
brute-forcer. The obtained session cookie is held in memory for the one scan
and is never written to a finding, a saved run, a log, or a progress line
(you will see `authenticated as "admin"`, never the cookie).

### Auth-flow modeling

While authenticating, Argus models the target's auth machinery from what it
observes: the mechanism, whether the login form carries a CSRF token, and the
session cookies the login sets, with their security flags. The cookie flags
drive deterministic hardening findings: a session cookie without `HttpOnly`
(readable by JavaScript, so exposed to XSS theft), without `Secure` over HTTPS
(sendable in cleartext), or without `SameSite` (sent cross-site, widening CSRF
exposure). These come for free on any authenticated scan and report on the
cookie's name and flags only, never its value.

## Scope and tuning

- `--templates`: comma-separated nuclei templates (files, directories, or
  ids). Default is nuclei's installed template set. Point it at `cves/` or a
  curated directory to bound scope and time.
- `--tags`: nuclei tag filter, e.g. `misconfig,exposure,cve`.
- `--severity`: nuclei severity filter, e.g. `medium,high,critical`.
- `--rate-limit`: max requests per second (be a considerate guest).
- `--timeout`: whole-scan timeout in seconds.
- `--dast`: enable active fuzzing (see above).
- `--auth-auto` / `--auth-user-env` / `--auth-pass-env` / `--login-url`:
  authenticate before scanning (see above).

## Gate, save, and dispositions

`argus dast` behaves like `argus scan` and `argus cloud-scan` for everything
after the scan: `--fail-severity` gates on the banded severity, `--save`
records the run under `.appsec/dast/<target>/runs` for the console, and
accepted-risk / false-positive dispositions suppress a finding from the gate
(but not the report) unless `--strict-gate` is set. Install nuclei from
[its releases](https://github.com/projectdiscovery/nuclei/releases) or your
package manager; `argus dast` reports honestly if it is not on `PATH`.

## From the console

The console can run DAST scans too: register a **DAST (URL)** target on the
Admin tab, then launch it from the Operate tab like any other target. The run
lands in the target's history with the matched URLs, and findings can be
triaged, dispositioned, and ticketed the same as code findings.
