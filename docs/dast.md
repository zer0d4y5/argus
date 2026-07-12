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

> Active fuzzing sends real payloads and will exercise state-changing
> endpoints. Run it against targets you own and treat as disposable (a test or
> staging instance), never production.

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
