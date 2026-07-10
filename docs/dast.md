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

Only scan targets you are authorized to test.

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

## Findings never carry the response

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

## Scope and tuning

- `--templates`: comma-separated nuclei templates (files, directories, or
  ids). Default is nuclei's installed template set. Point it at `cves/` or a
  curated directory to bound scope and time.
- `--tags`: nuclei tag filter, e.g. `misconfig,exposure,cve`.
- `--severity`: nuclei severity filter, e.g. `medium,high,critical`.
- `--rate-limit`: max requests per second (be a considerate guest).
- `--timeout`: whole-scan timeout in seconds.

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
