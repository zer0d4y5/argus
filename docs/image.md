# Container image scanning

`argus image <ref>` scans a container image for vulnerable OS and application
packages with trivy, and maps the results into the same findings model as
every other surface (category `SCA`): banded severity, risk scoring,
compliance mapping, and the same severity gate.

```bash
argus image nginx:1.27-alpine
argus image registry.example.com/team/app:v1.2.3 --fail-severity high
argus image app@sha256:abc123... --format sarif -o image.sarif
```

## A distinct surface from the filesystem SCA pass

`argus scan` (the filesystem SCA pass) sees the dependencies your **source**
declares: `go.mod`, `package-lock.json`, `requirements.txt`, and so on.
`argus image` sees what is actually **baked into the image**: the base
image's OS packages (apk/apt/rpm), plus the application dependencies present
in the built layers. The two overlap but are not the same. A CVE in a base
image's `libexpat` never appears in your lockfile; a dev dependency in your
lockfile may be absent from the production image. Run both.

## Per-image identity

Each finding carries the image reference you passed as its location
(`location.resource`), so the same vulnerable package in two different images
is two distinct findings with distinct fingerprints, and a combined report
names which image each came from. That makes `argus image` usable across a
fleet of images without collapsing findings.

## Credentials are referenced, never collected

For a private registry, trivy uses your ambient container credentials (the
same `docker login` / registry config your environment already has). Argus
passes nothing: no tokens on the command line, none in config, none logged.
This is the same referenced-credential discipline as the cloud posture scan.

## Gate, save, and dispositions

`argus image` behaves like `argus scan`, `argus cloud-scan`, and `argus dast`
for everything after the scan: `--fail-severity` gates on the banded
severity, `--save` records the run under `.appsec/image/<ref>/runs` for the
console, and accepted-risk / false-positive dispositions suppress a finding
from the gate (but not the report) unless `--strict-gate` is set.

Install trivy from [its releases](https://github.com/aquasecurity/trivy) or
your package manager; `argus image` reports honestly if it is not on `PATH`.
The first run downloads trivy's vulnerability database; subsequent runs reuse
the local cache.

## From the console

Register an **Image** target on the Admin tab with a container reference, then
launch it from the Operate tab like any other target. The run lands in the
target's history with each finding tagged by the image reference, ready for
triage, disposition, and ticketing.
