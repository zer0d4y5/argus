# Install

Argus is a single Go binary with the web console embedded, so there is nothing
to host and no account to create. Install the CLI, then add whichever scanners
you want on your `PATH`. Missing scanners are skipped with a note, so you can
start with one and grow.

## Prerequisites

- **Go 1.22+** to build the binary. `go build` alone works; the UI bundle is
  committed, so you do not need Node to run Argus.
- **Scanners on `PATH`** (all optional, install what you need):

    | Tool | Covers | Install |
    | --- | --- | --- |
    | semgrep | SAST (code) | `pipx install semgrep` |
    | gitleaks | secrets | `brew install gitleaks` |
    | trivy | dependencies (SCA) and IaC misconfig | `brew install trivy` |
    | checkov | broader IaC | `pipx install checkov` |
    | prowler | cloud posture (AWS/Azure/GCP) | `pipx install prowler` |

- **Ollama** (optional) for local AI triage. Any capable local model works; the
  default is a small, fast one.

## Build from source

```bash
git clone https://github.com/leaky-hub/argus.git
cd argus

# One command builds the binary and reports which scanners it found:
./scripts/setup.sh

# Or by hand:
go build -o argus ./cmd/argus     # embeds the console; no Node needed to run
```

That produces an `argus` binary in the repo root. Move it onto your `PATH` if
you want it available everywhere:

```bash
sudo mv argus /usr/local/bin/     # or anywhere on your PATH
argus --version
```

## Go install

If you have a Go toolchain and just want the CLI:

```bash
go install github.com/leaky-hub/argus/cmd/argus@latest
```

## Verify it works

Run Argus against the deliberately vulnerable sample that ships with the repo.
You should see findings:

```bash
argus scan testdata/fixture
```

## A note on privacy

Argus is local-first by design. Scans run on your machine, triage runs against a
local model by default, and cloud credentials are referenced by name, never
collected or stored (see [Cloud posture](getting-started.md#cloud-posture)).
Nothing is uploaded unless you explicitly configure a non-local provider.

Next: [take it for a first scan](getting-started.md).
