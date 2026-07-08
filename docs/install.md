# Install

Argus is a single Go binary with the web console embedded, so there is nothing
to host and no account to create. Install the CLI, then add whichever scanners
you want on your `PATH`. Missing scanners are skipped with a note, so you can
start with one and grow.

Pick your platform below; the steps are the same shape everywhere, just with the
right package manager.

## 1. Prerequisites

You need **Go 1.22 or newer** to build the binary. `go build` alone works; the UI
bundle is committed, so you do not need Node to run Argus.

=== ":material-apple: macOS"

    ```bash
    brew install go            # or from https://go.dev/dl
    ```

=== ":material-linux: Linux"

    ```bash
    # Debian/Ubuntu; or use your distro's package, or https://go.dev/dl
    sudo apt-get update && sudo apt-get install -y golang-go git
    ```

=== ":material-microsoft-windows: Windows"

    ```powershell
    winget install GoLang.Go Git.Git    # or scoop install go git
    ```

    For the full scanner set, we recommend **WSL2** (semgrep, our SAST engine,
    does not support native Windows). Install it with `wsl --install`, then
    follow the **Linux** tab inside your WSL shell. The steps below cover a
    native Windows build for the scanners that do support it.

## 2. Scanners (optional, install what you want)

Each scanner Argus finds on `PATH` lights up a capability. None are required;
start with one.

| Tool | Covers |
| --- | --- |
| semgrep | SAST (code) |
| gitleaks | secrets |
| trivy | dependencies (SCA) and IaC misconfig |
| checkov | broader IaC |
| prowler | cloud posture (AWS/Azure/GCP) |

=== ":material-apple: macOS"

    ```bash
    brew install gitleaks trivy
    pipx install semgrep checkov prowler   # pipx keeps each tool isolated
    ```

=== ":material-linux: Linux"

    ```bash
    # trivy (official apt repo shown; see the trivy docs for rpm/others)
    sudo apt-get install -y wget gnupg
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
    sudo apt-get update && sudo apt-get install -y trivy

    # gitleaks (grab the latest release binary onto your PATH)
    #   https://github.com/gitleaks/gitleaks/releases

    # Python tools
    pipx install semgrep checkov prowler   # or: pip install --user semgrep checkov prowler
    ```

=== ":material-microsoft-windows: Windows"

    ```powershell
    scoop install gitleaks trivy           # or choco install gitleaks trivy
    pip install checkov prowler            # Python tools work on native Windows
    ```

    `semgrep` (SAST) is not supported on native Windows; run it under **WSL2**
    (follow the Linux tab there) if you want code scanning. Secrets, SCA, IaC,
    and cloud posture all work natively.

- **Ollama** (optional) enables local AI triage. Install from
  [ollama.com](https://ollama.com), then `ollama pull` a capable model.

## 3. Build and install Argus

=== ":material-apple: macOS / :material-linux: Linux"

    ```bash
    git clone https://github.com/zer0d4y5/argus.git
    cd argus
    ./scripts/setup.sh          # builds the binary and reports which scanners it found
    # or by hand:
    go build -o argus ./cmd/argus

    sudo mv argus /usr/local/bin/    # put it on your PATH
    argus --version
    ```

=== ":material-microsoft-windows: Windows"

    ```powershell
    git clone https://github.com/zer0d4y5/argus.git
    cd argus
    go build -o argus.exe ./cmd/argus

    # Put argus.exe somewhere on your PATH, e.g. a tools folder you control:
    mkdir $HOME\bin -Force; move argus.exe $HOME\bin\
    # then add $HOME\bin to PATH (once):
    setx PATH "$env:PATH;$HOME\bin"
    argus.exe --version
    ```

### Or with `go install`

If you have a Go toolchain and just want the CLI, this works on every platform:

```bash
go install github.com/zer0d4y5/argus/cmd/argus@latest
```

## 4. Verify it works

Run Argus against the deliberately vulnerable sample that ships with the repo.
You should see findings:

```bash
argus scan testdata/fixture
```

## A note on privacy

Argus is local-first by design. Scans run on your machine, triage runs against a
local model by default, and cloud credentials are referenced by name, never
collected or stored. Nothing is uploaded unless you explicitly configure a
non-local provider.

Next: [take it for a first scan](getting-started.md).
