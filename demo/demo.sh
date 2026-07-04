#!/usr/bin/env bash
#
# demo.sh — the 10-minute appsec story, end to end.
#
#   breadth → local AI triage kills the false positives → open the console →
#   walk the three persona views.
#
# Self-contained: builds the binary, seeds a nine-language demo repo with a
# realistic true-positive + false-positive mix, records two runs (so the trend
# and new-vs-resolved delta are real), and opens the console. Triage needs a
# local Ollama; without it the demo still runs, just without verdicts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/appsec"
DEMO_DIR="${DEMO_DIR:-/tmp/appsec-demo}"
ADDR="${ADDR:-127.0.0.1:8080}"

say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
note() { printf "    \033[2m%s\033[0m\n" "$*"; }
pause(){ if [ -t 0 ]; then read -rp $'\n    (enter to continue) '; fi; }

# --- 0. build -----------------------------------------------------------------
say "Building the single binary (embeds the web console — no Node needed)"
( cd "$REPO_ROOT" && go build -o appsec ./cmd/appsec )
note "$($BIN --version)"

# --- 1. seed a nine-language demo repo ---------------------------------------
say "Seeding a nine-language demo repo with real + false-positive-inducing code"
rm -rf "$DEMO_DIR"
cp -r "$REPO_ROOT/testdata/polyglot" "$DEMO_DIR"
rm -f "$DEMO_DIR/labels.json"
mkdir -p "$DEMO_DIR/payments"
# A textbook false positive: MD5 used purely as a cache key, not for security.
cat > "$DEMO_DIR/payments/cache.py" <<'PY'
# Cache-key helper. MD5 here is a fast content hash for cache bucketing, never a
# password or signature. A scanner flags it on sight; triage should reject it.
import hashlib
def cache_key(url: str, params: str) -> str:
    return "cache:" + hashlib.md5(f"{url}?{params}".encode()).hexdigest()
PY
cp "$REPO_ROOT/testdata/triage-eval/vuln_app.py" "$DEMO_DIR/payments/" 2>/dev/null || true
note "Languages: python js ts go java c# ruby php kotlin (+ a benign MD5 cache helper)"
pause

# --- 2. baseline run: breadth -------------------------------------------------
say "Run 1 — baseline scan with the default 'standard' multi-language profile"
note "Watch the finding count: breadth across every language, on purpose."
( cd "$DEMO_DIR" && "$BIN" scan . --profile standard --save ) || true
pause

# --- 3. remediate, then triage: the false-positive kill -----------------------
say "A sprint later: two services are fixed and shipped"
rm -rf "$DEMO_DIR/kotlin" "$DEMO_DIR/csharp"
note "Removed the kotlin and csharp fixtures — those findings should resolve."

say "Run 2 — same scan, now with LOCAL AI triage (nothing leaves this machine)"
note "Triage gives every finding a verdict + rationale and kills the MD5 false positives."
( cd "$DEMO_DIR" && "$BIN" scan . --profile standard --triage --save ) || true
pause

# --- 4. coverage receipt ------------------------------------------------------
say "Coverage is proven, not claimed — the generated matrix"
note "See docs/coverage.md for the full language × weakness grid + profiles."
sed -n '/## Language/,/## Canaries/p' "$REPO_ROOT/docs/coverage.md" 2>/dev/null | head -n 16 || true
pause

# --- 5. the console -----------------------------------------------------------
say "Open the console — three persona views over the saved runs"
note "Overview (GRC): posture + trend  |  Findings (AppSec): explorer + rationale  |  Runs (SecOps): deltas"
note "Local-first, no auth, binds ${ADDR%%:*}. Finding data is rendered inert (escaped, strict CSP)."
URL="http://$ADDR"
note "Opening $URL  (Ctrl-C to stop the server)"
( command -v open >/dev/null && open "$URL" ) 2>/dev/null || \
  ( command -v xdg-open >/dev/null && xdg-open "$URL" ) 2>/dev/null || \
  note "Navigate to $URL manually."
exec "$BIN" serve --dir "$DEMO_DIR" --addr "$ADDR"
