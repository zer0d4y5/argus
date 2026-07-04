# appsec — build, UI, and coverage targets.
#
# `make build` produces the single self-contained binary. The committed UI
# bundle (ui/dist) is embedded, so `go build` alone always works; `make ui`
# rebuilds that bundle from the React sources.

# Node 22 LTS is keg-only on this machine; prefer it for frontend tooling.
NODE_BIN := /opt/homebrew/opt/node@22/bin
PATH := $(NODE_BIN):$(PATH)

.PHONY: build ui test coverage demo clean

build: ## Build the appsec binary (embeds the committed UI bundle)
	go build -o appsec ./cmd/appsec

ui: ## Rebuild the React console into ui/dist (requires Node 22)
	cd ui && npm install --no-audit --no-fund && npm run build

test: ## Run the Go test suite (network-dependent scans auto-skip in -short)
	go test ./...

coverage: build ## Regenerate docs/coverage.md from a live scan of the polyglot fixtures
	APPSEC_UPDATE_COVERAGE=1 go test ./internal/coverage -run TestPolyglotCoverage -v

demo: build ## Run the end-to-end investor demo
	./demo/demo.sh

clean:
	rm -f appsec coverage.out
