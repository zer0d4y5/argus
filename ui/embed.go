// Package ui embeds the built web console (Vite output under dist/) so a plain
// `go build` produces a single self-contained binary — no separate asset step
// at runtime. The dist/ directory is committed; `make ui` rebuilds it from the
// React sources that live alongside this file.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// Dist returns the built console file system rooted at dist/ (so paths are
// "index.html", "assets/…"). It fails only if the embed is somehow empty, which
// is a build-time guarantee here.
func Dist() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
