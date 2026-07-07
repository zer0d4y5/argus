// Skip accounting: what a scan did NOT look at. Honesty is part of output
// quality — "no findings" in a tree full of unscanned binaries or Rust code
// is not the same claim as "no findings" in a fully-analyzable tree. The
// accounting is computed at save time, stored in the run document (schema
// 2.0.0), and surfaced in the console run detail.
package coverage

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/leaky-hub/argus/internal/scanner"
)

// OversizeLimitBytes is the accounting threshold for "large file": above it,
// static analyzers time out or skip internally, so we call the file
// effectively unscanned rather than pretending otherwise.
const OversizeLimitBytes = 5 * 1024 * 1024

// sampleCap bounds each sample path list stored in a run document.
const sampleCap = 10

// Accounting summarizes, for one scan root, what was analyzable and what was
// skipped — by bucket, with sample paths for the console. Buckets are
// mutually exclusive per file; counts are files.
type Accounting struct {
	FilesTotal int   `json:"filesTotal"` // regular files walked (excluding .git/.appsec)
	BytesTotal int64 `json:"bytesTotal"`

	// SastCovered: source files in languages the semgrep profiles claim
	// (docs/coverage.md). IacConfig: IaC/manifest/config files the IaC and
	// SCA scanners parse. SecretsOnly: other text — the secret scanner reads
	// it, no static analyzer does.
	SastCovered int `json:"sastCovered"`
	IacConfig   int `json:"iacConfig"`
	SecretsOnly int `json:"secretsOnly"`

	// The honest skip buckets.
	UnsupportedSource int `json:"unsupportedSource"` // recognized code, unclaimed language: secrets-only coverage
	Binary            int `json:"binary"`            // NUL-sniffed: no scanner analyzes content
	Oversize          int `json:"oversize"`          // > OversizeLimitBytes: effectively unscanned
	Unreadable        int `json:"unreadable"`        // stat/open failures during the walk

	OversizeLimitBytes int64 `json:"oversizeLimitBytes"`

	// Git facts about the target (not claims about scanner behavior): a git
	// repository is history-eligible for the secret scanner; a shallow clone
	// has a single commit of history.
	GitRepo    bool `json:"gitRepo"`
	GitShallow bool `json:"gitShallow"`

	// Sample paths per skip bucket, capped at sampleCap, sorted.
	UnsupportedSample []string `json:"unsupportedSample,omitempty"`
	BinarySample      []string `json:"binarySample,omitempty"`
	OversizeSample    []string `json:"oversizeSample,omitempty"`
}

// sastExtensions: the languages the semgrep profiles claim (one pack per
// language in `standard`; see internal/scanner/profiles.go and
// docs/coverage.md). Extending profile coverage means extending this table.
var sastExtensions = map[string]bool{
	".py": true, ".pyi": true,
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true,
	".go":   true,
	".java": true,
	".cs":   true,
	".rb":   true,
	".php":  true,
	".kt":   true, ".kts": true,
	// Cloud-posture session: languages that landed with proven plants.
	".rs":    true,              // rust (p/rust)
	".scala": true, ".sc": true, // scala (p/scala)
	".c": true, ".h": true, //nolint // c (p/security-audit's C rules)
	// Swift (.swift) and Elixir (.ex/.exs) did NOT land — their packs caught
	// nothing plantable — so they stay in unsupportedSourceExtensions below.
}

// iacConfigExtensions / iacConfigNames: files the IaC scanners
// (trivy-config, checkov) and the SCA scanner (trivy fs) actually parse —
// plus lockfiles and dependency manifests.
var iacConfigExtensions = map[string]bool{
	".tf": true, ".tfvars": true,
	".yaml": true, ".yml": true, ".json": true,
	".toml": true, ".lock": true, ".gradle": true,
	".ini": true, ".cfg": true, ".conf": true, ".properties": true, ".env": true,
	".xml": true, // pom.xml etc.
}

var iacConfigNames = map[string]bool{
	"dockerfile": true, "containerfile": true, "makefile": true,
	"gemfile": true, "rakefile": true, "procfile": true,
	"go.mod": true, "go.sum": true, "requirements.txt": true,
}

// unsupportedSourceExtensions: recognizably source code in languages no
// profile pack analyzes. These get secrets-only coverage and the accounting
// says so — this is the "we did NOT statically analyze this" list.
var unsupportedSourceExtensions = map[string]bool{
	// .c/.h/.rs/.scala/.sc moved to sastExtensions this session (landed
	// languages). .cpp/.cc/etc stay unsupported: C++ is a different rule set
	// than the C rules that landed.
	".cpp": true, ".cc": true, ".cxx": true, ".hpp": true,
	".swift": true, // did not land
	".m":     true, ".mm": true, ".pl": true, ".pm": true, ".lua": true,
	".dart": true, ".ex": true, ".exs": true, ".erl": true, ".hrl": true, // elixir/erlang did not land
	".clj": true, ".cljs": true, ".hs": true, ".ml": true, ".mli": true,
	".fs": true, ".fsx": true, ".r": true, ".jl": true, ".nim": true,
	".zig": true, ".sol": true, ".groovy": true, ".sh": true, ".bash": true,
	".zsh": true, ".ps1": true, ".bat": true, ".cmd": true, ".sql": true,
	".asm": true, ".s": true, ".vb": true, ".pas": true, ".d": true,
}

// skipDirs are never walked: VCS internals and our own run store.
var skipDirs = map[string]bool{".git": true, ".appsec": true}

// Account walks root and buckets every regular file. It never reads more
// than a sniff (512 bytes) per file, never follows symlinks, and never
// fails: unreadable entries are counted, not fatal. A file target accounts
// just that file.
func Account(root string) Accounting {
	acc := Accounting{OversizeLimitBytes: OversizeLimitBytes}

	fi, err := os.Stat(root)
	if err != nil {
		acc.Unreadable++
		return acc
	}
	if !fi.IsDir() {
		acc.accountFile(root, filepath.Base(root), fi.Size())
		return acc
	}

	acc.GitRepo = scanner.GitHistoryEligible(root)
	acc.GitShallow = scanner.GitShallow(root)

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			acc.Unreadable++
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks, sockets, devices: not scan input
		}
		info, err := d.Info()
		if err != nil {
			acc.Unreadable++
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		acc.accountFile(path, filepath.ToSlash(rel), info.Size())
		return nil
	})

	sort.Strings(acc.UnsupportedSample)
	sort.Strings(acc.BinarySample)
	sort.Strings(acc.OversizeSample)
	return acc
}

func (a *Accounting) accountFile(path, rel string, size int64) {
	a.FilesTotal++
	a.BytesTotal += size

	if size > OversizeLimitBytes {
		a.Oversize++
		addSample(&a.OversizeSample, rel)
		return
	}

	name := strings.ToLower(filepath.Base(rel))
	ext := strings.ToLower(filepath.Ext(rel))
	switch {
	case sastExtensions[ext]:
		a.SastCovered++
	case iacConfigExtensions[ext] || iacConfigNames[name] || strings.HasPrefix(name, "dockerfile"):
		a.IacConfig++
	case unsupportedSourceExtensions[ext]:
		a.UnsupportedSource++
		addSample(&a.UnsupportedSample, rel)
	case isBinary(path):
		a.Binary++
		addSample(&a.BinarySample, rel)
	default:
		a.SecretsOnly++
	}
}

func addSample(list *[]string, rel string) {
	if len(*list) < sampleCap {
		*list = append(*list, rel)
	}
}

// isBinary sniffs the first 512 bytes for a NUL — the same cheap heuristic
// git uses. Unreadable files count as binary here: either way no scanner
// analyzed their content.
func isBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return true
	}
	return bytes.IndexByte(buf[:n], 0) >= 0
}
