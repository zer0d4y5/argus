package server

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// repoOutline summarizes a directory for the component-suggestion prompt: the
// directory tree to a shallow depth plus recognized manifest files, as short
// "dir:" / "file:" lines. It reads NO file contents — names only — and is
// bounded, so a pathological tree can't balloon a prompt or pin the request.
// The seam sanitizes and re-bounds every line before it reaches the model.

const (
	outlineMaxDepth   = 3
	outlineMaxEntries = 80
	outlineMaxWalk    = 50000
)

// outlineSkipDirs mirrors iacdetect's walk-skip set.
var outlineSkipDirs = map[string]bool{
	".git": true, ".appsec": true, "node_modules": true, "vendor": true,
	".terraform": true, "dist": true, "build": true, "__pycache__": true,
}

// outlineManifests are files whose NAME alone signals architecture.
var outlineManifests = map[string]bool{
	"go.mod": true, "package.json": true, "requirements.txt": true,
	"pyproject.toml": true, "pom.xml": true, "build.gradle": true,
	"cargo.toml": true, "gemfile": true, "composer.json": true,
	"dockerfile": true, "docker-compose.yml": true, "docker-compose.yaml": true,
	"compose.yml": true, "compose.yaml": true, "chart.yaml": true,
	"values.yaml": true, "serverless.yml": true, "pulumi.yaml": true,
	"main.tf": true, "template.yaml": true, "template.json": true,
	"main.bicep": true, "makefile": true, "procfile": true,
}

func repoOutline(dir string) []string {
	var dirs, files []string
	walked := 0
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if walked++; walked > outlineMaxWalk {
			return fs.SkipAll
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil || rel == "." {
			return nil
		}
		depth := strings.Count(rel, string(filepath.Separator))
		if d.IsDir() {
			if outlineSkipDirs[strings.ToLower(d.Name())] || strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			if depth >= outlineMaxDepth {
				return fs.SkipDir
			}
			dirs = append(dirs, "dir: "+filepath.ToSlash(rel)+"/")
			return nil
		}
		if outlineManifests[strings.ToLower(d.Name())] {
			files = append(files, "file: "+filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(dirs)
	sort.Strings(files)
	// Manifests carry more signal than bare directory names; keep them all
	// (within the cap) and fill the rest with directories.
	out := files
	if len(out) > outlineMaxEntries {
		out = out[:outlineMaxEntries]
	}
	for _, d := range dirs {
		if len(out) >= outlineMaxEntries {
			break
		}
		out = append(out, d)
	}
	return out
}
