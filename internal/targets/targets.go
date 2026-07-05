// Package targets is the scan-target registry: the closed allowlist of
// directories the console may launch scans against.
//
// SECURITY-CRITICAL (docs/console-ops.md T1): the registry is the ONLY
// bridge between a browser request and a filesystem path. The scan API
// accepts an opaque target ID; every path here was validated at
// registration time by an admin (absolute, clean, exists, directory, not
// "/"). The server never joins request input into a path.
package targets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/leaky-hub/appsec/internal/scanner"
)

const targetsFileName = "targets.json"

// ErrNotFound is returned when a target ID (or name) does not exist.
var ErrNotFound = errors.New("target not found")

// nameRe keeps display names log- and JSON-friendly.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9 ._/-]{1,80}$`)

// Target is one registered scan target.
type Target struct {
	ID        string    `json:"id"`   // opaque, server-assigned (t-<hex>)
	Name      string    `json:"name"` // human label shown in the console
	Path      string    `json:"path"` // absolute directory, validated at registration
	Scanners  []string  `json:"scanners,omitempty"` // allowed subset; empty = all
	Profile   string    `json:"profile,omitempty"`  // default profile; empty = standard
	CreatedAt time.Time `json:"createdAt"`
}

type targetsFile struct {
	Schema  int      `json:"schema"`
	Targets []Target `json:"targets"`
}

// Registry is the file-backed target registry (<repo>/.appsec/targets.json).
// Like the user store it re-reads on mtime change so CLI edits reach a
// running server.
type Registry struct {
	path string

	mu      sync.Mutex
	targets []Target
	modTime time.Time
	loaded  bool
}

// ForRepo returns the registry for <repoRoot>/.appsec/targets.json.
func ForRepo(repoRoot string) *Registry {
	return &Registry{path: filepath.Join(repoRoot, ".appsec", targetsFileName)}
}

// ValidatePath enforces the registration-time path rules. It returns the
// cleaned absolute path to store. Relative paths are the caller's problem:
// the CLI resolves them against its own CWD before calling; the API refuses
// them outright (the server's CWD means nothing to a browser user).
func ValidatePath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("target path must be absolute")
	}
	clean := filepath.Clean(path)
	if strings.Contains(path, "..") {
		// Clean would resolve these, but a registration attempt written with
		// ".." is at best confusing and at worst probing — reject loudly.
		return "", fmt.Errorf("target path must not contain \"..\"")
	}
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("refusing to register the filesystem root")
	}
	fi, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("target path: %w", err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("target path must be a directory")
	}
	return clean, nil
}

// Add validates and registers a target. scanners must be a subset of the
// known scanner names; profile must be a known profile (or empty).
func (r *Registry) Add(name, path string, scannerNames []string, profile string) (Target, error) {
	if !nameRe.MatchString(name) {
		return Target{}, fmt.Errorf("invalid target name (letters, digits, space, . _ / -; max 80)")
	}
	clean, err := ValidatePath(path)
	if err != nil {
		return Target{}, err
	}
	if err := validateScanners(scannerNames); err != nil {
		return Target{}, err
	}
	if profile != "" {
		if err := scanner.ValidateProfile(profile); err != nil {
			return Target{}, fmt.Errorf("invalid profile: %w", err)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refresh(); err != nil {
		return Target{}, err
	}
	for _, t := range r.targets {
		if t.Name == name {
			return Target{}, fmt.Errorf("target name %q already exists", name)
		}
		if t.Path == clean {
			return Target{}, fmt.Errorf("path already registered as %q (%s)", t.Name, t.ID)
		}
	}
	t := Target{ID: newID(), Name: name, Path: clean, Scanners: scannerNames, Profile: profile, CreatedAt: time.Now().UTC()}
	r.targets = append(r.targets, t)
	if err := r.save(); err != nil {
		r.loaded = false
		return Target{}, err
	}
	return t, nil
}

// Remove deletes a target by ID or name.
func (r *Registry) Remove(idOrName string) (Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refresh(); err != nil {
		return Target{}, err
	}
	for i, t := range r.targets {
		if t.ID == idOrName || t.Name == idOrName {
			r.targets = append(r.targets[:i], r.targets[i+1:]...)
			if err := r.save(); err != nil {
				r.loaded = false
				return Target{}, err
			}
			return t, nil
		}
	}
	return Target{}, ErrNotFound
}

// Get resolves a target by ID only — the scan API never looks up by
// anything a user typed.
func (r *Registry) Get(id string) (Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refresh(); err != nil {
		return Target{}, err
	}
	for _, t := range r.targets {
		if t.ID == id {
			return t, nil
		}
	}
	return Target{}, ErrNotFound
}

// List returns all targets sorted by name.
func (r *Registry) List() ([]Target, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refresh(); err != nil {
		return nil, err
	}
	out := make([]Target, len(r.targets))
	copy(out, r.targets)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *Registry) refresh() error {
	fi, err := os.Stat(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			r.targets, r.modTime, r.loaded = nil, time.Time{}, true
			return nil
		}
		return fmt.Errorf("targets: stat registry: %w", err)
	}
	if r.loaded && fi.ModTime().Equal(r.modTime) {
		return nil
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("targets: read registry: %w", err)
	}
	var f targetsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("targets: parse registry: %w", err)
	}
	r.targets, r.modTime, r.loaded = f.Targets, fi.ModTime(), true
	return nil
}

func (r *Registry) save() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return fmt.Errorf("targets: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(targetsFile{Schema: 1, Targets: r.targets}, "", "  ")
	if err != nil {
		return fmt.Errorf("targets: marshal: %w", err)
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("targets: write registry: %w", err)
	}
	if err := os.Rename(tmp, r.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("targets: replace registry: %w", err)
	}
	if fi, err := os.Stat(r.path); err == nil {
		r.modTime = fi.ModTime()
	}
	return nil
}

// KnownScanners returns the closed set of scanner names, derived from the
// adapter registry so it cannot drift from the scan pipeline.
func KnownScanners() []string {
	var names []string
	for _, a := range scanner.All(nil) {
		names = append(names, a.Name())
	}
	return names
}

func validateScanners(names []string) error {
	known := map[string]bool{}
	for _, n := range KnownScanners() {
		known[n] = true
	}
	for _, n := range names {
		if !known[strings.ToLower(n)] {
			return fmt.Errorf("unknown scanner %q (known: %s)", n, strings.Join(KnownScanners(), ", "))
		}
	}
	return nil
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("targets: crypto/rand unavailable: " + err.Error())
	}
	return "t-" + hex.EncodeToString(b[:])
}
