// Package targets is the scan-target registry: the closed allowlist of
// directories and git repositories the console may launch scans against.
//
// SECURITY-CRITICAL (docs/console-ops.md T1, S1): the registry is the ONLY
// bridge between a browser request and a filesystem path or clone URL. The
// scan API accepts an opaque target ID; every path here was validated at
// registration time by an admin (absolute, clean, exists, directory, not
// "/"), and every git URL passed the S1 policy (https only, host present,
// no userinfo). The server never joins request input into a path or a git
// argv.
package targets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/leaky-hub/argus/internal/cloudscan"
	"github.com/leaky-hub/argus/internal/scanner"
	"github.com/leaky-hub/argus/internal/snippet"
)

const targetsFileName = "targets.json"

// ErrNotFound is returned when a target ID (or name) does not exist.
var ErrNotFound = errors.New("target not found")

// nameRe keeps display names log- and JSON-friendly.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9 ._/-]{1,80}$`)

// branchRe bounds git branch names to safe refname characters. A leading
// "-" is additionally rejected (never an argv flag), as is "..".
var branchRe = regexp.MustCompile(`^[a-zA-Z0-9._/-]{1,100}$`)

// Target types. An empty Type means TypeDir so pre-existing registry files
// parse unchanged (additive schema).
const (
	TypeDir   = "dir"
	TypeGit   = "git"
	TypeCloud = "cloud" // schema 2.1.0: a cloud account referenced by profile name
)

// regionRe bounds a cloud region filter entry — the same closed grammar the
// cloudscan validator enforces, checked here at the admin boundary too.
var regionRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Config is the console-editable scan-configuration subset stored on a
// registry entry (docs/console-ops.md S3/§12.3). It is a CLOSED set by
// design: triage provider/model/endpoint, semgrep rulesets, fail severity
// and report format are deliberately absent — those come from the target
// repo's appsec.yml and the environment only.
type Config struct {
	TimeoutSec  int      `json:"timeoutSec,omitempty"`  // per-scanner timeout; 0 = repo/config default
	Triage      *bool    `json:"triage,omitempty"`      // default triage on/off; nil = repo default
	IgnorePaths []string `json:"ignorePaths,omitempty"` // glob patterns (admin-set, audited)
	IgnoreRules []string `json:"ignoreRules,omitempty"` // exact rule IDs (admin-set, audited)
}

// Target is one registered scan target.
type Target struct {
	ID     string `json:"id"`               // opaque, server-assigned (t-<hex>)
	Name   string `json:"name"`             // human label shown in the console
	Type   string `json:"type,omitempty"`   // TypeDir (default when empty) or TypeGit
	Path   string `json:"path,omitempty"`   // dir targets: absolute directory, validated at registration
	URL    string `json:"url,omitempty"`    // git targets: validated https clone URL (S1)
	Branch string `json:"branch,omitempty"` // git targets: optional branch to track

	// Cloud targets (schema 2.1.0). CREDENTIALS ARE NEVER STORED: ProfileName
	// is a NAME validated against the closed list discovered from the local
	// cloud config (never free-form), passed to prowler as an identifier. No
	// key material ever reaches this struct, targets.json, or a log.
	Provider    string   `json:"provider,omitempty"`    // "aws" | "azure" | "gcp" (cloud targets)
	ProfileName string   `json:"profileName,omitempty"` // AWS: a name from the local cloud config's closed list
	Account     string   `json:"account,omitempty"`     // Azure subscription id / GCP project id (the account reference)
	Regions     []string `json:"regions,omitempty"`     // AWS optional region filter

	Scanners  []string  `json:"scanners,omitempty"` // allowed subset; empty = all
	Profile   string    `json:"profile,omitempty"`  // default profile; empty = standard
	Config    *Config   `json:"config,omitempty"`   // console-managed overrides (S3)
	CreatedAt time.Time `json:"createdAt"`
}

// Kind returns the effective target type (empty Type = dir).
func (t Target) Kind() string {
	if t.Type == "" {
		return TypeDir
	}
	return t.Type
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

// ValidateGitURL enforces the S1 registration policy on a clone URL and
// returns the normalized string to store. Only https URLs with a host and
// WITHOUT userinfo are accepted: ssh://, git://, file://, scp-style
// "host:path", and token-in-URL forms are all rejected here, once, at the
// admin boundary — the executor's transport lockdown is the backstop, not
// the policy.
func ValidateGitURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("git url must not be empty")
	}
	if strings.ContainsAny(raw, " \t\n\r") {
		return "", fmt.Errorf("git url must not contain whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("git url: %v", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("git url must use https:// (got %q; ssh/git/file/scp forms are not accepted)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("git url must include a host")
	}
	if u.User != nil {
		return "", fmt.Errorf("git url must not embed credentials — the server uses the host's git credential helper")
	}
	if u.Fragment != "" || u.RawQuery != "" {
		return "", fmt.Errorf("git url must not carry a query or fragment")
	}
	return u.String(), nil
}

// ValidateBranch bounds an optional branch name (empty = remote default).
func ValidateBranch(branch string) error {
	if branch == "" {
		return nil
	}
	if !branchRe.MatchString(branch) || strings.HasPrefix(branch, "-") || strings.Contains(branch, "..") {
		return fmt.Errorf("invalid branch name")
	}
	return nil
}

// Workspace returns the server-owned working-copy directory for a git
// target: <servedRepo>/.appsec/workspace/<targetID>. The ID is always
// server-generated hex, never request input.
func (r *Registry) Workspace(t Target) string {
	return filepath.Join(filepath.Dir(r.path), "workspace", t.ID)
}

// Root resolves the directory a target is scanned from (and whose
// .appsec/runs holds its history): the registered path for dir targets, the
// workspace for git targets.
func (r *Registry) Root(t Target) string {
	if t.Kind() == TypeGit {
		return r.Workspace(t)
	}
	return t.Path
}

// CloudRunStore resolves the run-history directory for a cloud target: there
// is no filesystem target to own the history, so cloud runs live under the
// served repo's .appsec/cloud/<targetID>/runs (locked decision 9). The ID is
// always server-generated hex, never request input, so the path is safe to
// join. The returned dir is the runstore.Store.Dir a caller uses.
func (r *Registry) CloudRunStore(t Target) string {
	return filepath.Join(filepath.Dir(r.path), "cloud", t.ID, "runs")
}

// ResolveScope confines a per-launch scan scope (docs/console-ops.md S2) and
// returns the absolute path to scan. scope must be relative; it is cleaned,
// joined to root server-side, symlink-resolved, verified inside root, must
// exist, and may not enter .git/ or .appsec/ (VCS and platform bookkeeping
// are never scan surface). Empty scope = the whole target.
//
// Callers validate at enqueue AND re-validate at execution: the tree can
// change between the two — always, for git targets, whose workspace is
// refreshed per scan.
func ResolveScope(root, scope string) (string, error) {
	if err := ValidateScopeSyntax(scope); err != nil {
		return "", err
	}
	clean := filepath.Clean(filepath.FromSlash(scope))
	if scope == "" || clean == "." {
		return root, nil
	}
	joined := filepath.Join(root, clean)
	// One containment implementation for the whole platform: resolve
	// symlinks and require the result to stay inside the resolved root.
	real, err := snippet.ContainedPath(root, joined)
	if err != nil {
		return "", fmt.Errorf("scope: %s does not exist inside the target or escapes it", scope)
	}
	return real, nil
}

// ValidateScopeSyntax rejects every scope attack expressible without a
// filesystem: absolute paths, traversal, VCS/bookkeeping segments. It is the
// enqueue-time check for git targets, whose tree does not exist until the
// executor syncs the workspace (ResolveScope then runs the full check).
func ValidateScopeSyntax(scope string) error {
	if scope == "" {
		return nil
	}
	if filepath.IsAbs(scope) || (len(scope) > 1 && scope[1] == ':') { // POSIX abs or Windows drive
		return fmt.Errorf("scope must be a relative path inside the target")
	}
	clean := filepath.Clean(filepath.FromSlash(scope))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("scope must not leave the target (\"..\")")
	}
	for _, seg := range strings.Split(clean, string(filepath.Separator)) {
		if seg == ".git" || seg == ".appsec" {
			return fmt.Errorf("scope must not enter %s", seg)
		}
	}
	return nil
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
	t := Target{ID: newID(), Name: name, Type: TypeDir, Path: clean, Scanners: scannerNames, Profile: profile, CreatedAt: time.Now().UTC()}
	r.targets = append(r.targets, t)
	if err := r.save(); err != nil {
		r.loaded = false
		return Target{}, err
	}
	return t, nil
}

// AddGit validates and registers a remote git target (S1). The working copy
// is created lazily by the job executor on first scan; registration only
// stores the validated URL and optional branch.
func (r *Registry) AddGit(name, rawURL, branch string, scannerNames []string, profile string) (Target, error) {
	if !nameRe.MatchString(name) {
		return Target{}, fmt.Errorf("invalid target name (letters, digits, space, . _ / -; max 80)")
	}
	cleanURL, err := ValidateGitURL(rawURL)
	if err != nil {
		return Target{}, err
	}
	if err := ValidateBranch(branch); err != nil {
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
		if t.URL == cleanURL && t.Branch == branch {
			return Target{}, fmt.Errorf("url already registered as %q (%s)", t.Name, t.ID)
		}
	}
	t := Target{ID: newID(), Name: name, Type: TypeGit, URL: cleanURL, Branch: branch, Scanners: scannerNames, Profile: profile, CreatedAt: time.Now().UTC()}
	r.targets = append(r.targets, t)
	if err := r.save(); err != nil {
		r.loaded = false
		return Target{}, err
	}
	return t, nil
}

// AddCloud validates and registers a cloud posture target (schema 2.1.0).
// The credential surface is a NAME only: profileName must be present in the
// closed list discovered from the local cloud config (cloudscan validates
// it), regions must match the closed region grammar. No key material is
// accepted, stored, or logged — the console form offers the discovered names
// as opaque choices and this is the one place a chosen name is bound to a
// target. Scans resolve the name against prowler at run time.
func (r *Registry) AddCloud(name, provider, profileName, account string, regions, scannerNames []string, profile string) (Target, error) {
	if !nameRe.MatchString(name) {
		return Target{}, fmt.Errorf("invalid target name (letters, digits, space, . _ / -; max 80)")
	}
	// Provider + account-reference validation lives in cloudscan (the one owner
	// of the credential-reference contract): an AWS profile outside the
	// discovered closed list, or a malformed Azure/GCP account id, never
	// registers. No key material ever reaches this struct.
	if err := cloudscan.Validate(cloudscan.Options{Provider: provider, Profile: profileName, Account: account, Regions: regions}); err != nil {
		return Target{}, err
	}
	for _, rg := range regions {
		if !regionRe.MatchString(rg) {
			return Target{}, fmt.Errorf("invalid region %q", rg)
		}
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
		if t.Kind() == TypeCloud && t.Provider == provider && t.ProfileName == profileName && t.Account == account {
			return Target{}, fmt.Errorf("cloud account already registered as %q (%s)", t.Name, t.ID)
		}
	}
	t := Target{ID: newID(), Name: name, Type: TypeCloud, Provider: provider, ProfileName: profileName,
		Account: account, Regions: regions, Scanners: scannerNames, Profile: profile, CreatedAt: time.Now().UTC()}
	r.targets = append(r.targets, t)
	if err := r.save(); err != nil {
		r.loaded = false
		return Target{}, err
	}
	return t, nil
}

// Config bounds (S3): patterns and rules are suppression knobs, so they are
// tightly bounded and every change is audited by the caller.
const (
	minTimeoutSec     = 10
	maxTimeoutSec     = 3600
	maxIgnoreEntries  = 50
	maxIgnoreEntryLen = 200
)

// ValidateConfig checks a console-supplied config block against the S3
// bounds. A nil config is valid (no overrides).
func ValidateConfig(c *Config) error {
	if c == nil {
		return nil
	}
	if c.TimeoutSec != 0 && (c.TimeoutSec < minTimeoutSec || c.TimeoutSec > maxTimeoutSec) {
		return fmt.Errorf("config timeout must be between %d and %d seconds (0 = default)", minTimeoutSec, maxTimeoutSec)
	}
	if err := validateIgnoreList("ignorePaths", c.IgnorePaths); err != nil {
		return err
	}
	return validateIgnoreList("ignoreRules", c.IgnoreRules)
}

func validateIgnoreList(field string, entries []string) error {
	if len(entries) > maxIgnoreEntries {
		return fmt.Errorf("%s: at most %d entries", field, maxIgnoreEntries)
	}
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			return fmt.Errorf("%s: entries must be non-empty", field)
		}
		if len(e) > maxIgnoreEntryLen {
			return fmt.Errorf("%s: entries are capped at %d characters", field, maxIgnoreEntryLen)
		}
		for _, r := range e {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("%s: entries must not contain control characters", field)
			}
		}
	}
	return nil
}

// Patch is a partial update to a target's console-editable fields. nil
// pointer = unchanged; Config replaces the stored block wholesale (an empty
// Config clears all overrides).
type Patch struct {
	Name     *string
	Scanners *[]string
	Profile  *string
	Config   *Config
}

// Update applies a validated patch and returns the updated target plus the
// list of changed-field names for the caller's audit line. Registration
// identity (type, path, url, branch) is immutable — replacing WHERE a target
// points is a delete + re-add, never an edit.
func (r *Registry) Update(id string, p Patch) (Target, []string, error) {
	if p.Name != nil && !nameRe.MatchString(*p.Name) {
		return Target{}, nil, fmt.Errorf("invalid target name (letters, digits, space, . _ / -; max 80)")
	}
	if p.Scanners != nil {
		if err := validateScanners(*p.Scanners); err != nil {
			return Target{}, nil, err
		}
	}
	if p.Profile != nil && *p.Profile != "" {
		if err := scanner.ValidateProfile(*p.Profile); err != nil {
			return Target{}, nil, fmt.Errorf("invalid profile: %w", err)
		}
	}
	if err := ValidateConfig(p.Config); err != nil {
		return Target{}, nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refresh(); err != nil {
		return Target{}, nil, err
	}
	for i := range r.targets {
		t := &r.targets[i]
		if t.ID != id {
			continue
		}
		var changed []string
		if p.Name != nil && *p.Name != t.Name {
			for _, other := range r.targets {
				if other.ID != id && other.Name == *p.Name {
					return Target{}, nil, fmt.Errorf("target name %q already exists", *p.Name)
				}
			}
			t.Name = *p.Name
			changed = append(changed, "name")
		}
		if p.Scanners != nil {
			t.Scanners = *p.Scanners
			changed = append(changed, "scanners")
		}
		if p.Profile != nil {
			t.Profile = *p.Profile
			changed = append(changed, "profile")
		}
		if p.Config != nil {
			t.Config = normalizeConfig(p.Config)
			changed = append(changed, "config")
		}
		if len(changed) == 0 {
			return *t, nil, nil
		}
		if err := r.save(); err != nil {
			r.loaded = false
			return Target{}, nil, err
		}
		return *t, changed, nil
	}
	return Target{}, nil, ErrNotFound
}

// normalizeConfig stores nil instead of an all-defaults block so cleared
// overrides disappear from targets.json rather than lingering as {}.
func normalizeConfig(c *Config) *Config {
	if c == nil {
		return nil
	}
	if c.TimeoutSec == 0 && c.Triage == nil && len(c.IgnorePaths) == 0 && len(c.IgnoreRules) == 0 {
		return nil
	}
	cp := *c
	return &cp
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
