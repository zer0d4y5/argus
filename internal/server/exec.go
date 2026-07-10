package server

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/compliance"
	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/coverage"
	"github.com/zer0d4y5/argus/internal/gitws"
	"github.com/zer0d4y5/argus/internal/jobs"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/snippet"
	"github.com/zer0d4y5/argus/internal/targets"
)

// ScanExecutor builds the queue's ExecFunc: resolve the registered target
// (syncing the git workspace for remote targets), load the target tree's own
// appsec.yml as the config base, apply the registry overrides and the
// closed-enum launch options through ONE merge function, re-validate the
// launch scope against the fresh tree, run the extracted pipeline, capture
// snippets, and save through the existing runstore path into the target's
// own .appsec/runs.
//
// The triage provider/model/endpoint always come from the repo config —
// neither the registry config block nor the request can touch them
// (docs/console-ops.md S3).
func ScanExecutor(reg *targets.Registry, auditLog *audit.Log, git gitws.Syncer, servedDir string) jobs.ExecFunc {
	return func(ctx context.Context, job jobs.Job, progress func(line string)) (jobs.Result, error) {
		res, err := execScan(ctx, reg, git, job, progress, servedDir)
		// scan.finish is written for success and failure alike: the audit
		// log, not in-memory job state, is the durable record.
		details := map[string]string{"job": job.ID, "target": job.TargetID}
		if res.Commit != "" {
			details["commit"] = res.Commit
		}
		if err != nil {
			details["result"] = "failed"
		} else {
			details["result"] = "done"
			details["run"] = res.RunID
		}
		if auditLog != nil {
			if aerr := auditLog.Write(audit.EventScanFinish, job.LaunchedBy, details); aerr != nil {
				fmt.Fprintf(os.Stderr, "WARN: audit write failed: %v\n", aerr)
			}
		}
		return res, err
	}
}

func execScan(ctx context.Context, reg *targets.Registry, git gitws.Syncer, job jobs.Job, progress func(line string), servedDir string) (jobs.Result, error) {
	// Re-resolve at execution time: a target deleted while the job sat in
	// the queue must not scan.
	t, err := reg.Get(job.TargetID)
	if err != nil {
		return jobs.Result{}, fmt.Errorf("target no longer registered")
	}

	// Cloud posture targets run a different pipeline (prowler, no filesystem
	// tree) and save to their own per-target store — split out so the
	// path/git machinery below never touches a credential reference. DAST
	// (nuclei against a URL) and image (trivy against a reference) are the
	// same shape: no source tree, their own per-target store.
	switch t.Kind() {
	case targets.TypeCloud:
		return execCloudScan(ctx, reg, t, job, progress)
	case targets.TypeDAST:
		return execDASTScan(ctx, reg, t, job, progress)
	case targets.TypeImage:
		return execImageScan(ctx, reg, t, job, progress)
	}

	root := reg.Root(t)
	var out jobs.Result
	if t.Kind() == targets.TypeGit {
		commit, err := git.Sync(ctx, t.URL, t.Branch, root, progress)
		if err != nil {
			return jobs.Result{}, err
		}
		out.Commit = commit
	}

	// S2: the scope was validated at enqueue, but the tree may have changed
	// since (it certainly did for git targets) — re-confine against the tree
	// that will actually be scanned.
	scanPath, err := targets.ResolveScope(root, job.Options.Scope)
	if err != nil {
		return out, err
	}

	cfg, err := mergeConfig(t, root, job.Options, servedDir)
	if err != nil {
		return out, err
	}

	res, err := pipeline.Run(ctx, pipeline.Options{Target: scanPath, Config: cfg}, progress)
	if err != nil {
		return out, err
	}

	// Code frames ride the run file (schema 1.4.0): captured under the S4
	// bounds, SECRET findings excluded, confined to the scanned tree.
	snippet.Capture(scanPath, res.Findings)

	// A scoped run is part of the TARGET's history: save to the target
	// root's store, never the scope subdirectory (docs/console-ops.md §12.2).
	// Skip accounting covers what was actually scanned (the scope path when
	// one is set), not the whole target tree.
	cov := coverage.Account(scanPath)
	meta, err := runstore.ForRepo(root).SaveWithCoverage(res.Findings, &cov, time.Now())
	if err != nil {
		return out, fmt.Errorf("save run: %w", err)
	}
	progress(fmt.Sprintf("==> saved run %s\n", meta.ID))
	out.RunID = meta.ID
	return out, nil
}

// execCloudScan runs a registered cloud posture target through prowler and
// the shared enrichment pipeline, saving to the target's own cloud store
// (locked decision 9). The credential is the registered profile NAME,
// re-validated by cloudscan against the local closed list at run time; it
// never appears in the job, the audit line, or the progress stream. The
// per-provider timeout (config default 1800s) bounds the whole run.
func execCloudScan(ctx context.Context, reg *targets.Registry, t targets.Target, job jobs.Job, progress func(line string)) (jobs.Result, error) {
	var out jobs.Result

	// Cloud runs use the served repo's own appsec.yml for enrichment settings
	// (triage on/off, cloud timeout); the registry entry's profile override
	// still applies. Credentials are never in config.
	cfg := config.Default()
	if job.Options.Triage != nil {
		cfg.Triage.Enabled = *job.Options.Triage
	} else if c := t.Config; c != nil && c.Triage != nil {
		cfg.Triage.Enabled = *c.Triage
	}
	if t.Profile != "" {
		cfg.Profile = t.Profile
	}
	if err := cfg.Validate(); err != nil {
		return out, err
	}

	timeout := time.Duration(cfg.Cloud.TimeoutSec) * time.Second
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res, err := pipeline.RunCloud(cctx, pipeline.CloudOptions{
		Provider: t.Provider,
		Profile:  t.ProfileName,
		Account:  t.Account,
		Regions:  t.Regions,
		Config:   cfg,
	}, progress)
	if err != nil {
		return out, err
	}
	progress(fmt.Sprintf("==> posture: %d failed, %d passed, %d manual\n", res.Failed, res.Passed, res.Manual))

	// Cloud findings have no source tree: no snippet capture, no filesystem
	// coverage accounting. Save to the per-target cloud store, recording the
	// prowler release for provenance.
	store := runstore.Store{Dir: reg.CloudRunStore(t)}
	var tools map[string]string
	if res.ToolVersion != "" {
		tools = map[string]string{"prowler": res.ToolVersion}
	}
	meta, err := store.SaveWithTools(res.Findings, tools, time.Now())
	if err != nil {
		return out, fmt.Errorf("save cloud run: %w", err)
	}
	progress(fmt.Sprintf("==> saved run %s\n", meta.ID))
	out.RunID = meta.ID
	return out, nil
}

// consoleEnrichConfig builds the config for the non-filesystem scan kinds
// (cloud, DAST, image): the served repo's own appsec.yml provides the
// enrichment settings (triage on/off, timeouts), with the launch-time triage
// toggle and the registry entry's triage default layered on. It never carries
// a filesystem scanner set or scope: those knobs do not apply to these kinds
// (rejected at the launch boundary), and no credential ever reaches config.
func consoleEnrichConfig(t targets.Target, job jobs.Job) (config.Config, error) {
	cfg := config.Default()
	if job.Options.Triage != nil {
		cfg.Triage.Enabled = *job.Options.Triage
	} else if c := t.Config; c != nil && c.Triage != nil {
		cfg.Triage.Enabled = *c.Triage
	}
	return cfg, cfg.Validate()
}

// execDASTScan runs a registered DAST target through nuclei and the shared
// enrichment pipeline, saving to the target's own per-target store. The URL
// was validated at registration; nuclei sends only requests to it.
func execDASTScan(ctx context.Context, reg *targets.Registry, t targets.Target, job jobs.Job, progress func(line string)) (jobs.Result, error) {
	var out jobs.Result
	cfg, err := consoleEnrichConfig(t, job)
	if err != nil {
		return out, err
	}
	opts := pipeline.DASTOptions{URL: t.URL, Config: cfg}
	applyDastConfig(&opts, t, progress)
	res, err := pipeline.RunDAST(ctx, opts, progress)
	if err != nil {
		return out, err
	}
	store := runstore.Store{Dir: reg.DASTRunStore(t)}
	var tools map[string]string
	if res.ToolVersion != "" {
		tools = map[string]string{"nuclei": res.ToolVersion}
	}
	meta, err := store.SaveWithTools(res.Findings, tools, time.Now())
	if err != nil {
		return out, fmt.Errorf("save dast run: %w", err)
	}
	progress(fmt.Sprintf("==> saved run %s\n", meta.ID))
	out.RunID = meta.ID
	return out, nil
}

// applyDastConfig folds a DAST target's console-set scan configuration
// (fuzzing, scope filters, authentication) into the run options. Credentials
// are resolved from the NAMED environment variables at scan time and used only
// in memory: a missing env var is a clear progress warning and the credential
// is skipped, never a silent unauthenticated scan when defaults are also off.
// This is the console analogue of the `argus dast` flags; it is hand-written
// because it sits on the credential/exec boundary.
func applyDastConfig(opts *pipeline.DASTOptions, t targets.Target, progress func(string)) {
	if t.Config == nil || t.Config.Dast == nil {
		return
	}
	d := t.Config.Dast
	opts.Fuzzing = d.Fuzzing
	opts.Templates = d.Templates
	opts.Tags = d.Tags
	opts.Severities = d.Severities
	opts.RateLimit = d.RateLimit
	if d.Auth == nil {
		return
	}
	a := &pipeline.DASTAuth{LoginURL: d.Auth.LoginURL, TryDefaults: d.Auth.TryDefaults}
	if d.Auth.UsernameEnv != "" {
		if v, ok := os.LookupEnv(d.Auth.UsernameEnv); ok {
			a.Username = v
		} else {
			progress(fmt.Sprintf("WARN: dast auth: env var %q (username) is not set on the server\n", d.Auth.UsernameEnv))
		}
	}
	if d.Auth.PasswordEnv != "" {
		if v, ok := os.LookupEnv(d.Auth.PasswordEnv); ok {
			a.Password = v
		} else {
			progress(fmt.Sprintf("WARN: dast auth: env var %q (password) is not set on the server\n", d.Auth.PasswordEnv))
		}
	}
	// Only attach auth when there is actually something to try, so a target
	// with an auth block but no resolvable creds and no defaults still scans
	// (unauthenticated) rather than failing the run.
	if a.TryDefaults || a.Username != "" || a.Password != "" {
		opts.Auth = a
	}
}

// execImageScan runs a registered image target through trivy and the shared
// enrichment pipeline, saving to the target's own per-target store. The image
// reference was validated at registration; registry credentials come from the
// ambient container config, never from Argus.
func execImageScan(ctx context.Context, reg *targets.Registry, t targets.Target, job jobs.Job, progress func(line string)) (jobs.Result, error) {
	var out jobs.Result
	cfg, err := consoleEnrichConfig(t, job)
	if err != nil {
		return out, err
	}
	res, err := pipeline.RunImage(ctx, pipeline.ImageOptions{Ref: t.Ref, Config: cfg}, progress)
	if err != nil {
		return out, err
	}
	store := runstore.Store{Dir: reg.ImageRunStore(t)}
	meta, err := store.Save(res.Findings, time.Now())
	if err != nil {
		return out, fmt.Errorf("save image run: %w", err)
	}
	progress(fmt.Sprintf("==> saved run %s\n", meta.ID))
	out.RunID = meta.ID
	return out, nil
}

// mergeConfig owns the layering chain (docs/console-ops.md §12.3):
//
//	repo appsec.yml  <  registry entry (scanners/profile/config)  <  launch options
//
// Ignore lists are the one additive exception: registry entries APPEND to
// the repo's suppressions (console config can add suppressions, never undo
// what the repo declares). Git targets additionally always ignore .appsec/**
// so the workspace's own run history never feeds back into findings.
func mergeConfig(t targets.Target, root string, opts jobs.Options, servedDir string) (config.Config, error) {
	cfg, err := repoConfig(root)
	if err != nil {
		return cfg, err
	}
	// Overlay the console-managed settings when scanning the served repo, so a
	// UI change to scan defaults / triage takes effect at launch.
	if root == "" || root == servedDir {
		if cs, cerr := loadConsoleSettings(servedDir); cerr == nil {
			applyConsoleSettings(&cfg, cs)
		}
	}

	// Layer 2: the registry entry.
	if len(t.Scanners) > 0 {
		cfg.Scanners = t.Scanners
	}
	if t.Profile != "" {
		cfg.Profile = t.Profile
	}
	if c := t.Config; c != nil {
		if c.TimeoutSec > 0 {
			cfg.TimeoutSec = c.TimeoutSec
		}
		if c.Triage != nil {
			cfg.Triage.Enabled = *c.Triage
		}
		cfg.IgnorePaths = append(cfg.IgnorePaths, c.IgnorePaths...)
		cfg.IgnoreRules = append(cfg.IgnoreRules, c.IgnoreRules...)
	}
	if t.Kind() == targets.TypeGit {
		// Anchor the workspace-bookkeeping ignore to the scan root AS THE
		// SCANNERS WILL REPORT IT: findings carry the invocation prefix
		// (relative or absolute), so a bare ".appsec/**" would either miss —
		// or, with a relative serve dir, match the "<dir>/.appsec/workspace/…"
		// prefix of EVERY finding and suppress the whole scan.
		cfg.IgnorePaths = append(cfg.IgnorePaths, path.Join(filepath.ToSlash(root), ".appsec")+"/**")
	}

	// Layer 3: the launch options.
	if len(opts.Scanners) > 0 {
		cfg.Scanners = opts.Scanners
	}
	if opts.Profile != "" {
		cfg.Profile = opts.Profile
	}
	if opts.Triage != nil {
		cfg.Triage.Enabled = *opts.Triage
	}

	// S6: a framework focus narrows the effective scanner set. Validated at
	// enqueue; re-checked here because the effective set may differ after
	// the merge (e.g. the repo config narrowed scanners further).
	if len(opts.Frameworks) > 0 {
		effective := cfg.Scanners
		if len(effective) == 0 {
			effective = targets.KnownScanners()
		}
		narrowed, err := compliance.NarrowScanners(effective, opts.Frameworks)
		if err != nil {
			return cfg, err
		}
		cfg.Scanners = narrowed
	}

	return cfg, cfg.Validate()
}

// repoConfig loads the scanned tree's own config (argus.yml, then the
// legacy appsec.yml), falling back to defaults when absent.
func repoConfig(root string) (config.Config, error) {
	for _, name := range config.DefaultConfigNames {
		cfgPath := filepath.Join(root, name)
		if _, err := os.Stat(cfgPath); err == nil {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return cfg, fmt.Errorf("target config: %w", err)
			}
			return cfg, nil
		}
	}
	return config.Default(), nil
}

// launchDetails renders the accepted options for the scan.launch audit line.
func launchDetails(job jobs.Job, t targets.Target) map[string]string {
	details := map[string]string{"job": job.ID, "target": t.ID, "name": t.Name}
	if len(job.Options.Scanners) > 0 {
		details["scanners"] = strings.Join(job.Options.Scanners, ",")
	}
	if job.Options.Profile != "" {
		details["profile"] = job.Options.Profile
	}
	if job.Options.Triage != nil {
		details["triage"] = fmt.Sprintf("%t", *job.Options.Triage)
	}
	if job.Options.Scope != "" {
		details["scope"] = job.Options.Scope
	}
	if len(job.Options.Frameworks) > 0 {
		details["frameworks"] = strings.Join(job.Options.Frameworks, ",")
	}
	return details
}
