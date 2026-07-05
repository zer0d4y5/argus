package server

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/compliance"
	"github.com/leaky-hub/appsec/internal/config"
	"github.com/leaky-hub/appsec/internal/coverage"
	"github.com/leaky-hub/appsec/internal/gitws"
	"github.com/leaky-hub/appsec/internal/jobs"
	"github.com/leaky-hub/appsec/internal/pipeline"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/snippet"
	"github.com/leaky-hub/appsec/internal/targets"
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
func ScanExecutor(reg *targets.Registry, auditLog *audit.Log, git gitws.Syncer) jobs.ExecFunc {
	return func(ctx context.Context, job jobs.Job, progress func(line string)) (jobs.Result, error) {
		res, err := execScan(ctx, reg, git, job, progress)
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

func execScan(ctx context.Context, reg *targets.Registry, git gitws.Syncer, job jobs.Job, progress func(line string)) (jobs.Result, error) {
	// Re-resolve at execution time: a target deleted while the job sat in
	// the queue must not scan.
	t, err := reg.Get(job.TargetID)
	if err != nil {
		return jobs.Result{}, fmt.Errorf("target no longer registered")
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

	cfg, err := mergeConfig(t, root, job.Options)
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

// mergeConfig owns the layering chain (docs/console-ops.md §12.3):
//
//	repo appsec.yml  <  registry entry (scanners/profile/config)  <  launch options
//
// Ignore lists are the one additive exception: registry entries APPEND to
// the repo's suppressions (console config can add suppressions, never undo
// what the repo declares). Git targets additionally always ignore .appsec/**
// so the workspace's own run history never feeds back into findings.
func mergeConfig(t targets.Target, root string, opts jobs.Options) (config.Config, error) {
	cfg, err := repoConfig(root)
	if err != nil {
		return cfg, err
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

// repoConfig loads the scanned tree's own appsec.yml, falling back to
// defaults when absent.
func repoConfig(root string) (config.Config, error) {
	cfgPath := filepath.Join(root, "appsec.yml")
	if _, err := os.Stat(cfgPath); err == nil {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return cfg, fmt.Errorf("target config: %w", err)
		}
		return cfg, nil
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
