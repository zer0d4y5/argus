package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/config"
	"github.com/leaky-hub/appsec/internal/jobs"
	"github.com/leaky-hub/appsec/internal/pipeline"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/targets"
)

// ScanExecutor builds the queue's ExecFunc: resolve the registered target,
// load ITS OWN appsec.yml as the config base, apply the closed-enum launch
// options, run the extracted pipeline, and save through the existing
// runstore path (the run lands in the scanned repo's .appsec/runs exactly
// as `appsec scan --save` would put it).
//
// The triage provider/model/endpoint always come from the repo config —
// the request can only flip triage on or off (docs/console-ops.md §7).
func ScanExecutor(reg *targets.Registry, auditLog *audit.Log) jobs.ExecFunc {
	return func(ctx context.Context, job jobs.Job, progress func(line string)) (string, error) {
		runID, err := execScan(ctx, reg, job, progress)
		// scan.finish is written for success and failure alike: the audit
		// log, not in-memory job state, is the durable record.
		details := map[string]string{"job": job.ID, "target": job.TargetID}
		if err != nil {
			details["result"] = "failed"
		} else {
			details["result"] = "done"
			details["run"] = runID
		}
		if auditLog != nil {
			if aerr := auditLog.Write(audit.EventScanFinish, job.LaunchedBy, details); aerr != nil {
				fmt.Fprintf(os.Stderr, "WARN: audit write failed: %v\n", aerr)
			}
		}
		return runID, err
	}
}

func execScan(ctx context.Context, reg *targets.Registry, job jobs.Job, progress func(line string)) (string, error) {
	// Re-resolve at execution time: a target deleted while the job sat in
	// the queue must not scan.
	t, err := reg.Get(job.TargetID)
	if err != nil {
		return "", fmt.Errorf("target no longer registered")
	}

	cfg, err := targetConfig(t)
	if err != nil {
		return "", err
	}

	// Closed-enum launch options (validated against the registry entry at
	// enqueue time; config validation below backstops both).
	if len(job.Options.Scanners) > 0 {
		cfg.Scanners = job.Options.Scanners
	}
	if job.Options.Profile != "" {
		cfg.Profile = job.Options.Profile
	}
	if job.Options.Triage != nil {
		cfg.Triage.Enabled = *job.Options.Triage
	}
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	res, err := pipeline.Run(ctx, pipeline.Options{Target: t.Path, Config: cfg}, progress)
	if err != nil {
		return "", err
	}

	meta, err := runstore.ForRepo(t.Path).Save(res.Findings, time.Now())
	if err != nil {
		return "", fmt.Errorf("save run: %w", err)
	}
	progress(fmt.Sprintf("==> saved run %s\n", meta.ID))
	return meta.ID, nil
}

// targetConfig loads the target repo's own appsec.yml (falling back to
// defaults when absent) and applies the target's registered constraints.
func targetConfig(t targets.Target) (config.Config, error) {
	cfgPath := filepath.Join(t.Path, "appsec.yml")
	var cfg config.Config
	if _, err := os.Stat(cfgPath); err == nil {
		cfg, err = config.Load(cfgPath)
		if err != nil {
			return cfg, fmt.Errorf("target config: %w", err)
		}
	} else {
		cfg = config.Default()
	}
	if len(t.Scanners) > 0 {
		cfg.Scanners = t.Scanners
	}
	if t.Profile != "" {
		cfg.Profile = t.Profile
	}
	return cfg, nil
}
