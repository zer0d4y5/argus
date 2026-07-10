package pipeline

import (
	"context"
	"fmt"

	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/dastscan"
	"github.com/zer0d4y5/argus/internal/model"
)

// DASTOptions configure one dynamic scan.
type DASTOptions struct {
	URL        string
	Templates  []string
	Tags       []string
	Severities []string
	RateLimit  int
	TimeoutSec int
	Config     config.Config
}

// DASTResult is a completed dynamic scan.
type DASTResult struct {
	Findings    []model.Finding
	ToolVersion string
}

// RunDAST executes a dynamic scan through nuclei and the SAME enrichment half
// as a code or cloud scan (Enrich): unified model -> correlate -> triage seam
// -> risk+band -> compliance. The triage root is "" (a DAST finding has no
// source file; the triager feature-detects that, exactly like cloud).
func RunDAST(ctx context.Context, opts DASTOptions, progress Progress) (DASTResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !dastscan.Available() {
		return DASTResult{}, fmt.Errorf("nuclei not found on PATH: install nuclei to run DAST scans")
	}

	scan, err := dastscan.Scan(ctx, dastscan.Options{
		URL:        opts.URL,
		Templates:  opts.Templates,
		Tags:       opts.Tags,
		Severities: opts.Severities,
		RateLimit:  opts.RateLimit,
		TimeoutSec: opts.TimeoutSec,
	}, progress)
	if err != nil {
		return DASTResult{}, err
	}

	findings := Enrich(ctx, opts.Config, "", scan.Raw, progress)
	return DASTResult{Findings: findings, ToolVersion: scan.ToolVersion}, nil
}
