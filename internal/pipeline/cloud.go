package pipeline

import (
	"context"
	"fmt"

	"github.com/leaky-hub/argus/internal/cloudscan"
	"github.com/leaky-hub/argus/internal/config"
	"github.com/leaky-hub/argus/internal/model"
)

// CloudOptions configure one cloud posture run.
type CloudOptions struct {
	Provider string
	Profile  string
	Regions  []string
	Account  string
	Config   config.Config
}

// CloudResult is a completed cloud posture run: the enriched findings plus
// the posture counts (fail/pass/manual) — a posture assessment reports how
// many checks passed, not only how many failed.
type CloudResult struct {
	Findings []model.Finding
	Failed   int
	Passed   int
	Manual   int
	// ToolVersion is the prowler release that produced the run (provenance
	// for the saved run document); may be empty when the probe failed.
	ToolVersion string
}

// RunCloud executes a cloud posture scan through prowler and the SAME
// enrichment half as a code scan (Enrich): unified model → correlate →
// triage seam → risk+band → compliance. The credential is a validated
// profile NAME resolved inside the prowler child; no credential material
// enters this function, its progress output, or its results.
//
// The triage root is "" — cloud findings have no source file, so no snippet
// or explain-from-source path applies; the triager feature-detects that.
func RunCloud(ctx context.Context, opts CloudOptions, progress Progress) (CloudResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !cloudscan.Available() {
		return CloudResult{}, fmt.Errorf("prowler not found on PATH — install prowler to run cloud posture scans")
	}

	scan, err := cloudscan.Scan(ctx, cloudscan.Options{
		Provider: opts.Provider,
		Profile:  opts.Profile,
		Regions:  opts.Regions,
		Account:  opts.Account,
	}, progress)
	if err != nil {
		return CloudResult{}, err
	}

	findings := Enrich(ctx, opts.Config, "", scan.Raw, progress)
	return CloudResult{
		Findings:    findings,
		Failed:      scan.Failed,
		Passed:      scan.Passed,
		Manual:      scan.Manual,
		ToolVersion: scan.ToolVersion,
	}, nil
}
