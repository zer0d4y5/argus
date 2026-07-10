package pipeline

import (
	"context"
	"fmt"

	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/scanner"
)

// ImageOptions configure one container image scan.
type ImageOptions struct {
	Ref    string
	Config config.Config
}

// ImageResult is a completed image scan.
type ImageResult struct {
	Findings []model.Finding
}

// RunImage scans a container image through trivy and the SAME enrichment half
// as every other scan (Enrich): unified model -> correlate -> triage seam ->
// risk+band -> compliance. The triage root is "" (image findings have no
// source file in the working tree; the triager feature-detects that, like
// cloud and DAST).
func RunImage(ctx context.Context, opts ImageOptions, progress Progress) (ImageResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !scanner.ImageAvailable() {
		return ImageResult{}, fmt.Errorf("trivy not found on PATH: install trivy to scan container images")
	}

	progress(fmt.Sprintf("==> scanning image %s (trivy)\n", opts.Ref))
	raw, err := scanner.ScanImage(ctx, opts.Ref)
	if err != nil {
		return ImageResult{}, err
	}
	progress(fmt.Sprintf("trivy image: %d raw finding(s)\n", len(raw)))

	findings := Enrich(ctx, opts.Config, "", raw, progress)
	return ImageResult{Findings: findings}, nil
}
