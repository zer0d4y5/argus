// Package triage is the seam for AI-backed finding triage (Phase 2).
// Phase 1 wires the interface through the pipeline but ships only a no-op
// implementation, so the scan path never depends on an LLM being reachable.
package triage

import (
	"context"

	"github.com/zer0d4y5/argus/internal/model"
)

// Triager enriches findings in place with a triage verdict (and later a risk
// score). Implementations must be side-effect free on error: if triage fails,
// findings pass through unmodified — triage may never drop or reorder them.
type Triager interface {
	Name() string
	Triage(ctx context.Context, findings []model.Finding) ([]model.Finding, error)
}

// Noop is the Phase 1 default: findings pass through untouched.
type Noop struct{}

func (Noop) Name() string { return "noop" }

func (Noop) Triage(_ context.Context, findings []model.Finding) ([]model.Finding, error) {
	return findings, nil
}
