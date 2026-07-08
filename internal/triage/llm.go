package triage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zer0d4y5/argus/internal/llm"
	"github.com/zer0d4y5/argus/internal/model"
)

// Options tunes the LLM triager. Zero values get safe defaults in NewLLM.
type Options struct {
	Root             string        // scan target root; source snippets are read only from inside it
	Concurrency      int           // parallel LLM requests
	MaxFindings      int           // cap on findings sent to the LLM per run; 0 = all
	RequestTimeout   time.Duration // per-finding completion timeout
	AllowSecretCloud bool          // explicit opt-in: SECRET findings may go to a non-local provider
}

// LLM is the Phase 2 Triager. Contract (see Triager): it never drops or
// reorders findings, and any failure — provider down, timeout, garbage
// output — degrades that finding to an "uncertain" verdict or leaves it
// untouched; the scan never fails because triage did.
type LLM struct {
	client llm.Client
	opts   Options
}

func NewLLM(client llm.Client, opts Options) *LLM {
	if opts.Concurrency < 1 {
		opts.Concurrency = 4
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 90 * time.Second
	}
	if opts.Root == "" {
		opts.Root = "."
	}
	return &LLM{client: client, opts: opts}
}

func (t *LLM) Name() string { return "llm/" + t.client.Name() }

// Triage enriches findings[i].Triage in place on a copied slice, strictly by
// index: the output always has the same length and order as the input.
// Findings arrive sorted most-severe-first, so a MaxFindings cap spends the
// LLM budget on the worst findings.
func (t *LLM) Triage(ctx context.Context, findings []model.Finding) ([]model.Finding, error) {
	if len(findings) == 0 {
		return findings, nil
	}

	out := make([]model.Finding, len(findings))
	copy(out, findings)

	limit := len(out)
	if t.opts.MaxFindings > 0 && limit > t.opts.MaxFindings {
		limit = t.opts.MaxFindings
	}

	sem := make(chan struct{}, t.opts.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < limit; i++ {
		// Privacy gate: SECRET findings never leave this machine unless the
		// user opted in per-config. No verdict is set — the finding keeps its
		// heuristic risk score and full severity.
		secret := out[i].Category == model.CategorySecret
		if secret && !t.client.Local() && !t.opts.AllowSecretCloud {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, f model.Finding, withSnippet bool) {
			defer wg.Done()
			defer func() { <-sem }()
			tr := t.triageOne(ctx, f, withSnippet)
			out[i].Triage = &tr
		}(i, out[i], !secret)
	}
	wg.Wait()

	// A canceled run must not ship partial enrichment: pass the input through
	// unmodified, per the Triager contract.
	if err := ctx.Err(); err != nil {
		return findings, err
	}
	return out, nil
}

// triageOne runs the full per-finding path: bundle, prompt, complete, parse.
// It always returns a usable Triage value; failures yield "uncertain" with a
// short operator-facing note (never raw model output) as the rationale.
func (t *LLM) triageOne(ctx context.Context, f model.Finding, withSnippet bool) model.Triage {
	uncertain := func(note string) model.Triage {
		return model.Triage{
			Verdict:    model.VerdictUncertain,
			Confidence: 0,
			Rationale:  note,
			Model:      t.client.Name(),
		}
	}

	nonce, err := newNonce()
	if err != nil {
		return uncertain("triage skipped: no randomness source")
	}

	snippet := ""
	if withSnippet {
		// Unreadable or root-escaping paths degrade to metadata-only triage;
		// the prompt tells the model context is missing.
		snippet, err = extractSnippet(t.opts.Root, f)
		if err != nil {
			snippet = ""
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, t.opts.RequestTimeout)
	defer cancel()
	raw, err := t.client.Complete(reqCtx, llm.Request{
		System:      systemPrompt(nonce),
		User:        buildUserPrompt(f, snippet, withSnippet, nonce),
		MaxTokens:   400,
		Temperature: 0,
		ForceJSON:   true,
	})
	if err != nil {
		return uncertain(fmt.Sprintf("triage failed: %.120s", err.Error()))
	}

	tr, err := parseVerdict(raw)
	if err != nil {
		return uncertain("triage failed: unparseable model output")
	}
	tr.Model = t.client.Name()
	return tr
}
