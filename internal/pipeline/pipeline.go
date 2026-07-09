// Package pipeline is the scan pipeline, extracted from the CLI so the
// `argus scan` command and the console's job queue execute the exact same
// code path: adapter selection → parallel scanners → normalize →
// ignore-filter → correlate → triage (enrichment-only) → risk → compliance →
// optional false-positive exclusion.
//
// Progress reporting is a callback receiving the exact pre-formatted lines
// the CLI historically printed to stderr; the CLI writes them verbatim
// (byte-identical output) and the server appends them to job status. Report
// writing, run saving, the summary line and the severity gate stay with the
// caller: the CLI must write the report before saving, and the server saves
// but never writes reports.
package pipeline

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/zer0d4y5/argus/internal/compliance"
	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/correlate"
	"github.com/zer0d4y5/argus/internal/exploit"
	"github.com/zer0d4y5/argus/internal/llm"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/risk"
	"github.com/zer0d4y5/argus/internal/scanner"
	"github.com/zer0d4y5/argus/internal/triage"
)

// Progress receives one pre-formatted, newline-terminated status line per
// call. It must be safe to call from the goroutine running the pipeline but
// is never called concurrently with itself.
type Progress func(line string)

// Options configure one pipeline run. Config carries everything the scan
// needs (scanners, profile, ignore rules, triage settings, timeouts); Target
// is the directory or file to scan.
type Options struct {
	Target string
	Config config.Config
	// ReportRoot, when set, means Target is a stand-in directory (the
	// diff-scope mirror) whose files are a relative-path-preserving copy of
	// ReportRoot. Findings' paths are rebased from Target onto ReportRoot
	// BEFORE normalization, so fingerprints, ignore_paths, baselines, and
	// dispositions are byte-identical to a scan of ReportRoot itself, and
	// enrichment (triage snippets) reads the real files under ReportRoot.
	ReportRoot string
}

// Result is a completed pipeline run.
type Result struct {
	Findings []model.Finding
}

// Run executes the full scan pipeline. Scanner failures and triage failures
// degrade with a progress warning, never abort the run; a returned error
// means no scan happened at all (invalid profile, no scanners available).
func Run(ctx context.Context, opts Options, progress Progress) (Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	cfg := opts.Config

	if err := scanner.ValidateProfile(cfg.Profile); err != nil {
		return Result{}, fmt.Errorf("invalid profile: %w", err)
	}
	rulesets := scanner.ResolveSemgrepRulesets(cfg.Profile, cfg.SemgrepRules)
	rulesets = validateCustomRulesets(ctx, rulesets, progress)

	adapters, err := SelectAdapters(cfg, rulesets, progress)
	if err != nil {
		return Result{}, err
	}

	rawFindings := RunScanners(ctx, adapters, opts.Target, cfg.TimeoutSec, progress)

	enrichRoot := opts.Target
	if opts.ReportRoot != "" {
		RebaseRawPaths(rawFindings, opts.Target, opts.ReportRoot)
		enrichRoot = opts.ReportRoot
	}
	findings := Enrich(ctx, cfg, enrichRoot, rawFindings, progress)
	return Result{Findings: findings}, nil
}

// RebaseRawPaths rewrites raw findings' file paths as if the scan target had
// been reportRoot instead of scanned: the adapters' convention is that File
// carries the target prefix (CWD-relative), so the scanned prefix is swapped
// for reportRoot's. Both are directories by contract (the CLI enforces it).
// A path that does not carry the scanned prefix is left alone: reporting a
// surprising path honestly beats fabricating one.
func RebaseRawPaths(raws []model.RawFinding, scanned, reportRoot string) {
	from := filepath.ToSlash(scanned)
	to := filepath.ToSlash(reportRoot)
	if to == "." {
		to = ""
	}
	for i := range raws {
		f := filepath.ToSlash(raws[i].File)
		if f == "" {
			continue
		}
		var rel string
		switch {
		case f == from:
			rel = ""
		case strings.HasPrefix(f, from+"/"):
			rel = f[len(from)+1:]
		default:
			continue
		}
		if to != "" {
			rel = path.Join(to, rel)
		}
		raws[i].File = rel
	}
}

// validateCustomRulesets guards the one ruleset kind a user can get wrong: a
// LOCAL rule file/dir. Registry packs pass through untouched. A local rule that
// is missing or malformed is dropped from the list with a clear, specific
// progress warning naming the file and semgrep's own reason, so a typo'd BYO
// rule degrades to "that one rule skipped" rather than an opaque semgrep crash
// that loses the whole SAST pass. If nothing needs validating (the common
// case: packs only), the list is returned unchanged with no semgrep call.
func validateCustomRulesets(ctx context.Context, rulesets []string, progress Progress) []string {
	hasLocal := false
	for _, r := range rulesets {
		if k, err := scanner.ClassifyRuleset(r); err == nil && k == scanner.KindLocalPath {
			hasLocal = true
			break
		}
	}
	if !hasLocal {
		return rulesets
	}
	// baseDir "" resolves relative paths against the CWD, matching how semgrep
	// itself resolves a --config path.
	statuses := scanner.ValidateRulesets(ctx, rulesets, "")
	bad := map[string]string{}
	for _, s := range statuses {
		if !s.OK {
			bad[s.Entry] = s.Message
		}
	}
	if len(bad) == 0 {
		return rulesets
	}
	kept := make([]string, 0, len(rulesets))
	for _, r := range rulesets {
		if msg, isBad := bad[r]; isBad {
			progress(fmt.Sprintf("  ! custom rule skipped: %s", msg))
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// Enrich runs the post-scan half of the pipeline on already-collected raw
// findings: normalize -> ignore-filter -> correlate -> triage seam ->
// risk+band -> compliance -> optional FP exclusion. It is shared by every
// scan source (filesystem adapters via Run, cloud posture via RunCloud) so
// the banding, triage, and compliance contracts are identical regardless of
// where the findings came from. `target` is the triage root (a path for code
// scans, "" for cloud — cloud findings have no source file and triage
// feature-detects that).
func Enrich(ctx context.Context, cfg config.Config, target string, rawFindings []model.RawFinding, progress Progress) []model.Finding {
	if progress == nil {
		progress = func(string) {}
	}

	// Pipeline: normalize -> ignore-filter -> correlate -> triage seam.
	findings := model.Normalize(rawFindings)
	findings, suppressed := model.FilterIgnored(findings, cfg.IgnorePaths, cfg.IgnoreRules)
	if suppressed > 0 {
		progress(fmt.Sprintf("NOTE: %d finding(s) suppressed by ignore rules\n", suppressed))
	}
	findings = correlate.Correlate(findings)

	// Triage is enrichment, never a dependency: any error passes the findings
	// through unmodified with a warning. It must not drop, reorder, or
	// re-rank anything — verdicts and scores are additive fields only.
	triager := buildTriager(ctx, cfg, target, progress)
	if _, isNoop := triager.(triage.Noop); !isNoop {
		if cfg.Triage.MaxFindings > 0 && len(findings) > cfg.Triage.MaxFindings {
			progress(fmt.Sprintf("NOTE: triaging the %d most severe of %d findings (triage.max_findings)\n", cfg.Triage.MaxFindings, len(findings)))
		}
		progress(fmt.Sprintf("==> running AI triage (%s)\n", triager.Name()))
	}
	if triaged, err := triager.Triage(ctx, findings); err != nil {
		progress(fmt.Sprintf("WARN: triage failed, findings pass through unmodified: %v\n", err))
	} else {
		findings = triaged
	}

	// Every finding in every run gets a risk score, LLM or not. Severity is
	// banded from the returned STAGE-2 deterministic score (schema 2.0.0,
	// docs/risk-scoring.md "Severity banding") — never from the stored
	// stage-3 riskScore, so a triage verdict can move the score but never a
	// severity, and never the gate. Re-sort afterwards: reporters rely on
	// severity-descending order, and banding is what severity now means.
	risk.ApplyAndBandWith(findings, ExploitLookup(cfg, progress))
	model.Sort(findings)

	// Compliance mapping is always on: deterministic, hand-curated, cheap.
	// Like triage it is enrichment only — a mapping failure (a build defect
	// in the embedded data) warns and passes findings through unmodified.
	if err := compliance.Apply(findings); err != nil {
		progress(fmt.Sprintf("WARN: compliance mapping failed, findings pass through unmapped: %v\n", err))
	}

	// Opt-in only: dropping LLM-marked false positives is explicit and
	// counted, and applies to both the report and the gate. Default output
	// shows everything, verdicts included.
	if cfg.Triage.ExcludeFP {
		var excluded int
		findings, excluded = ExcludeFalsePositives(findings)
		if excluded > 0 {
			progress(fmt.Sprintf("NOTE: %d LLM-marked false positive(s) excluded from report and gate (--exclude-fp)\n", excluded))
		}
	}

	return findings
}

// buildTriager constructs the configured LLM triager, or Noop when triage is
// disabled or the provider is unreachable — a scan must always complete
// without an LLM. API keys come from the environment only, never appsec.yml.
// ExploitLookup builds the KEV/EPSS enrichment lookup for the risk stage, or
// nil when enrichment is disabled or its data fails to load. A load failure
// warns and falls back to unenriched scoring: exploitation evidence is
// additive, never load-bearing for a scan to succeed.
func ExploitLookup(cfg config.Config, progress Progress) risk.ExploitLookup {
	if !cfg.Exploit.On() {
		return nil
	}
	cat, err := exploit.Load(cfg.Exploit.EPSSFile)
	if err != nil {
		progress(fmt.Sprintf("WARN: exploit enrichment disabled: %v\n", err))
		return nil
	}
	return cat.Signals
}

func buildTriager(ctx context.Context, cfg config.Config, target string, progress Progress) triage.Triager {
	if !cfg.Triage.Enabled {
		return triage.Noop{}
	}

	timeout := time.Duration(cfg.Triage.TimeoutSec) * time.Second
	client := NewLLMClient(cfg)

	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			progress(fmt.Sprintf("NOTE: AI triage disabled: %v\n", err))
			return triage.Noop{}
		}
	}

	return triage.NewLLM(client, triage.Options{
		Root:             target,
		Concurrency:      cfg.Triage.Concurrency,
		MaxFindings:      cfg.Triage.MaxFindings,
		RequestTimeout:   timeout,
		AllowSecretCloud: cfg.Triage.AllowSecretCloud,
	})
}

// NewLLMClient builds the LLM client the config names — transport only, the
// same selection triage uses (the console's explain endpoint shares it so
// provider/model/endpoint always come from the repo config, never a
// request). API keys come from the environment only, never appsec.yml.
func NewLLMClient(cfg config.Config) llm.Client {
	timeout := time.Duration(cfg.Triage.TimeoutSec) * time.Second
	switch cfg.Triage.Provider {
	case "anthropic":
		return llm.NewAnthropic(os.Getenv("ANTHROPIC_API_KEY"), cfg.Triage.Model, timeout)
	default: // config validation only admits ollama|anthropic
		return llm.NewOllama(cfg.Triage.Endpoint, cfg.Triage.Model, timeout)
	}
}

// ExcludeFalsePositives drops LLM-marked false positives. Only reachable via
// the explicit --exclude-fp / triage.exclude_fp opt-in.
func ExcludeFalsePositives(findings []model.Finding) ([]model.Finding, int) {
	kept := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Triage != nil && f.Triage.Verdict == model.VerdictFalsePositive {
			continue
		}
		kept = append(kept, f)
	}
	return kept, len(findings) - len(kept)
}

// SelectAdapters filters the registry by config and availability. The resolved
// semgrep ruleset packs configure the semgrep adapter's coverage. In offline
// mode the packs are rewritten to their cached local files (registry refs not
// in the cache are dropped with a warning) so the semgrep run never touches the
// network; this happens here so both the scan and comply paths behave the same.
func SelectAdapters(cfg config.Config, semgrepRulesets []string, progress Progress) ([]scanner.Adapter, error) {
	offline := cfg.Offline.On()
	if offline {
		cacheDir := scanner.RulesCacheDir(cfg.Offline.CacheDir)
		semgrepRulesets = scanner.ResolveOffline(semgrepRulesets, cacheDir, func(m string) {
			progress("  ! " + m + "\n")
		})
	}
	var active []scanner.Adapter
	for _, a := range scanner.All(semgrepRulesets, offline) {
		if len(cfg.Scanners) > 0 && !nameIn(a.Name(), cfg.Scanners) {
			continue
		}
		if !a.Available() {
			progress(fmt.Sprintf("NOTE: %s not found on PATH — skipping %s scan\n", a.Name(), a.Category()))
			continue
		}
		active = append(active, a)
	}
	if len(active) == 0 {
		return nil, fmt.Errorf("no available scanners to run (install semgrep, gitleaks, trivy, or checkov)")
	}
	return active, nil
}

func nameIn(name string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}

// RunScanners fans out to all adapters in parallel, each under its own
// timeout. One scanner failing (or timing out) never aborts the others; the
// failure is reported via progress and the run continues with partial
// results. Progress calls are serialized under the same mutex protecting the
// findings slice.
func RunScanners(ctx context.Context, adapters []scanner.Adapter, target string, timeoutSec int, progress Progress) []model.RawFinding {
	var (
		mu  sync.Mutex
		raw []model.RawFinding
	)
	emit := func(line string) {
		mu.Lock()
		progress(line)
		mu.Unlock()
	}
	g, gCtx := errgroup.WithContext(ctx)
	for _, a := range adapters {
		g.Go(func() error {
			emit(fmt.Sprintf("==> running %s (%s)\n", a.Name(), a.Category()))
			scanCtx, cancel := context.WithTimeout(gCtx, time.Duration(timeoutSec)*time.Second)
			defer cancel()

			findings, err := a.Scan(scanCtx, target)
			if err != nil {
				emit(fmt.Sprintf("WARN: %s failed: %v\n", a.Name(), err))
				return nil
			}
			mu.Lock()
			raw = append(raw, findings...)
			progress(fmt.Sprintf("%s: %d raw findings\n", a.Name(), len(findings)))
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait() // goroutines only ever return nil; errors are reported above
	return raw
}
