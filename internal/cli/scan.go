package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/leaky-hub/appsec/internal/config"
	"github.com/leaky-hub/appsec/internal/correlate"
	"github.com/leaky-hub/appsec/internal/llm"
	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/report"
	"github.com/leaky-hub/appsec/internal/risk"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/scanner"
	"github.com/leaky-hub/appsec/internal/triage"
)

// errGateFailed is the sentinel for "scan succeeded, findings exceed the
// configured severity gate". It maps to exit code 1 in Execute.
var errGateFailed = errors.New("severity gate exceeded")

func init() {
	scanCmd.Flags().StringP("format", "f", "", "Output format: sarif, markdown, or json (default from config)")
	scanCmd.Flags().String("fail-severity", "", "Fail if findings meet or exceed this severity (critical|high|medium|low|info|none)")
	scanCmd.Flags().StringP("config", "c", "", "Path to appsec.yml configuration file")
	scanCmd.Flags().StringP("output", "o", "", "Output file path (default is stdout)")
	scanCmd.Flags().String("scanners", "", "Comma-separated list of scanner names to run (e.g., semgrep,gitleaks)")
	scanCmd.Flags().String("profile", "", "Scan profile: fast, standard, or max (default standard; config: profile)")
	scanCmd.Flags().Bool("save", false, "Save the JSON report to .appsec/runs/<timestamp>.json in the scanned repo for the console")
	scanCmd.Flags().Int("timeout", 0, "Per-scanner timeout in seconds")
	scanCmd.Flags().Bool("triage", false, "Enable AI triage of findings (config: triage.enabled)")
	scanCmd.Flags().Bool("exclude-fp", false, "Exclude LLM-marked false positives from the report and severity gate (opt-in)")
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run security scanners on the target path",
	Long: `Runs configured security scanners against the specified target directory or file.
Defaults to scanning the current directory if no path is provided.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}

	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	gate, err := model.ParseGate(cfg.FailSeverity)
	if err != nil {
		return fmt.Errorf("invalid fail-severity: %w", err)
	}

	if err := scanner.ValidateProfile(cfg.Profile); err != nil {
		return fmt.Errorf("invalid profile: %w", err)
	}
	rulesets := scanner.ResolveSemgrepRulesets(cfg.Profile, cfg.SemgrepRules)

	adapters, err := selectAdapters(cfg, rulesets)
	if err != nil {
		return err
	}

	rawFindings := runScanners(cmd.Context(), adapters, target, cfg.TimeoutSec)

	// Pipeline: normalize -> ignore-filter -> correlate -> triage seam.
	findings := model.Normalize(rawFindings)
	findings, suppressed := model.FilterIgnored(findings, cfg.IgnorePaths, cfg.IgnoreRules)
	if suppressed > 0 {
		fmt.Fprintf(os.Stderr, "NOTE: %d finding(s) suppressed by ignore rules\n", suppressed)
	}
	findings = correlate.Correlate(findings)

	// Triage is enrichment, never a dependency: any error passes the findings
	// through unmodified with a warning. It must not drop, reorder, or
	// re-rank anything — verdicts and scores are additive fields only.
	triager := buildTriager(cmd.Context(), cfg, target)
	if _, isNoop := triager.(triage.Noop); !isNoop {
		if cfg.Triage.MaxFindings > 0 && len(findings) > cfg.Triage.MaxFindings {
			fmt.Fprintf(os.Stderr, "NOTE: triaging the %d most severe of %d findings (triage.max_findings)\n", cfg.Triage.MaxFindings, len(findings))
		}
		fmt.Fprintf(os.Stderr, "==> running AI triage (%s)\n", triager.Name())
	}
	if triaged, err := triager.Triage(cmd.Context(), findings); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: triage failed, findings pass through unmodified: %v\n", err)
	} else {
		findings = triaged
	}

	// Every finding in every run gets a risk score, LLM or not.
	risk.Apply(findings)

	// Opt-in only: dropping LLM-marked false positives is explicit and
	// counted, and applies to both the report and the gate. Default output
	// shows everything, verdicts included.
	if cfg.Triage.ExcludeFP {
		var excluded int
		findings, excluded = excludeFalsePositives(findings)
		if excluded > 0 {
			fmt.Fprintf(os.Stderr, "NOTE: %d LLM-marked false positive(s) excluded from report and gate (--exclude-fp)\n", excluded)
		}
	}

	if err := writeReport(cmd, cfg.Format, findings); err != nil {
		return err
	}

	// Opt-in run history for the console. A save failure is a warning, never a
	// scan failure — the report has already been written successfully.
	if save, _ := cmd.Flags().GetBool("save"); save {
		if meta, err := saveRun(target, findings); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: --save failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "==> saved run %s to %s\n", meta.ID, meta.Path)
		}
	}

	printSummary(findings)

	// The gate decision comes last, after the report is safely written.
	if model.GateExceeded(findings, gate) {
		return errGateFailed
	}
	return nil
}

// loadConfig loads appsec.yml and applies flag overrides for flags the user
// actually set.
func loadConfig(cmd *cobra.Command) (config.Config, error) {
	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err != nil {
		return cfg, err
	}

	if cmd.Flags().Changed("format") {
		if v, _ := cmd.Flags().GetString("format"); v != "" {
			cfg.Format = v
		}
	}
	if cmd.Flags().Changed("fail-severity") {
		if v, _ := cmd.Flags().GetString("fail-severity"); v != "" {
			cfg.FailSeverity = v
		}
	}
	if cmd.Flags().Changed("scanners") {
		if v, _ := cmd.Flags().GetString("scanners"); v != "" {
			cfg.Scanners = strings.Split(v, ",")
			for i := range cfg.Scanners {
				cfg.Scanners[i] = strings.TrimSpace(cfg.Scanners[i])
			}
		}
	}
	if cmd.Flags().Changed("profile") {
		if v, _ := cmd.Flags().GetString("profile"); v != "" {
			cfg.Profile = v
		}
	}
	if cmd.Flags().Changed("timeout") {
		if v, _ := cmd.Flags().GetInt("timeout"); v > 0 {
			cfg.TimeoutSec = v
		}
	}
	if cmd.Flags().Changed("triage") {
		cfg.Triage.Enabled, _ = cmd.Flags().GetBool("triage")
	}
	if cmd.Flags().Changed("exclude-fp") {
		cfg.Triage.ExcludeFP, _ = cmd.Flags().GetBool("exclude-fp")
	}

	return cfg, cfg.Validate()
}

// buildTriager constructs the configured LLM triager, or Noop when triage is
// disabled or the provider is unreachable — a scan must always complete
// without an LLM. API keys come from the environment only, never appsec.yml.
func buildTriager(ctx context.Context, cfg config.Config, target string) triage.Triager {
	if !cfg.Triage.Enabled {
		return triage.Noop{}
	}

	timeout := time.Duration(cfg.Triage.TimeoutSec) * time.Second
	var client llm.Client
	switch cfg.Triage.Provider {
	case "anthropic":
		client = llm.NewAnthropic(os.Getenv("ANTHROPIC_API_KEY"), cfg.Triage.Model, timeout)
	default: // config validation only admits ollama|anthropic
		client = llm.NewOllama(cfg.Triage.Endpoint, cfg.Triage.Model, timeout)
	}

	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "NOTE: AI triage disabled: %v\n", err)
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

// excludeFalsePositives drops LLM-marked false positives. Only reachable via
// the explicit --exclude-fp / triage.exclude_fp opt-in.
func excludeFalsePositives(findings []model.Finding) ([]model.Finding, int) {
	kept := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Triage != nil && f.Triage.Verdict == model.VerdictFalsePositive {
			continue
		}
		kept = append(kept, f)
	}
	return kept, len(findings) - len(kept)
}

// saveRun writes the current findings as a timestamped run file under the
// scanned repo's .appsec/runs directory, for the `appsec serve` console. The
// repo root is the scan target directory (or the file's directory).
func saveRun(target string, findings []model.Finding) (runstore.RunMeta, error) {
	root := target
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		root = filepath.Dir(target)
	}
	return runstore.ForRepo(root).Save(findings, time.Now())
}

// selectAdapters filters the registry by config and availability. The resolved
// semgrep ruleset packs configure the semgrep adapter's coverage.
func selectAdapters(cfg config.Config, semgrepRulesets []string) ([]scanner.Adapter, error) {
	var active []scanner.Adapter
	for _, a := range scanner.All(semgrepRulesets) {
		if len(cfg.Scanners) > 0 && !nameIn(a.Name(), cfg.Scanners) {
			continue
		}
		if !a.Available() {
			fmt.Fprintf(os.Stderr, "NOTE: %s not found on PATH — skipping %s scan\n", a.Name(), a.Category())
			continue
		}
		active = append(active, a)
	}
	if len(active) == 0 {
		return nil, fmt.Errorf("no available scanners to run (install semgrep, gitleaks, or trivy)")
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

// runScanners fans out to all adapters in parallel, each under its own
// timeout. One scanner failing (or timing out) never aborts the others; the
// failure is reported on stderr and the run continues with partial results.
func runScanners(ctx context.Context, adapters []scanner.Adapter, target string, timeoutSec int) []model.RawFinding {
	var (
		mu  sync.Mutex
		raw []model.RawFinding
	)
	g, gCtx := errgroup.WithContext(ctx)
	for _, a := range adapters {
		g.Go(func() error {
			fmt.Fprintf(os.Stderr, "==> running %s (%s)\n", a.Name(), a.Category())
			scanCtx, cancel := context.WithTimeout(gCtx, time.Duration(timeoutSec)*time.Second)
			defer cancel()

			findings, err := a.Scan(scanCtx, target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN: %s failed: %v\n", a.Name(), err)
				return nil
			}
			mu.Lock()
			raw = append(raw, findings...)
			mu.Unlock()
			fmt.Fprintf(os.Stderr, "%s: %d raw findings\n", a.Name(), len(findings))
			return nil
		})
	}
	_ = g.Wait() // goroutines only ever return nil; errors are reported above
	return raw
}

// writeReport writes findings in the chosen format, to --output or stdout.
// A file is closed (and its error checked) before the caller decides the
// gate: a report that failed to flush must fail the run loudly, not ride
// along under a gate exit code.
func writeReport(cmd *cobra.Command, format string, findings []model.Finding) error {
	var w io.Writer = os.Stdout
	var file *os.File
	if outputPath, _ := cmd.Flags().GetString("output"); outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		file = f
		w = f
	}

	var err error
	switch strings.ToLower(format) {
	case "sarif":
		err = report.WriteSARIF(w, findings)
	case "json":
		err = report.WriteJSON(w, findings)
	case "markdown", "":
		err = report.WriteMarkdown(w, findings)
	default:
		err = fmt.Errorf("unsupported format: %s", format)
	}
	if file != nil {
		if cerr := file.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("failed to write output file: %w", cerr)
		}
	}
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func printSummary(findings []model.Finding) {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity.String()]++
	}
	var parts []string
	for _, name := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[name] > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", name, counts[name]))
		}
	}
	summary := strings.Join(parts, ", ")
	if summary == "" {
		summary = "no findings"
	}
	fmt.Fprintf(os.Stderr, "\nSummary: %d total finding(s) (%s)\n", len(findings), summary)

	verdicts := map[string]int{}
	for _, f := range findings {
		if f.Triage != nil {
			verdicts[f.Triage.Verdict]++
		}
	}
	if len(verdicts) > 0 {
		fmt.Fprintf(os.Stderr, "Triage: %d true-positive, %d false-positive, %d uncertain\n",
			verdicts[model.VerdictTruePositive], verdicts[model.VerdictFalsePositive], verdicts[model.VerdictUncertain])
	}
}
