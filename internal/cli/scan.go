package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/leaky-hub/appsec/internal/config"
	"github.com/leaky-hub/appsec/internal/correlate"
	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/report"
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
	scanCmd.Flags().Int("timeout", 0, "Per-scanner timeout in seconds")
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

	adapters, err := selectAdapters(cfg)
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
	if findings, err = (triage.Noop{}).Triage(cmd.Context(), findings); err != nil {
		return fmt.Errorf("triage: %w", err)
	}

	if err := writeReport(cmd, cfg.Format, findings); err != nil {
		return err
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
	if cmd.Flags().Changed("timeout") {
		if v, _ := cmd.Flags().GetInt("timeout"); v > 0 {
			cfg.TimeoutSec = v
		}
	}

	return cfg, cfg.Validate()
}

// selectAdapters filters the registry by config and availability.
func selectAdapters(cfg config.Config) ([]scanner.Adapter, error) {
	var active []scanner.Adapter
	for _, a := range scanner.All() {
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
}
