package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/leaky-hub/argus/internal/compliance"
	"github.com/leaky-hub/argus/internal/config"
	"github.com/leaky-hub/argus/internal/coverage"
	"github.com/leaky-hub/argus/internal/disposition"
	"github.com/leaky-hub/argus/internal/model"
	"github.com/leaky-hub/argus/internal/pipeline"
	"github.com/leaky-hub/argus/internal/report"
	"github.com/leaky-hub/argus/internal/runstore"
	"github.com/leaky-hub/argus/internal/snippet"
	"github.com/leaky-hub/argus/internal/targets"
)

// errGateFailed is the sentinel for "scan succeeded, findings exceed the
// configured severity gate". It maps to exit code 1 in Execute.
var errGateFailed = errors.New("severity gate exceeded")

func init() {
	scanCmd.Flags().StringP("format", "f", "", "Output format: sarif, markdown, json, or html (default from config)")
	scanCmd.Flags().String("fail-severity", "", "Fail if findings meet or exceed this severity (critical|high|medium|low|info|none)")
	scanCmd.Flags().StringP("config", "c", "", "Path to argus.yml (or appsec.yml) configuration file")
	scanCmd.Flags().StringP("output", "o", "", "Output file path (default is stdout)")
	scanCmd.Flags().String("scanners", "", "Comma-separated list of scanner names to run (e.g., semgrep,gitleaks)")
	scanCmd.Flags().String("profile", "", "Scan profile: fast, standard, or max (default standard; config: profile)")
	scanCmd.Flags().Bool("save", false, "Save the JSON report to .appsec/runs/<timestamp>.json in the scanned repo for the console")
	scanCmd.Flags().Int("timeout", 0, "Per-scanner timeout in seconds")
	scanCmd.Flags().Bool("triage", false, "Enable AI triage of findings (config: triage.enabled)")
	scanCmd.Flags().Bool("exclude-fp", false, "Exclude LLM-marked false positives from the report and severity gate (opt-in)")
	scanCmd.Flags().Bool("strict-gate", false, "Gate on ALL findings, ignoring accepted-risk/false-positive dispositions (default: dispositioned findings don't fail the gate)")
	scanCmd.Flags().String("frameworks", "", "Comma-separated compliance frameworks to focus on (narrows scanners to the relevant set; see `argus comply`)")
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run security scanners on the target path",
	Long: `Runs configured security scanners against the specified target directory or file.
Defaults to scanning the current directory if no path is provided.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

// runScan is a thin wrapper over pipeline.Run: it parses flags into a config,
// streams the pipeline's progress lines verbatim to stderr (byte-identical to
// the pre-extraction output), then handles the CLI-only concerns — report
// writing, optional run saving, the summary line, and the severity gate.
func runScan(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}

	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	// Compliance focus (docs/console-ops.md S6): a closed-enum validation
	// plus scanner narrowing through the curated relevance table — the same
	// helper the console uses, applied BEFORE the pipeline so the shared
	// pipeline itself is untouched.
	if v, _ := cmd.Flags().GetString("frameworks"); v != "" {
		var fws []string
		for _, f := range strings.Split(v, ",") {
			fws = append(fws, strings.TrimSpace(f))
		}
		effective := cfg.Scanners
		if len(effective) == 0 {
			effective = targets.KnownScanners()
		}
		narrowed, err := compliance.NarrowScanners(effective, fws)
		if err != nil {
			return err
		}
		cfg.Scanners = narrowed
		fmt.Fprintf(os.Stderr, "NOTE: framework focus (%s) narrows scanners to: %s\n", strings.Join(fws, ","), strings.Join(narrowed, ", "))
	}

	gate, err := model.ParseGate(cfg.FailSeverity)
	if err != nil {
		return fmt.Errorf("invalid fail-severity: %w", err)
	}

	res, err := pipeline.Run(cmd.Context(), pipeline.Options{Target: target, Config: cfg}, func(line string) {
		fmt.Fprint(os.Stderr, line)
	})
	if err != nil {
		return err
	}
	findings := res.Findings

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
	// Findings a human dispositioned accepted-risk or false-positive (in the
	// scanned tree's .appsec/dispositions.json, e.g. via the console) are
	// excluded from the gate by default — accepted risk stops failing CI but
	// stays in the report. --strict-gate gates on everything.
	gated := findings
	strict, _ := cmd.Flags().GetBool("strict-gate")
	if !strict {
		var suppressed int
		gated, suppressed = excludeDispositioned(scanRoot(target), findings)
		if suppressed > 0 {
			fmt.Fprintf(os.Stderr, "NOTE: %d finding(s) excluded from the gate by disposition (accepted-risk/false-positive); --strict-gate to include them\n", suppressed)
		}
	}
	if model.GateExceeded(gated, gate) {
		return errGateFailed
	}
	return nil
}

// scanRoot is the directory whose .appsec holds a scan's run/disposition
// history: the target dir, or the file's directory for a single-file scan.
func scanRoot(target string) string {
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		return filepath.Dir(target)
	}
	return target
}

// excludeDispositioned returns the findings that still count toward the gate
// (dropping accepted-risk / false-positive dispositions from root's store) and
// the number suppressed. A missing store suppresses nothing.
func excludeDispositioned(root string, findings []model.Finding) ([]model.Finding, int) {
	return excludeDispositionedAt(filepath.Join(root, ".appsec"), findings)
}

// excludeDispositionedAt is the shared gate-suppression step, taking the
// disposition directory directly so the code and cloud paths (whose stores sit
// under different roots) apply identical semantics. A missing store suppresses
// nothing.
func excludeDispositionedAt(dispDir string, findings []model.Finding) ([]model.Finding, int) {
	all, err := disposition.At(dispDir).All()
	if err != nil || len(all) == 0 {
		return findings, 0
	}
	kept := make([]model.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		if rec, ok := all[f.ID]; ok && disposition.GateSuppressed(rec.Status) {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
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

// saveRun writes the current findings as a timestamped run file under the
// scanned repo's .appsec/runs directory, for the `argus serve` console. The
// repo root is the scan target directory (or the file's directory).
// Snippets (schema 1.4.0) are captured only on the save path: the stdout
// report is unchanged, run files gain the code frames the console renders.
func saveRun(target string, findings []model.Finding) (runstore.RunMeta, error) {
	snippet.Capture(target, findings)
	root := target
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		root = filepath.Dir(target)
	}
	// Skip accounting (schema 2.0.0): what the scan did NOT look at, stored
	// with the run and surfaced in the console. Save-path only, like
	// snippets — stdout reports are unchanged.
	cov := coverage.Account(target)
	return runstore.ForRepo(root).SaveWithCoverage(findings, &cov, time.Now())
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
	case "html":
		err = report.WriteHTML(w, findings, report.HTMLMeta{GeneratedAt: time.Now().Format("2006-01-02 15:04 MST")})
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
