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

	"github.com/zer0d4y5/argus/internal/baseline"
	"github.com/zer0d4y5/argus/internal/compliance"
	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/coverage"
	"github.com/zer0d4y5/argus/internal/diffscope"
	"github.com/zer0d4y5/argus/internal/disposition"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/report"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/snippet"
	"github.com/zer0d4y5/argus/internal/targets"
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
	scanCmd.Flags().Bool("offline", false, "Use only local rules (embedded curated + `argus rules sync` cache + local BYO); never fetch registry packs")
	scanCmd.Flags().String("baseline", "", "Gate only on findings NEW since this baseline file; known findings stay in the report")
	scanCmd.Flags().String("write-baseline", "", "Write the current findings' fingerprints to this baseline file and exit without gating")
	scanCmd.Flags().Bool("pr-comments", false, "Post the gated findings as review comments on the GitHub pull request (pairs with --baseline; advisory, never changes the exit code)")
	scanCmd.Flags().Int("pr", 0, "Pull request number for --pr-comments (default: auto-detected in GitHub Actions)")
	scanCmd.Flags().String("diff-base", "", "Scan only files changed since this git ref (merge-base aware, e.g. origin/main); falls back to a full scan with a warning if the ref cannot be resolved")
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

	// Incremental scope: scan a temp mirror of just the files changed since
	// the base ref. The mirror preserves relative paths, so file paths, line
	// numbers, and therefore fingerprints match a full scan and baselines,
	// dispositions, and PR comments compose unchanged. Every failure path
	// falls back to the FULL scan with a warning: fail-safe is more
	// coverage, never silently less.
	scanTarget := target
	skipScan := false
	if base, _ := cmd.Flags().GetString("diff-base"); base != "" {
		if wb, _ := cmd.Flags().GetString("write-baseline"); wb != "" {
			return fmt.Errorf("--write-baseline records the full backlog; do not combine it with --diff-base")
		}
		if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
			return fmt.Errorf("--diff-base needs a directory target")
		}
		files, err := diffscope.ChangedFiles(cmd.Context(), target, base)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "WARN: %v; running a full scan instead\n", err)
		case len(files) == 0:
			fmt.Fprintf(os.Stderr, "NOTE: diff scope vs %s: no changed files, nothing to scan\n", base)
			skipScan = true
		default:
			mirror, skipped, cleanup, err := diffscope.Mirror(target, files)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN: %v; running a full scan instead\n", err)
			} else {
				defer cleanup()
				scanTarget = mirror
				fmt.Fprintf(os.Stderr, "NOTE: diff scope vs %s: scanning %d changed file(s)\n", base, len(files)-len(skipped))
				for _, s := range skipped {
					fmt.Fprintf(os.Stderr, "NOTE: diff scope skipped %s (deleted, symlink, or outside the scan root)\n", s)
				}
			}
		}
	}

	var findings []model.Finding
	if !skipScan {
		popts := pipeline.Options{Target: scanTarget, Config: cfg}
		if scanTarget != target {
			popts.ReportRoot = target
		}
		res, err := pipeline.Run(cmd.Context(), popts, func(line string) {
			fmt.Fprint(os.Stderr, line)
		})
		if err != nil {
			return err
		}
		findings = res.Findings
	}

	if err := writeReport(cmd, cfg.Format, findings); err != nil {
		return err
	}

	// Opt-in run history for the console. A save failure is a warning, never a
	// scan failure — the report has already been written successfully.
	if save, _ := cmd.Flags().GetBool("save"); save {
		if meta, err := saveRun(target, scanTarget, findings); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: --save failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "==> saved run %s to %s\n", meta.ID, meta.Path)
		}
	}

	printSummary(findings)

	// --write-baseline establishes a baseline from this run and exits without
	// gating: recording the current backlog is a setup action, never a CI
	// failure. It runs after the report/save so the user sees exactly what is
	// being baselined.
	if wb, _ := cmd.Flags().GetString("write-baseline"); wb != "" {
		if bl, _ := cmd.Flags().GetString("baseline"); bl != "" {
			return fmt.Errorf("use --baseline OR --write-baseline, not both")
		}
		bf := baseline.FromFindings(findings, target, time.Now())
		if err := baseline.Write(wb, bf); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "==> wrote baseline: %d finding(s) to %s\n", bf.Count, wb)
		return nil
	}

	// The gate decision comes last, after the report is safely written.
	// A baseline restricts the gate to findings NEW since it was written: known
	// findings stay in the report but never fail CI, so a repo with a backlog
	// can still block anything newly introduced. Baseline filtering happens
	// before disposition exclusion so both narrowings compose.
	gated := findings
	if bl, _ := cmd.Flags().GetString("baseline"); bl != "" {
		set, err := baseline.Load(bl)
		if err != nil {
			return err
		}
		newF, known := baseline.Partition(findings, set)
		gated = newF
		fmt.Fprintf(os.Stderr, "NOTE: baseline %s: %d new, %d known (gating on new only)\n", bl, len(newF), len(known))
	}
	strict, _ := cmd.Flags().GetBool("strict-gate")
	if !strict {
		var suppressed int
		gated, suppressed = excludeDispositioned(scanRoot(target), gated)
		if suppressed > 0 {
			fmt.Fprintf(os.Stderr, "NOTE: %d finding(s) excluded from the gate by disposition (accepted-risk/false-positive); --strict-gate to include them\n", suppressed)
		}
	}
	// PR comments see exactly the set the gate judges (new since baseline,
	// disposition-filtered), so a comment and a red check always agree on
	// what the pull request adds. Advisory: posting never moves the exit code.
	if on, _ := cmd.Flags().GetBool("pr-comments"); on {
		postPRComments(cmd, cfg, gated)
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
	if cmd.Flags().Changed("offline") {
		v, _ := cmd.Flags().GetBool("offline")
		cfg.Offline.Enabled = &v
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
// scanned is the directory the scanners actually saw: the target itself, or
// the diff-scope mirror. Coverage accounting walks scanned (a scoped run
// must not claim it looked at the whole repo), while snippets and the run
// store resolve against the real target (the mirror preserves relative
// paths, so both name the same files).
func saveRun(target, scanned string, findings []model.Finding) (runstore.RunMeta, error) {
	snippet.Capture(target, findings)
	root := target
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		root = filepath.Dir(target)
	}
	// Skip accounting (schema 2.0.0): what the scan did NOT look at, stored
	// with the run and surfaced in the console. Save-path only, like
	// snippets — stdout reports are unchanged.
	cov := coverage.Account(scanned)
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
