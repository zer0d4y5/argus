package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/dastscan"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/runstore"
)

func init() {
	dastCmd.Flags().StringP("format", "f", "", "Output format: sarif, markdown, or json (default from config)")
	dastCmd.Flags().String("fail-severity", "", "Fail if findings meet or exceed this severity (critical|high|medium|low|info|none)")
	dastCmd.Flags().StringP("config", "c", "", "Path to argus.yml (or appsec.yml) configuration file")
	dastCmd.Flags().StringP("output", "o", "", "Output file path (default is stdout)")
	dastCmd.Flags().String("templates", "", "Comma-separated nuclei templates (files, dirs, or ids); default is nuclei's installed set")
	dastCmd.Flags().String("tags", "", "Comma-separated nuclei tag filter (e.g. misconfig,exposure,cve)")
	dastCmd.Flags().String("severity", "", "Comma-separated nuclei severity filter (info,low,medium,high,critical)")
	dastCmd.Flags().Int("rate-limit", 0, "Max requests per second (0 = nuclei default)")
	dastCmd.Flags().Int("timeout", 0, "Whole-scan timeout in seconds (0 = no limit)")
	dastCmd.Flags().Bool("triage", false, "Enable AI triage of findings (config: triage.enabled)")
	dastCmd.Flags().Bool("exclude-fp", false, "Exclude LLM-marked false positives from the report and severity gate (opt-in)")
	dastCmd.Flags().Bool("save", false, "Save the run under .appsec/dast/<target>/runs for the console")
	dastCmd.Flags().Bool("strict-gate", false, "Gate on ALL findings, ignoring accepted-risk/false-positive dispositions (default: dispositioned findings don't fail the gate)")
	rootCmd.AddCommand(dastCmd)
}

var dastCmd = &cobra.Command{
	Use:   "dast <url>",
	Short: "Run a dynamic application security test (nuclei) against a running target",
	Long: `Scans a running web target with nuclei and maps the results into the unified
findings model (category DAST): banded severity, risk signals, and compliance
mapping, in the same pipeline as code and cloud findings.

The target is a URL you are authorized to test. nuclei runs with its OOB
callout server and update check disabled, so a scan performs no network
callouts beyond requests to the target itself. Findings carry the weakness
identity and the matched URL, never the target's response bodies.

  argus dast https://staging.example.com
  argus dast https://staging.example.com --tags misconfig,exposure --severity medium,high,critical
  argus dast https://staging.example.com --templates cves/ --rate-limit 50 --fail-severity high`,
	Args: cobra.ExactArgs(1),
	RunE: runDAST,
}

func runDAST(cmd *cobra.Command, args []string) error {
	target := args[0]
	if err := dastscan.ValidateURL(target); err != nil {
		return err
	}

	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	gate, err := model.ParseGate(cfg.FailSeverity)
	if err != nil {
		return fmt.Errorf("invalid fail-severity: %w", err)
	}

	timeoutSec, _ := cmd.Flags().GetInt("timeout")
	rateLimit, _ := cmd.Flags().GetInt("rate-limit")
	res, err := pipeline.RunDAST(cmd.Context(), pipeline.DASTOptions{
		URL:        target,
		Templates:  splitCSV(cmd, "templates"),
		Tags:       splitCSV(cmd, "tags"),
		Severities: splitCSV(cmd, "severity"),
		RateLimit:  rateLimit,
		TimeoutSec: timeoutSec,
		Config:     cfg,
	}, func(line string) { fmt.Fprint(os.Stderr, line) })
	if err != nil {
		return err
	}
	findings := res.Findings

	if err := writeReport(cmd, cfg.Format, findings); err != nil {
		return err
	}

	if save, _ := cmd.Flags().GetBool("save"); save {
		if meta, err := saveDASTRun(target, findings, res.ToolVersion); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: --save failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "==> saved run %s to %s\n", meta.ID, meta.Path)
		}
	}

	printSummary(findings)

	// Disposition suppression, same as code and cloud scans: a risk accepted
	// in the console (stored beside this target's DAST runs) stops failing CI
	// but stays in the report. --strict-gate gates on everything.
	gated := findings
	if strict, _ := cmd.Flags().GetBool("strict-gate"); !strict {
		base, err := os.Getwd()
		if err != nil {
			return err
		}
		dispDir := filepath.Join(base, ".appsec", "dast", dastTargetDir(target))
		var suppressed int
		gated, suppressed = excludeDispositionedAt(dispDir, findings)
		if suppressed > 0 {
			fmt.Fprintf(os.Stderr, "NOTE: %d finding(s) excluded from the gate by disposition (accepted-risk/false-positive); --strict-gate to include them\n", suppressed)
		}
	}

	if model.GateExceeded(gated, gate) {
		return errGateFailed
	}
	return nil
}

// splitCSV reads a comma-separated flag into a trimmed, non-empty slice.
func splitCSV(cmd *cobra.Command, name string) []string {
	v, _ := cmd.Flags().GetString(name)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// saveDASTRun stores a DAST run under a per-target directory, mirroring cloud
// runs: there is no filesystem target to own the history, so runs live at
// .appsec/dast/<target>/runs off the current directory.
func saveDASTRun(target string, findings []model.Finding, toolVersion string) (runstore.RunMeta, error) {
	base, err := os.Getwd()
	if err != nil {
		return runstore.RunMeta{}, err
	}
	store := runstore.Store{Dir: filepath.Join(base, ".appsec", "dast", dastTargetDir(target), "runs")}
	var tools map[string]string
	if toolVersion != "" {
		tools = map[string]string{"nuclei": toolVersion}
	}
	return store.SaveWithTools(findings, tools, time.Now())
}

// dastTargetDir is a filesystem-safe per-target directory name derived from
// the URL: every character outside [A-Za-z0-9-_] becomes '_', so no scheme
// slash, port colon, or path separator can escape the runs directory.
func dastTargetDir(target string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, target)
	safe = strings.Trim(safe, "_")
	if safe == "" {
		return "target"
	}
	if len(safe) > 100 {
		safe = safe[:100]
	}
	return safe
}
