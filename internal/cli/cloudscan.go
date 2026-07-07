package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/leaky-hub/argus/internal/cloudscan"
	"github.com/leaky-hub/argus/internal/model"
	"github.com/leaky-hub/argus/internal/pipeline"
	"github.com/leaky-hub/argus/internal/runstore"
)

func init() {
	cloudScanCmd.Flags().String("provider", cloudscan.ProviderAWS, "Cloud provider: aws")
	cloudScanCmd.Flags().String("profile", "", "Credential REFERENCE: a named profile from your local cloud config (AWS_PROFILE). Never a raw key.")
	cloudScanCmd.Flags().String("regions", "", "Comma-separated region filter (default: provider default)")
	cloudScanCmd.Flags().StringP("format", "f", "", "Output format: sarif, markdown, or json (default from config)")
	cloudScanCmd.Flags().String("fail-severity", "", "Fail if findings meet or exceed this severity (critical|high|medium|low|info|none)")
	cloudScanCmd.Flags().StringP("config", "c", "", "Path to argus.yml (or appsec.yml) configuration file")
	cloudScanCmd.Flags().StringP("output", "o", "", "Output file path (default is stdout)")
	cloudScanCmd.Flags().Bool("triage", false, "Enable AI triage of findings (config: triage.enabled)")
	cloudScanCmd.Flags().Bool("exclude-fp", false, "Exclude LLM-marked false positives from the report and severity gate (opt-in)")
	cloudScanCmd.Flags().Bool("save", false, "Save the run under .appsec/cloud/<provider>-<profile>/runs for the console")
	cloudScanCmd.Flags().Bool("strict-gate", false, "Gate on ALL findings, ignoring accepted-risk/false-positive dispositions (default: dispositioned findings don't fail the gate)")
	rootCmd.AddCommand(cloudScanCmd)
}

var cloudScanCmd = &cobra.Command{
	Use:   "cloud-scan",
	Short: "Run a cloud security posture scan (prowler) against a referenced account",
	Long: `Assesses cloud security posture through prowler and maps the results into the
unified findings model (category CLOUD): banded severity, risk signals, and
CIS-AWS compliance mapping, in the same pipeline as code findings.

Credentials are REFERENCED, never collected. --profile names a profile from
your local cloud config (e.g. ~/.aws); the platform passes only that NAME to
prowler as AWS_PROFILE. Create a read-only security-audit principal
(AWS SecurityAudit + ViewOnlyAccess) and point --profile at it; the platform
runs with exactly what that profile can do.

  argus cloud-scan --provider aws --profile security-audit
  argus cloud-scan --provider aws --profile security-audit --regions us-east-1,us-west-2`,
	Args: cobra.NoArgs,
	RunE: runCloudScan,
}

func runCloudScan(cmd *cobra.Command, _ []string) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	provider, _ := cmd.Flags().GetString("provider")
	profile, _ := cmd.Flags().GetString("profile")
	if profile == "" {
		return fmt.Errorf("--profile is required: name a profile from your local cloud config (never a raw key)")
	}
	var regions []string
	if v, _ := cmd.Flags().GetString("regions"); v != "" {
		for _, r := range strings.Split(v, ",") {
			if r = strings.TrimSpace(r); r != "" {
				regions = append(regions, r)
			}
		}
	}

	gate, err := model.ParseGate(cfg.FailSeverity)
	if err != nil {
		return fmt.Errorf("invalid fail-severity: %w", err)
	}

	// Whole-scan timeout (cloud runs are long; config default 1800s).
	timeout := time.Duration(cfg.Cloud.TimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	res, err := pipeline.RunCloud(ctx, pipeline.CloudOptions{
		Provider: provider,
		Profile:  profile,
		Regions:  regions,
		Config:   cfg,
	}, func(line string) { fmt.Fprint(os.Stderr, line) })
	if err != nil {
		return err
	}
	findings := res.Findings

	if err := writeReport(cmd, cfg.Format, findings); err != nil {
		return err
	}

	if save, _ := cmd.Flags().GetBool("save"); save {
		if meta, err := saveCloudRun(provider, profile, findings, res.ToolVersion); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: --save failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "==> saved run %s to %s\n", meta.ID, meta.Path)
		}
	}

	// Posture summary: fails AND the checks that passed — "3 fails of 12" and
	// "3 fails of 600" are different claims.
	fmt.Fprintf(os.Stderr, "\nPosture: %d checks failed, %d passed, %d manual\n", res.Failed, res.Passed, res.Manual)
	printSummary(findings)

	// Apply disposition suppression so the CLI gate matches the console: a risk
	// accepted in the console (stored beside this target's cloud runs) stops
	// failing CI but stays in the report. --strict-gate gates on everything.
	gated := findings
	if strict, _ := cmd.Flags().GetBool("strict-gate"); !strict {
		base, err := os.Getwd()
		if err != nil {
			return err
		}
		dispDir := filepath.Join(base, ".appsec", "cloud", cloudTargetDir(provider, profile))
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

// saveCloudRun stores a cloud run under a per-target directory: there is no
// filesystem target to own the history, so cloud runs live at
// .appsec/cloud/<provider>-<profile>/runs off the current directory
// (locked decision 9). The store is the same runstore machinery code scans
// use — deltas, list, load all work unchanged; the resource-slot fingerprint
// makes cloud deltas meaningful across runs.
func saveCloudRun(provider, profile string, findings []model.Finding, toolVersion string) (runstore.RunMeta, error) {
	base, err := os.Getwd()
	if err != nil {
		return runstore.RunMeta{}, err
	}
	id := cloudTargetDir(provider, profile)
	store := runstore.Store{Dir: filepath.Join(base, ".appsec", "cloud", id, "runs")}
	var tools map[string]string
	if toolVersion != "" {
		tools = map[string]string{"prowler": toolVersion}
	}
	return store.SaveWithTools(findings, tools, time.Now())
}

// cloudTargetDir is the filesystem-safe per-target directory name. The
// profile is already validated against the closed list before any scan runs,
// but this is a defense-in-depth sanitize for the path component.
func cloudTargetDir(provider, profile string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, profile)
	return provider + "-" + safe
}
