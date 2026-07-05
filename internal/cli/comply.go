package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/leaky-hub/appsec/internal/compliance"
	"github.com/leaky-hub/appsec/internal/correlate"
	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/risk"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/scanner"
)

func init() {
	complyCmd.Flags().StringP("format", "f", "markdown", "Report format: markdown or json")
	complyCmd.Flags().StringP("output", "o", "", "Output file path (default is stdout)")
	complyCmd.Flags().StringP("config", "c", "", "Path to appsec.yml configuration file")
	complyCmd.Flags().String("run", "", "Assess a saved run by ID instead of scanning (see .appsec/runs)")
	complyCmd.Flags().Bool("latest", false, "Assess the most recent saved run instead of scanning")
	rootCmd.AddCommand(complyCmd)
}

var complyCmd = &cobra.Command{
	Use:   "comply [path]",
	Short: "Produce a per-framework compliance gap assessment",
	Long: `Maps findings to the security controls they violate (ASVS, PCI DSS, CIS
benchmarks) and reports per-framework control coverage: violated controls with
evidence, controls with no violations detected, and the areas static scanning
cannot assess.

By default it scans the target path (same scanners as 'appsec scan', without
AI triage — the assessment is fully deterministic). Use --latest or --run <id>
to assess a saved run instead. The report never gates: exit code 0 unless the
assessment itself fails.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runComply,
}

func runComply(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	format, _ := cmd.Flags().GetString("format")
	format = strings.ToLower(format)
	if format != "markdown" && format != "json" {
		return fmt.Errorf("unsupported format %q (markdown|json)", format)
	}

	findings, source, err := complyFindings(cmd, target)
	if err != nil {
		return err
	}
	// Deterministic severity-descending order so per-control evidence pointers
	// always lead with the worst finding.
	model.Sort(findings)

	rep, err := compliance.BuildReport(findings, target, source, time.Now())
	if err != nil {
		return fmt.Errorf("compliance assessment: %w", err)
	}

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
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		err = enc.Encode(rep)
	default:
		err = compliance.WriteMarkdown(w, rep)
	}
	if file != nil {
		if cerr := file.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("failed to write output file: %w", cerr)
		}
	}
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	printComplySummary(rep)
	return nil
}

// complyFindings resolves the findings to assess: a saved run when --run or
// --latest is given, otherwise a fresh deterministic scan (no triage).
func complyFindings(cmd *cobra.Command, target string) ([]model.Finding, string, error) {
	runID, _ := cmd.Flags().GetString("run")
	latest, _ := cmd.Flags().GetBool("latest")
	if runID != "" || latest {
		return savedRunFindings(target, runID)
	}

	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, "", err
	}
	if err := scanner.ValidateProfile(cfg.Profile); err != nil {
		return nil, "", fmt.Errorf("invalid profile: %w", err)
	}
	rulesets := scanner.ResolveSemgrepRulesets(cfg.Profile, cfg.SemgrepRules)
	adapters, err := selectAdapters(cfg, rulesets)
	if err != nil {
		return nil, "", err
	}

	raw := runScanners(cmd.Context(), adapters, target, cfg.TimeoutSec)
	findings := model.Normalize(raw)
	findings, suppressed := model.FilterIgnored(findings, cfg.IgnorePaths, cfg.IgnoreRules)
	if suppressed > 0 {
		fmt.Fprintf(os.Stderr, "NOTE: %d finding(s) suppressed by ignore rules\n", suppressed)
	}
	findings = correlate.Correlate(findings)
	risk.Apply(findings)
	return findings, "scan", nil
}

// savedRunFindings loads a stored run from the target repo's run store.
func savedRunFindings(target, runID string) ([]model.Finding, string, error) {
	root := target
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		root = filepath.Dir(target)
	}
	store := runstore.ForRepo(root)
	if runID == "" {
		runs, err := store.List()
		if err != nil {
			return nil, "", fmt.Errorf("list saved runs: %w", err)
		}
		if len(runs) == 0 {
			return nil, "", fmt.Errorf("no saved runs under %s (run `appsec scan %s --save` first)", store.Dir, target)
		}
		runID = runs[len(runs)-1].ID
	}
	doc, err := store.Load(runID)
	if err != nil {
		return nil, "", fmt.Errorf("load run %s: %w", runID, err)
	}
	return doc.Findings, runID, nil
}

// printComplySummary is the stderr one-glance rollup, findings-report style.
func printComplySummary(rep compliance.Report) {
	fmt.Fprintf(os.Stderr, "\nCompliance: %d finding(s) assessed across %d frameworks\n",
		rep.TotalFindings, len(rep.Frameworks))
	for _, fw := range rep.Frameworks {
		fmt.Fprintf(os.Stderr, "  %-10s v%-6s %d violated, %d clean, %d not assessable, %d unmapped finding(s)\n",
			fw.ID, fw.Version, fw.ViolatedControls, fw.CleanControls, len(fw.NotAssessable), fw.UnmappedFindings)
	}
}
