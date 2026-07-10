package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/scanner"
)

func init() {
	imageCmd.Flags().StringP("format", "f", "", "Output format: sarif, markdown, or json (default from config)")
	imageCmd.Flags().String("fail-severity", "", "Fail if findings meet or exceed this severity (critical|high|medium|low|info|none)")
	imageCmd.Flags().StringP("config", "c", "", "Path to argus.yml (or appsec.yml) configuration file")
	imageCmd.Flags().StringP("output", "o", "", "Output file path (default is stdout)")
	imageCmd.Flags().Int("timeout", 600, "Scan timeout in seconds")
	imageCmd.Flags().Bool("triage", false, "Enable AI triage of findings (config: triage.enabled)")
	imageCmd.Flags().Bool("exclude-fp", false, "Exclude LLM-marked false positives from the report and severity gate (opt-in)")
	imageCmd.Flags().Bool("save", false, "Save the run under .appsec/image/<ref>/runs for the console")
	imageCmd.Flags().Bool("strict-gate", false, "Gate on ALL findings, ignoring accepted-risk/false-positive dispositions (default: dispositioned findings don't fail the gate)")
	rootCmd.AddCommand(imageCmd)
}

var imageCmd = &cobra.Command{
	Use:   "image <ref>",
	Short: "Scan a container image for vulnerabilities (trivy)",
	Long: `Scans a container image for vulnerable OS and application packages with trivy
and maps the results into the unified findings model (category SCA): banded
severity, risk signals, and compliance mapping, in the same pipeline as code,
cloud, and DAST findings.

This is a distinct surface from the filesystem SCA pass: it sees the OS
packages baked into the image, not only the dependencies your source declares.
Registry credentials are REFERENCED from your ambient container config
(docker login), never collected by Argus.

  argus image nginx:1.27-alpine
  argus image registry.example.com/team/app:v1.2.3 --fail-severity high
  argus image app@sha256:abc123... --format sarif -o image.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: runImage,
}

func runImage(cmd *cobra.Command, args []string) error {
	ref := args[0]
	if err := scanner.ValidateImageRef(ref); err != nil {
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

	ctx := cmd.Context()
	if timeoutSec, _ := cmd.Flags().GetInt("timeout"); timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}

	res, err := pipeline.RunImage(ctx, pipeline.ImageOptions{Ref: ref, Config: cfg},
		func(line string) { fmt.Fprint(os.Stderr, line) })
	if err != nil {
		return err
	}
	findings := res.Findings

	if err := writeReport(cmd, cfg.Format, findings); err != nil {
		return err
	}

	if save, _ := cmd.Flags().GetBool("save"); save {
		if meta, err := saveImageRun(ref, findings); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: --save failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "==> saved run %s to %s\n", meta.ID, meta.Path)
		}
	}

	printSummary(findings)

	// Disposition suppression, same as every other scan surface.
	gated := findings
	if strict, _ := cmd.Flags().GetBool("strict-gate"); !strict {
		base, err := os.Getwd()
		if err != nil {
			return err
		}
		dispDir := filepath.Join(base, ".appsec", "image", imageTargetDir(ref))
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

// saveImageRun stores an image run under a per-image directory, mirroring
// cloud and DAST runs: there is no filesystem target to own the history.
func saveImageRun(ref string, findings []model.Finding) (runstore.RunMeta, error) {
	base, err := os.Getwd()
	if err != nil {
		return runstore.RunMeta{}, err
	}
	store := runstore.Store{Dir: filepath.Join(base, ".appsec", "image", imageTargetDir(ref), "runs")}
	return store.Save(findings, time.Now())
}

// imageTargetDir is a filesystem-safe per-image directory name: every
// character outside [A-Za-z0-9-_] becomes '_', so a registry slash, tag
// colon, or digest '@' cannot escape the runs directory.
func imageTargetDir(ref string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, ref)
	safe = strings.Trim(safe, "_")
	if safe == "" {
		return "image"
	}
	if len(safe) > 100 {
		safe = safe[:100]
	}
	return safe
}
