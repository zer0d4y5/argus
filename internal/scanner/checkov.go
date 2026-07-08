package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// Checkov implements the Adapter interface for checkov IaC misconfiguration
// scanning (Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, ARM,
// Bicep, Serverless). The secrets framework is skipped: leaked credentials are
// gitleaks' job (category SECRET); letting checkov report them here would
// miscategorize them as IAC and double-count.
type Checkov struct{}

func (c *Checkov) Name() string     { return "checkov" }
func (c *Checkov) Category() string { return model.CategoryIaC }
func (c *Checkov) Available() bool  { return toolOnPath("checkov") }

// Scan executes checkov against the target and returns raw findings.
func (c *Checkov) Scan(ctx context.Context, target string) ([]model.RawFinding, error) {
	// checkov selects file vs directory mode by flag, not by inspection.
	targetFlag := "-d"
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		targetFlag = "-f"
	}
	args := []string{
		"-o", "json",
		"--quiet",
		"--compact",
		"--skip-framework", "secrets",
		targetFlag, target,
	}
	data, err := runJSON(ctx, "checkov", args...)
	if err != nil {
		return nil, fmt.Errorf("checkov scan: %w", err)
	}
	findings, err := parseCheckov(data)
	if err != nil {
		return nil, err
	}
	// checkov reports file_path relative to the scanned directory with a
	// leading slash ("/main.tf"). Re-root onto the scan target so paths agree
	// with the other tools (CWD-relative) and ignore_paths/SARIF work.
	prefix := pathPrefix(target)
	for i := range findings {
		rel := strings.TrimPrefix(filepath.ToSlash(findings[i].File), "/")
		if prefix != "" {
			rel = path.Join(prefix, rel)
		}
		findings[i].File = rel
	}
	return findings, nil
}

// pathPrefix returns the prefix that makes a scanned-dir-relative path
// CWD-relative: the target itself for a directory, its parent for a file,
// and "" when the target is the current directory.
func pathPrefix(target string) string {
	if target == "" || target == "." {
		return ""
	}
	if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
		dir := filepath.Dir(target)
		if dir == "." {
			return ""
		}
		return filepath.ToSlash(dir)
	}
	return filepath.ToSlash(target)
}

// checkovRun is one framework's result set. checkov emits a single run object
// when one framework matched and an array of runs when several did.
type checkovRun struct {
	CheckType string `json:"check_type"` // terraform | kubernetes | dockerfile | ...
	Results   struct {
		// Raw messages so each failed check's original object is preserved
		// verbatim in RawPayload.
		FailedChecks []json.RawMessage `json:"failed_checks"`
	} `json:"results"`
}

type checkovCheck struct {
	CheckID       string          `json:"check_id"`    // e.g. CKV_AWS_24
	BcCheckID     string          `json:"bc_check_id"` // e.g. BC_AWS_NETWORKING_1
	CheckName     string          `json:"check_name"`
	FilePath      string          `json:"file_path"`       // "/main.tf", scanned-dir-relative
	FileLineRange []int           `json:"file_line_range"` // [start, end]
	Resource      string          `json:"resource"`        // e.g. aws_security_group.open_ssh
	Severity      string          `json:"severity"`        // null in OSS runs; set in platform-enriched runs
	Guideline     string          `json:"guideline"`       // remediation URL
	Benchmarks    json.RawMessage `json:"benchmarks"`      // CIS benchmark IDs, platform-enriched runs only
}

// parseCheckov converts checkov JSON output into RawFindings. Split out from
// Scan so it is unit-testable without invoking the binary.
func parseCheckov(data []byte) ([]model.RawFinding, error) {
	// Tolerate both top-level shapes: one run object or an array of runs.
	var runs []checkovRun
	if err := json.Unmarshal(data, &runs); err != nil {
		var single checkovRun
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, fmt.Errorf("checkov json decode: %w", err)
		}
		runs = []checkovRun{single}
	}

	var findings []model.RawFinding
	for _, run := range runs {
		for _, checkRaw := range run.Results.FailedChecks {
			var check checkovCheck
			if err := json.Unmarshal(checkRaw, &check); err != nil {
				// Skip only the malformed entry, not the whole run.
				continue
			}
			if check.CheckID == "" {
				continue
			}

			startLine, endLine := 0, 0
			if len(check.FileLineRange) == 2 {
				startLine, endLine = check.FileLineRange[0], check.FileLineRange[1]
			}

			meta := map[string]string{}
			if run.CheckType != "" {
				meta["framework"] = run.CheckType
			}
			if check.Resource != "" {
				meta["resource"] = check.Resource
			}
			if check.BcCheckID != "" {
				meta["bcCheckId"] = check.BcCheckID
			}
			if check.Guideline != "" {
				meta["guideline"] = check.Guideline
			}
			// CIS/benchmark IDs only appear in platform-enriched runs; capture
			// them verbatim when present (compliance mapping itself is Phase 5).
			if b := strings.TrimSpace(string(check.Benchmarks)); b != "" && b != "null" {
				meta["benchmarks"] = b
			}
			if len(meta) == 0 {
				meta = nil
			}

			findings = append(findings, model.RawFinding{
				Tool:        "checkov",
				Category:    model.CategoryIaC,
				RuleID:      check.CheckID,
				Title:       firstNonEmpty(check.CheckName, check.CheckID),
				RawSeverity: check.Severity,
				File:        check.FilePath,
				StartLine:   startLine,
				EndLine:     endLine,
				Meta:        meta,
				RawPayload:  checkRaw,
			})
		}
	}
	return findings, nil
}
