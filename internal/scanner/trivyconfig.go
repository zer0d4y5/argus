package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"

	"github.com/zer0d4y5/argus/internal/model"
)

// TrivyConfig implements the Adapter interface for trivy misconfiguration
// scanning of IaC files (Terraform, CloudFormation, Kubernetes, Dockerfile,
// Helm). It is a separate adapter from the SCA Trivy so `--scanners` can
// select the two independently and the summary attributes findings to the
// right pass; both shell out to the same `trivy` binary, so IaC scanning
// works with no new tool installed.
type TrivyConfig struct{}

func (t *TrivyConfig) Name() string     { return "trivy-config" }
func (t *TrivyConfig) Category() string { return model.CategoryIaC }
func (t *TrivyConfig) Available() bool  { return toolOnPath("trivy") }

// Scan executes trivy config against the target and returns raw findings.
func (t *TrivyConfig) Scan(ctx context.Context, target string) ([]model.RawFinding, error) {
	args := []string{
		"config",
		"--quiet",
		"--format", "json",
		target,
	}
	data, err := runJSON(ctx, "trivy", args...)
	if err != nil {
		return nil, fmt.Errorf("trivy config scan: %w", err)
	}
	findings, err := parseTrivyConfig(data)
	if err != nil {
		return nil, err
	}
	// Same path convention as the SCA trivy adapter: trivy reports Target
	// relative to the scanned directory; join the scan-target prefix so all
	// tools agree on CWD-relative paths.
	for i := range findings {
		if target != "." && target != "" {
			findings[i].File = path.Join(filepath.ToSlash(target), findings[i].File)
		}
	}
	return findings, nil
}

type trivyConfigReport struct {
	Results []trivyConfigResult `json:"Results"`
}

type trivyConfigResult struct {
	Target string `json:"Target"`
	// Raw messages so each misconfiguration's original object is preserved
	// verbatim in RawPayload. May be null/absent.
	Misconfigurations []json.RawMessage `json:"Misconfigurations"`
}

type trivyMisconf struct {
	ID          string `json:"ID"`    // e.g. AWS-0107, KSV-0017, DS-0001
	AVDID       string `json:"AVDID"` // sometimes set, e.g. AVD-AWS-0107
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"` // instance-specific detail
	Resolution  string `json:"Resolution"`
	Severity    string `json:"Severity"`
	Status      string `json:"Status"` // FAIL | PASS | EXCEPTION
	PrimaryURL  string `json:"PrimaryURL"`
	CauseMeta   struct {
		Resource  string `json:"Resource"`
		Provider  string `json:"Provider"`
		Service   string `json:"Service"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

// parseTrivyConfig converts trivy config JSON output into RawFindings. Split
// out from Scan so it is unit-testable without invoking the binary.
func parseTrivyConfig(data []byte) ([]model.RawFinding, error) {
	var report trivyConfigReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("trivy config json decode: %w", err)
	}

	var findings []model.RawFinding
	for _, result := range report.Results {
		for _, misconfRaw := range result.Misconfigurations {
			var m trivyMisconf
			if err := json.Unmarshal(misconfRaw, &m); err != nil {
				// Skip only the malformed entry, not the whole run.
				continue
			}
			if m.ID == "" {
				continue
			}
			// Only failures become findings. PASS/EXCEPTION entries appear
			// under --include-non-failures; an unknown future status is kept
			// (never silently drop something trivy chose to report).
			if m.Status == "PASS" || m.Status == "EXCEPTION" {
				continue
			}

			meta := map[string]string{}
			if result.Target != "" {
				meta["target"] = result.Target
			}
			for k, v := range map[string]string{
				"message":    m.Message,
				"resource":   m.CauseMeta.Resource,
				"provider":   m.CauseMeta.Provider,
				"service":    m.CauseMeta.Service,
				"avdid":      m.AVDID,
				"primaryURL": m.PrimaryURL,
			} {
				if v != "" {
					meta[k] = v
				}
			}
			if len(meta) == 0 {
				meta = nil
			}

			findings = append(findings, model.RawFinding{
				Tool:        "trivy-config",
				Category:    model.CategoryIaC,
				RuleID:      m.ID,
				Title:       firstNonEmpty(m.Title, m.ID),
				Description: m.Description,
				RawSeverity: m.Severity,
				File:        result.Target,
				StartLine:   m.CauseMeta.StartLine,
				EndLine:     m.CauseMeta.EndLine,
				Remediation: m.Resolution,
				Meta:        meta,
				RawPayload:  misconfRaw,
			})
		}
	}
	return findings, nil
}
