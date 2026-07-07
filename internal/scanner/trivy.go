package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/leaky-hub/argus/internal/model"
)

// Trivy implements the Adapter interface for trivy filesystem SCA scanning.
type Trivy struct{}

func (t *Trivy) Name() string     { return "trivy" }
func (t *Trivy) Category() string { return model.CategorySCA }
func (t *Trivy) Available() bool  { return toolOnPath("trivy") }

// Scan executes trivy fs against the target and returns raw findings.
func (t *Trivy) Scan(ctx context.Context, target string) ([]model.RawFinding, error) {
	args := []string{
		"fs",
		"--quiet",
		"--format", "json",
		"--scanners", "vuln",
		target,
	}
	data, err := runJSON(ctx, "trivy", args...)
	if err != nil {
		return nil, fmt.Errorf("trivy scan: %w", err)
	}
	findings, err := parseTrivy(data)
	if err != nil {
		return nil, err
	}
	// Trivy reports Target (the manifest, e.g. requirements.txt) relative to
	// the scanned directory; semgrep and gitleaks include the scan-target
	// prefix. Join so all tools agree, and surface the manifest as the
	// finding's File so ignore_paths and SARIF locations work for SCA
	// findings too.
	for i := range findings {
		t := findings[i].Meta["target"]
		if t == "" {
			continue
		}
		if target != "." && target != "" {
			t = path.Join(filepath.ToSlash(target), t)
			findings[i].Meta["target"] = t
		}
		findings[i].File = t
	}
	return findings, nil
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target string `json:"Target"`
	// Kept as raw messages so each vulnerability's original object can be
	// stored verbatim in RawPayload. May be null/absent.
	Vulnerabilities []json.RawMessage `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	CweIDs           []string `json:"CweIDs"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	PrimaryURL       string   `json:"PrimaryURL"`
}

// parseTrivy converts trivy JSON output into RawFindings. Split out from Scan
// so it is unit-testable without invoking the binary.
func parseTrivy(data []byte) ([]model.RawFinding, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("trivy json decode: %w", err)
	}

	var findings []model.RawFinding
	for _, result := range report.Results {
		for _, vulnRaw := range result.Vulnerabilities {
			var vuln trivyVuln
			if err := json.Unmarshal(vulnRaw, &vuln); err != nil {
				// Skip only the malformed entry, not the whole run.
				continue
			}

			cve := ""
			if strings.HasPrefix(vuln.VulnerabilityID, "CVE-") ||
				strings.HasPrefix(vuln.VulnerabilityID, "GHSA-") {
				cve = vuln.VulnerabilityID
			}

			pkg := vuln.PkgName
			if vuln.InstalledVersion != "" {
				pkg += "@" + vuln.InstalledVersion
			}

			remediation := ""
			if vuln.FixedVersion != "" {
				remediation = "Upgrade " + vuln.PkgName + " to " + vuln.FixedVersion
			}

			meta := map[string]string{}
			if result.Target != "" {
				meta["target"] = result.Target
			}
			if vuln.PrimaryURL != "" {
				meta["primaryURL"] = vuln.PrimaryURL
			}
			if len(meta) == 0 {
				meta = nil
			}

			findings = append(findings, model.RawFinding{
				Tool:        "trivy",
				Category:    model.CategorySCA,
				RuleID:      vuln.VulnerabilityID,
				Title:       firstNonEmpty(vuln.Title, vuln.VulnerabilityID),
				Description: vuln.Description,
				RawSeverity: vuln.Severity,
				Package:     pkg,
				CWEs:        vuln.CweIDs,
				CVE:         cve,
				Remediation: remediation,
				Meta:        meta,
				RawPayload:  vulnRaw,
			})
		}
	}
	return findings, nil
}
