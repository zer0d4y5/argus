package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// OSV implements the Adapter interface for osv-scanner, a software-composition
// analysis scanner backed by the OSV.dev database. It runs alongside trivy: the
// two databases overlap but each catches advisories the other misses, and the
// correlate stage dedups shared CVEs (this adapter prefers the CVE/GHSA alias
// as the rule id so a vuln trivy also reports collapses to one finding).
type OSV struct{}

func (o *OSV) Name() string     { return "osv-scanner" }
func (o *OSV) Category() string { return model.CategorySCA }
func (o *OSV) Available() bool  { return toolOnPath("osv-scanner") }

// Scan runs osv-scanner recursively against the target and returns raw findings.
func (o *OSV) Scan(ctx context.Context, target string) ([]model.RawFinding, error) {
	args := []string{
		"scan",
		"-r",
		"--allow-no-lockfiles", // a project without a lockfile is not an error
		"--format", "json",
		target,
	}
	data, err := runJSON(ctx, "osv-scanner", args...)
	if err != nil {
		return nil, fmt.Errorf("osv-scanner scan: %w", err)
	}
	findings, err := parseOSV(data)
	if err != nil {
		return nil, err
	}
	// osv-scanner reports ABSOLUTE lockfile paths; the other adapters emit
	// target-prefixed, repo-relative paths, and ignore_paths / SARIF locations
	// depend on that shape. Normalize each finding's path to match, so a fixture
	// under testdata/** is ignored the same way it is for trivy.
	absTarget, _ := filepath.Abs(target)
	for i := range findings {
		p := repoRelPath(findings[i].Meta["source"], target, absTarget)
		if p == "" {
			continue
		}
		findings[i].Meta["source"] = p
		findings[i].File = p
	}
	return findings, nil
}

// repoRelPath converts an osv-scanner source path into the target-prefixed,
// slash-separated, repo-relative form the rest of the pipeline expects.
func repoRelPath(src, target, absTarget string) string {
	src = strings.TrimSpace(src)
	if src == "" {
		return ""
	}
	rel := src
	if filepath.IsAbs(src) {
		if r, err := filepath.Rel(absTarget, src); err == nil {
			rel = r
		}
	}
	rel = filepath.ToSlash(rel)
	if target != "." && target != "" {
		return path.Join(filepath.ToSlash(target), rel)
	}
	return rel
}

type osvReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
}

type osvPackage struct {
	Package         osvPkgInfo        `json:"package"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	Groups          []osvGroup        `json:"groups"`
}

type osvPkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvGroup struct {
	IDs         []string `json:"ids"`
	MaxSeverity string   `json:"max_severity"` // osv-scanner's computed CVSS base score, e.g. "9.8"
}

type osvVuln struct {
	ID       string          `json:"id"`
	Summary  string          `json:"summary"`
	Details  string          `json:"details"`
	Aliases  []string        `json:"aliases"`
	Affected []osvAffected   `json:"affected"`
	DBSpec   json.RawMessage `json:"database_specific"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Events []map[string]string `json:"events"`
}

// parseOSV converts osv-scanner JSON into RawFindings. Split out from Scan so it
// is unit-testable without invoking the binary.
func parseOSV(data []byte) ([]model.RawFinding, error) {
	var report osvReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("osv-scanner json decode: %w", err)
	}

	var findings []model.RawFinding
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			sevByID := severityByID(pkg.Groups)
			pkgLabel := pkg.Package.Name
			if pkg.Package.Version != "" {
				pkgLabel += "@" + pkg.Package.Version
			}
			for _, vulnRaw := range pkg.Vulnerabilities {
				var vuln osvVuln
				if err := json.Unmarshal(vulnRaw, &vuln); err != nil || vuln.ID == "" {
					continue // skip only the malformed entry
				}
				cve := preferredCVE(vuln.ID, vuln.Aliases)
				findings = append(findings, model.RawFinding{
					Tool:     "osv-scanner",
					Category: model.CategorySCA,
					// Prefer the CVE/GHSA alias as the id so a vuln trivy also
					// reports dedups to one finding; fall back to the OSV id.
					RuleID:      firstNonEmpty(cve, vuln.ID),
					Title:       firstNonEmpty(vuln.Summary, vuln.ID),
					Description: vuln.Details,
					RawSeverity: sevByID[vuln.ID],
					Package:     pkgLabel,
					CVE:         cveAlias(vuln.Aliases, vuln.ID),
					Remediation: remediationFor(pkg.Package.Name, vuln.Affected),
					Meta:        osvMeta(result.Source.Path, pkg.Package.Ecosystem, vuln.ID),
					RawPayload:  vulnRaw,
				})
			}
		}
	}
	return findings, nil
}

// severityByID maps each vuln id to a severity band derived from its group's
// osv-scanner-computed CVSS score. Empty score yields "" (the pipeline treats
// unknown severity as medium, never info).
func severityByID(groups []osvGroup) map[string]string {
	out := map[string]string{}
	for _, g := range groups {
		band := bandFromScore(g.MaxSeverity)
		for _, id := range g.IDs {
			out[id] = band
		}
	}
	return out
}

func bandFromScore(score string) string {
	score = strings.TrimSpace(score)
	if score == "" {
		return ""
	}
	f, err := strconv.ParseFloat(score, 64)
	if err != nil {
		return ""
	}
	switch {
	case f >= 9.0:
		return "critical"
	case f >= 7.0:
		return "high"
	case f >= 4.0:
		return "medium"
	case f > 0:
		return "low"
	default:
		return ""
	}
}

// preferredCVE returns the id to use as the rule id, preferring a CVE (from the
// id or any alias) over a GHSA, so it aligns with trivy (which keys on CVEs)
// for dedup. Empty when neither the id nor the aliases are a CVE/GHSA.
func preferredCVE(id string, aliases []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	if strings.HasPrefix(id, "GHSA-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "GHSA-") {
			return a
		}
	}
	return ""
}

// cveAlias returns the CVE id for the finding's CVE field (for exploit
// enrichment), preferring a real CVE- alias over the OSV id.
func cveAlias(aliases []string, id string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	return ""
}

// remediationFor returns an upgrade hint from the first fixed version in the
// advisory's affected ranges, or "" when the advisory lists no fix.
func remediationFor(pkgName string, affected []osvAffected) string {
	for _, a := range affected {
		for _, rng := range a.Ranges {
			for _, ev := range rng.Events {
				if fixed := ev["fixed"]; fixed != "" {
					return "Upgrade " + pkgName + " to " + fixed
				}
			}
		}
	}
	return ""
}

func osvMeta(source, ecosystem, osvID string) map[string]string {
	meta := map[string]string{"osvId": osvID}
	if source != "" {
		meta["source"] = source
	}
	if ecosystem != "" {
		meta["ecosystem"] = ecosystem
	}
	return meta
}
