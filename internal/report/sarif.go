// SARIF 2.1.0 writer. This file is the contract with GitHub code scanning
// and other SARIF consumers; it is security-critical because a malformed or
// lossy SARIF file silently drops findings from the destination system.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
)

const (
	sarifSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	sarifVersion   = "2.1.0"
	toolName       = "appsec"
	toolInfoURI    = "https://github.com/leaky-hub/appsec"
	toolVersion    = "0.1.0"
)

// Typed structs for exactly the SARIF subset we emit — no map[string]any, so
// the shape is enforced at compile time.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                `json:"id"`
	Name             string                `json:"name,omitempty"`
	ShortDescription *sarifMessage         `json:"shortDescription,omitempty"`
	FullDescription  *sarifMessage         `json:"fullDescription,omitempty"`
	Help             *sarifMessage         `json:"help,omitempty"`
	Properties       *sarifRuleProperties  `json:"properties,omitempty"`
	DefaultConfig    *sarifRuleDefaultConf `json:"defaultConfiguration,omitempty"`
}

type sarifRuleDefaultConf struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
	// GitHub uses security-severity (a CVSS-like 0-10 string) to bucket
	// alerts into critical/high/medium/low in the UI.
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           int                   `json:"ruleIndex"`
	Level               string                `json:"level"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations,omitempty"`
	PartialFingerprints map[string]string     `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProperties `json:"properties"`
}

type sarifResultProperties struct {
	Tools    []string `json:"tools,omitempty"`
	Category string   `json:"category,omitempty"`
	CVE      string   `json:"cve,omitempty"`
	Package  string   `json:"package,omitempty"`
	// Severity is the banded deterministic risk severity (schema 2.0.0,
	// docs/risk-scoring.md "Severity banding"); toolSeverity is what the
	// tool's own scale normalized to — the "tool said" audit trail.
	Severity     string `json:"severity,omitempty"`
	ToolSeverity string `json:"toolSeverity,omitempty"`
	// Phase 2 enrichment. riskScore is the 0-10 prioritization score
	// (docs/risk-scoring.md); triageVerdict/-Rationale carry the AI triage
	// outcome. Deliberately NOT mapped onto security-severity: GitHub's
	// alert bucketing must never move on LLM output. (Banded severity is
	// LLM-free by construction — stage-3 triage never reaches it — so
	// level/security-severity reading it keeps that guarantee.)
	RiskScore       *float64 `json:"riskScore,omitempty"`
	TriageVerdict   string   `json:"triageVerdict,omitempty"`
	TriageRationale string   `json:"triageRationale,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// WriteSARIF emits all findings as a single SARIF 2.1.0 run. Every finding
// becomes exactly one result — nothing is filtered here; filtering/gating is
// the caller's job and happens before reporting.
func WriteSARIF(w io.Writer, findings []model.Finding) error {
	rules := make([]sarifRule, 0)
	ruleIndex := map[string]int{}
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.Tool + "/unclassified"
		}
		idx, ok := ruleIndex[ruleID]
		if !ok {
			idx = len(rules)
			ruleIndex[ruleID] = idx
			rules = append(rules, buildRule(ruleID, f))
		}

		res := sarifResult{
			RuleID:    ruleID,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: resultMessage(f)},
			PartialFingerprints: map[string]string{
				"appsec/fingerprint/v1": f.ID,
			},
			Properties: sarifResultProperties{
				Tools:     f.Tools,
				Category:  f.Category,
				CVE:       f.CVE,
				Package:   f.Package,
				Severity:  f.Severity.String(),
				RiskScore: f.RiskScore,
			},
		}
		if f.ToolSeverity != nil {
			res.Properties.ToolSeverity = f.ToolSeverity.String()
		}
		if f.Triage != nil {
			res.Properties.TriageVerdict = f.Triage.Verdict
			res.Properties.TriageRationale = f.Triage.Rationale
		}
		if loc, ok := resultLocation(f); ok {
			res.Locations = []sarifLocation{loc}
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				InformationURI: toolInfoURI,
				Version:        toolVersion,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func buildRule(ruleID string, f model.Finding) sarifRule {
	tags := []string{"security", f.Category}
	tags = append(tags, f.CWEs...)
	short := f.Title
	if short == "" {
		short = ruleID
	}
	rule := sarifRule{
		ID:               ruleID,
		ShortDescription: &sarifMessage{Text: short},
		Properties: &sarifRuleProperties{
			Tags:             tags,
			SecuritySeverity: securitySeverityScore(f.Severity),
		},
		DefaultConfig: &sarifRuleDefaultConf{Level: sarifLevel(f.Severity)},
	}
	if f.Description != "" {
		rule.FullDescription = &sarifMessage{Text: f.Description}
	}
	if f.Remediation != "" {
		rule.Help = &sarifMessage{Text: f.Remediation}
	}
	return rule
}

// resultMessage guarantees a non-empty message.text (required by the schema).
func resultMessage(f model.Finding) string {
	msg := strings.TrimSpace(f.Description)
	if msg == "" {
		msg = strings.TrimSpace(f.Title)
	}
	if msg == "" {
		msg = f.RuleID
	}
	if msg == "" {
		msg = "finding reported by " + f.Tool
	}
	if f.Package != "" {
		msg = fmt.Sprintf("%s [package: %s]", msg, f.Package)
	}
	return msg
}

// resultLocation builds the physical location. SCA findings have no source
// file, so we fall back to the manifest the scanner reported (Meta["target"]);
// CLOUD findings (schema 2.1.0) have no file either — their resource UID/ARN
// is the natural location, so it fills the artifact URI. With no location at
// all we omit locations entirely (valid SARIF, and consumers show it as a
// run-level result).
func resultLocation(f model.Finding) (sarifLocation, bool) {
	uri := sanitizeURI(f.Location.File)
	startLine, endLine := f.Location.StartLine, f.Location.EndLine
	if uri == "" && f.Location.Resource != "" {
		// The ARN/UID is a stable resource identifier; SARIF's artifactLocation
		// URI is an opaque string to consumers, and a cloud finding has no line.
		uri = sanitizeURI(f.Location.Resource)
		startLine, endLine = 0, 0
	}
	if uri == "" && f.Meta != nil {
		uri = sanitizeURI(f.Meta["target"])
		startLine, endLine = 0, 0
	}
	if uri == "" {
		return sarifLocation{}, false
	}
	loc := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: uri},
		},
	}
	// region.startLine must be >= 1 per the schema; omit region when unknown.
	if startLine >= 1 {
		region := &sarifRegion{StartLine: startLine}
		if endLine >= startLine {
			region.EndLine = endLine
		}
		loc.PhysicalLocation.Region = region
	}
	return loc, true
}

// sanitizeURI converts a scan path into the relative, forward-slash URI form
// SARIF consumers (GitHub in particular) expect.
func sanitizeURI(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.TrimPrefix(p, "./")
	return p
}

// sarifLevel maps normalized severity onto the SARIF level enum. SARIF has
// only error/warning/note, so critical+high collapse to error; the precise
// severity is preserved in properties.severity and security-severity.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverityScore is the CVSS-like score GitHub uses for bucketing:
// >=9.0 critical, >=7.0 high, >=4.0 medium, >0 low.
func securitySeverityScore(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	case model.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}
