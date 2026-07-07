package compliance

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/leaky-hub/argus/internal/model"
)

// Cloud compliance passthrough (cloud-posture session follow-up).
//
// Prowler maps every cloud check to controls across dozens of frameworks and
// emits that mapping PER FINDING in its OCSF output (`unmapped.compliance`).
// That is authoritative, expert-maintained, version-pinned mapping we could
// never hand-curate as completely — so for CLOUD findings we PASS IT THROUGH
// verbatim, exactly as we already do for CIS via the materialized data file.
// Same ethos as the rest of internal/compliance: deterministic, no invented
// mappings, version-pinned (prowler 5.31); the ONLY curation here is (a) a
// reviewed allow-list of which frameworks to surface, and (b) a normalization
// of prowler's framework keys to stable display IDs. Control IDs are prowler's
// own, unchanged.
//
// These passthrough values are per-finding EVIDENCE (the chips on a finding).
// They do NOT enter the curated gap report (internal/compliance/assess.go),
// which is catalog-driven off the embedded framework data files and is
// unchanged — a passthrough framework we hold no control catalog for cannot be
// assessed for coverage, only cited per finding. CIS-AWS is deliberately NOT
// in the allow-list below: it stays engine-mapped (the materialized CIS-1.5
// rules) so it remains gap-reportable and version-consistent, and the
// passthrough never double-labels it.

// cloudFramework is one reviewed allow-list entry: prowler's key in
// unmapped.compliance, the stable display ID we emit, and the human name.
type cloudFramework struct {
	ProwlerKey string
	ID         string
	Name       string
}

// cloudFrameworkAllowList is the reviewed set of frameworks surfaced from
// prowler's per-finding mapping. Recognized international/industry standards
// only; prowler's localized duplicates (e.g. the Korean KISA variant), its
// internal ProwlerThreatScore, and onboarding checklists are deliberately
// excluded. Extending this is a normal reviewed change — add prowler's key,
// a stable ID, and the name; the passthrough picks it up with no other edits.
// Version pinned to prowler 5.31's embedded framework data.
var cloudFrameworkAllowList = []cloudFramework{
	{"NIST-CSF-2.0", "NIST-CSF", "NIST Cybersecurity Framework 2.0"},
	{"NIST-800-53-Revision-5", "NIST-800-53", "NIST SP 800-53 Rev. 5"},
	{"NIST-800-171-Revision-2", "NIST-800-171", "NIST SP 800-171 Rev. 2"},
	{"ISO27001-2022", "ISO-27001", "ISO/IEC 27001:2022"},
	{"PCI-4.0", "PCI-DSS-Cloud", "PCI DSS v4.0 (cloud)"},
	{"SOC2", "SOC2", "AICPA SOC 2"},
	{"HIPAA", "HIPAA", "HIPAA Security Rule"},
	{"GDPR", "GDPR", "EU GDPR"},
	{"MITRE-ATTACK", "MITRE-ATTACK", "MITRE ATT&CK"},
	{"FedRamp-Moderate-Revision-4", "FedRAMP-Moderate", "FedRAMP Moderate Rev. 4"},
	{"NIS2", "NIS2", "EU NIS2 Directive"},
	{"AWS-Foundational-Security-Best-Practices", "AWS-FSBP", "AWS Foundational Security Best Practices"},
	{"AWS-Well-Architected-Framework-Security-Pillar", "AWS-WAF-Security", "AWS Well-Architected — Security Pillar"},
}

// cloudAllowByKey indexes the allow-list by prowler key (built once).
var cloudAllowByKey = func() map[string]cloudFramework {
	m := make(map[string]cloudFramework, len(cloudFrameworkAllowList))
	for _, f := range cloudFrameworkAllowList {
		m[f.ProwlerKey] = f
	}
	return m
}()

// prowlerOCSF is the minimal shape we unmarshal from a cloud finding's
// RawPayload to reach prowler's per-finding compliance mapping. Everything
// else in the record is ignored.
type prowlerOCSF struct {
	Unmapped struct {
		Compliance map[string][]string `json:"compliance"`
	} `json:"unmapped"`
}

// CloudControls returns the passthrough "<DISPLAY-ID>:<control>" values for a
// CLOUD finding, read from prowler's own mapping in the finding's RawPayload,
// filtered to the reviewed allow-list, sorted and deduplicated. Empty for
// non-cloud findings, findings without a prowler payload, or when the payload
// carries no allow-listed framework. Never errors: a malformed payload yields
// no passthrough, never a failure (compliance is enrichment, never a gate).
func CloudControls(f model.Finding) []string {
	if f.Category != model.CategoryCloud || len(f.RawPayload) == 0 {
		return nil
	}
	var rec prowlerOCSF
	if err := json.Unmarshal(f.RawPayload, &rec); err != nil || len(rec.Unmapped.Compliance) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for key, controls := range rec.Unmapped.Compliance {
		fw, ok := cloudAllowByKey[key]
		if !ok {
			continue
		}
		for _, c := range controls {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			v := fw.ID + ":" + c
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// CloudFrameworks returns the reviewed allow-list (id + name) for docs/UI.
func CloudFrameworks() []cloudFramework { return cloudFrameworkAllowList }
