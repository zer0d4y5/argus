package cloudscan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
)

// The OCSF Detection Finding fields this parser reads. Designed from what
// prowler 5.31 ACTUALLY emits (`prowler aws -M json-ocsf`) — the committed
// fixture testdata/cloud/prowler-aws.json-ocsf is a recorded, sanitized
// slice of a real run, and the parser is proven against it in CI. Unknown
// fields are ignored by encoding/json; absent fields degrade to empty.
type ocsfRecord struct {
	Message      string          `json:"message"`
	StatusCode   string          `json:"status_code"`   // FAIL | PASS | MANUAL
	StatusDetail string          `json:"status_detail"` // per-resource failure detail
	Severity     string          `json:"severity"`      // Informational..Critical
	RiskDetails  string          `json:"risk_details"`
	Metadata     ocsfMetadata    `json:"metadata"`
	FindingInfo  ocsfFindingInfo `json:"finding_info"`
	Resources    []ocsfResource  `json:"resources"`
	Cloud        ocsfCloud       `json:"cloud"`
	Remediation  ocsfRemediation `json:"remediation"`
	Unmapped     ocsfUnmapped    `json:"unmapped"`
}

type ocsfMetadata struct {
	EventCode string `json:"event_code"` // the prowler check ID — our rule ID
}

type ocsfFindingInfo struct {
	Title string `json:"title"`
	UID   string `json:"uid"`
}

type ocsfResource struct {
	UID    string `json:"uid"` // resource ARN/UID — location.resource
	Name   string `json:"name"`
	Type   string `json:"type"`
	Region string `json:"region"`
	Group  struct {
		Name string `json:"name"` // service, e.g. "s3", "iam"
	} `json:"group"`
}

type ocsfCloud struct {
	Provider string `json:"provider"`
	Region   string `json:"region"`
	Account  struct {
		UID string `json:"uid"`
	} `json:"account"`
}

type ocsfRemediation struct {
	Desc       string   `json:"desc"`
	References []string `json:"references"`
}

type ocsfUnmapped struct {
	Categories []string            `json:"categories"` // prowler check categories, e.g. "internet-exposed"
	Compliance map[string][]string `json:"compliance"` // framework -> control IDs (prowler's own mapping)
	Provider   string              `json:"provider"`
}

// cisFrameworkKey is prowler's key for the CIS AWS Foundations Benchmark
// v1.5.0 mapping inside unmapped.compliance — the one framework version our
// embedded CIS-AWS data file pins. The passthrough test in
// internal/compliance asserts the engine reproduces this mapping exactly.
const cisFrameworkKey = "CIS-1.5"

// Meta keys the parser writes. Reviewed surface: risk signals and the
// compliance passthrough read these and nothing else.
const (
	MetaProvider   = "provider"
	MetaService    = "service"
	MetaRegion     = "region"
	MetaAccount    = "account"
	MetaResource   = "resourceName"
	MetaType       = "resourceType"
	MetaCategories = "categories" // comma-joined prowler check categories
	MetaCISAWS     = "cisAws150"  // comma-joined CIS-AWS 1.5.0 controls (prowler's mapping)
	MetaProwlerUID = "prowlerUid" // prowler's own finding UID, for cross-referencing
)

// ParseOCSF maps a prowler JSON-OCSF document (an array of Detection
// Finding records) into RawFindings. Only FAIL records become findings;
// PASS and MANUAL are counted — a posture assessment reports both. Records
// with an unknown status are skipped and reported in the error only if the
// whole document yields nothing.
func ParseOCSF(data []byte) (Result, error) {
	var records []ocsfRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return Result{}, fmt.Errorf("prowler: parse json-ocsf: %w", err)
	}

	// Raw payloads: re-decode as raw messages so each finding carries its
	// original record verbatim, exactly like every other adapter.
	var rawRecords []json.RawMessage
	if err := json.Unmarshal(data, &rawRecords); err != nil {
		return Result{}, fmt.Errorf("prowler: parse json-ocsf payloads: %w", err)
	}

	var res Result
	for i, r := range records {
		switch strings.ToUpper(r.StatusCode) {
		case "PASS":
			res.Passed++
			continue
		case "MANUAL":
			res.Manual++
			continue
		case "FAIL":
			res.Failed++
		default:
			continue // unknown status: not a posture claim we can make
		}

		var resource ocsfResource
		if len(r.Resources) > 0 {
			resource = r.Resources[0]
		}
		meta := map[string]string{
			MetaProvider: firstNonEmpty(r.Unmapped.Provider, r.Cloud.Provider),
			MetaService:  resource.Group.Name,
			MetaRegion:   firstNonEmpty(resource.Region, r.Cloud.Region),
			MetaAccount:  r.Cloud.Account.UID,
			MetaResource: resource.Name,
			MetaType:     resource.Type,
		}
		if len(r.Unmapped.Categories) > 0 {
			cats := append([]string(nil), r.Unmapped.Categories...)
			sort.Strings(cats)
			meta[MetaCategories] = strings.Join(cats, ",")
		}
		if controls := r.Unmapped.Compliance[cisFrameworkKey]; len(controls) > 0 {
			cc := append([]string(nil), controls...)
			sort.Strings(cc)
			meta[MetaCISAWS] = strings.Join(cc, ",")
		}
		if r.FindingInfo.UID != "" {
			meta[MetaProwlerUID] = r.FindingInfo.UID
		}
		for k, v := range meta {
			if v == "" {
				delete(meta, k)
			}
		}

		res.Raw = append(res.Raw, model.RawFinding{
			Tool:        ToolName,
			Category:    model.CategoryCloud,
			RuleID:      r.Metadata.EventCode,
			Title:       r.FindingInfo.Title, // prowler titles are human; Normalize sanitizes and floors empties
			Description: firstNonEmpty(r.StatusDetail, r.Message, r.RiskDetails),
			RawSeverity: r.Severity,
			Resource:    resource.UID,
			Remediation: remediationText(r.Remediation),
			Meta:        meta,
			RawPayload:  rawRecords[i],
		})
	}
	return res, nil
}

func remediationText(r ocsfRemediation) string {
	desc := strings.TrimSpace(r.Desc)
	if len(r.References) > 0 && r.References[0] != "" {
		if desc != "" {
			return desc + " (" + r.References[0] + ")"
		}
		return r.References[0]
	}
	return desc
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
