package dastscan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// nucleiResult is the subset of nuclei's JSONL record we read. nuclei emits
// one JSON object per line (`-jsonl`). Fields not listed here (request,
// response, curl-command, template-encoded, extracted-results) are
// deliberately NOT decoded: they carry the live app's response bytes and must
// never reach a finding. See the package doc SECURITY note.
type nucleiResult struct {
	TemplateID  string     `json:"template-id"`
	Template    string     `json:"template"`
	Type        string     `json:"type"` // http | dns | tcp | ...
	MatcherName string     `json:"matcher-name"`
	MatchedAt   string     `json:"matched-at"`
	URL         string     `json:"url"`
	Host        string     `json:"host"`
	Port        string     `json:"port"`
	Info        nucleiInfo `json:"info"`
	// Request/Response and the fuzzing locus are decoded ONLY to build opt-in,
	// redacted evidence. They are never written to a finding unless evidence
	// capture is enabled (see buildEvidence); the default path drops them.
	Request          string `json:"request"`
	Response         string `json:"response"`
	FuzzingParameter string `json:"fuzzing_parameter"`
	FuzzingPosition  string `json:"fuzzing_position"`
}

// nucleiInfo is the template's `info` block.
type nucleiInfo struct {
	Name           string               `json:"name"`
	Description    string               `json:"description"`
	Severity       string               `json:"severity"`
	Tags           []string             `json:"tags"`
	Reference      json.RawMessage      `json:"reference"` // string OR []string across templates
	Remediation    string               `json:"remediation"`
	Classification nucleiClassification `json:"classification"`
}

type nucleiClassification struct {
	CVEID json.RawMessage `json:"cve-id"` // null | string | []string
	CWEID json.RawMessage `json:"cwe-id"` // null | string | []string
}

// safePayload is the whitelisted RawPayload for a DAST finding: identity and
// classification only, never request/response/extracted bodies.
type safePayload struct {
	TemplateID  string   `json:"templateId"`
	Template    string   `json:"template,omitempty"`
	Type        string   `json:"type,omitempty"`
	MatcherName string   `json:"matcherName,omitempty"`
	MatchedAt   string   `json:"matchedAt,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	CVE         string   `json:"cve,omitempty"`
}

// parseNuclei maps nuclei JSONL into raw findings. Split out from Scan so it
// is unit-testable without invoking the binary. A malformed line is skipped,
// never fatal, so one bad record does not lose the whole run. When evidence is
// true, each finding also carries the redacted request/response (opt-in).
func parseNuclei(data []byte, evidence bool) ([]model.RawFinding, error) {
	var findings []model.RawFinding
	sc := bufio.NewScanner(bytes.NewReader(data))
	// nuclei records can be large (matcher lists); raise the line cap well
	// above bufio's 64KiB default so a big record is parsed, not truncated.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r nucleiResult
		if err := json.Unmarshal(line, &r); err != nil || r.TemplateID == "" {
			continue // skip only the malformed entry
		}

		// Identity: the template id, plus the matcher name when nuclei reports
		// one. A template like http-missing-security-headers fires once per
		// missing header (same template id, different matcher-name); folding
		// the matcher into the rule id keeps those distinct findings distinct
		// in the fingerprint instead of collapsing to one.
		ruleID := r.TemplateID
		if r.MatcherName != "" {
			ruleID = r.TemplateID + ":" + r.MatcherName
		}

		title := strings.TrimSpace(r.Info.Name)
		if r.MatcherName != "" && title != "" {
			title = title + " (" + r.MatcherName + ")"
		}

		meta := map[string]string{}
		if r.Type != "" {
			meta["nucleiType"] = r.Type
		}
		if len(r.Info.Tags) > 0 {
			meta["tags"] = strings.Join(r.Info.Tags, ",")
		}
		if ref := firstStringOrList(r.Info.Reference); ref != "" {
			meta["reference"] = ref
		}
		if len(meta) == 0 {
			meta = nil
		}

		cwes := allStringsOrList(r.Info.Classification.CWEID)
		cve := firstStringOrList(r.Info.Classification.CVEID)

		payload, _ := json.Marshal(safePayload{
			TemplateID:  r.TemplateID,
			Template:    r.Template,
			Type:        r.Type,
			MatcherName: r.MatcherName,
			MatchedAt:   locationURL(r),
			Severity:    r.Info.Severity,
			Tags:        r.Info.Tags,
			CWEs:        cwes,
			CVE:         cve,
		})

		var ev *model.Evidence
		if evidence {
			ev = buildEvidence(r)
		}
		findings = append(findings, model.RawFinding{
			Tool:        "nuclei",
			Category:    model.CategoryDAST,
			RuleID:      ruleID,
			Title:       title,
			Description: strings.TrimSpace(r.Info.Description),
			RawSeverity: r.Info.Severity,
			URL:         locationURL(r),
			CWEs:        cwes,
			CVE:         cve,
			Remediation: strings.TrimSpace(r.Info.Remediation),
			Meta:        meta,
			RawPayload:  payload,
			Evidence:    ev,
		})
	}
	if err := sc.Err(); err != nil {
		return findings, nil // partial results beat none; the scan still ran
	}
	return findings, nil
}

// locationURL is the most specific target for a finding: the matched-at URL,
// then the reported url, then a reconstructed host:port.
func locationURL(r nucleiResult) string {
	if r.MatchedAt != "" {
		return r.MatchedAt
	}
	if r.URL != "" {
		return r.URL
	}
	if r.Host != "" && r.Port != "" {
		return r.Host + ":" + r.Port
	}
	return r.Host
}

// firstStringOrList decodes a JSON value that may be a string, a list of
// strings, or null, returning the first non-empty string. nuclei's cve-id and
// reference fields vary this shape across templates.
func firstStringOrList(raw json.RawMessage) string {
	all := allStringsOrList(raw)
	if len(all) > 0 {
		return all[0]
	}
	return ""
}

// allStringsOrList decodes a string | []string | null into a slice.
func allStringsOrList(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one = strings.TrimSpace(one); one != "" {
			return []string{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		var out []string
		for _, s := range many {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
