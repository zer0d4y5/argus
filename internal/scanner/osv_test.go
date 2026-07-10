package scanner

import (
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

// A trimmed but real-shaped osv-scanner JSON document: one npm package with a
// CVE-aliased vuln (severity + fix) and one Go package with an unfixed,
// severity-less advisory.
const osvJSON = `{
  "results": [
    {
      "source": {"path": "package-lock.json"},
      "packages": [
        {
          "package": {"name": "lodash", "version": "4.17.11", "ecosystem": "npm"},
          "vulnerabilities": [
            {"id": "GHSA-jf85-cpcp-j695", "summary": "Prototype Pollution in lodash",
             "details": "lodash is vulnerable to prototype pollution.",
             "aliases": ["CVE-2019-10744"],
             "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}]}
          ],
          "groups": [{"ids": ["GHSA-jf85-cpcp-j695"], "max_severity": "9.1"}]
        }
      ]
    },
    {
      "source": {"path": "go.mod"},
      "packages": [
        {
          "package": {"name": "golang.org/x/crypto", "version": "0.54.0", "ecosystem": "Go"},
          "vulnerabilities": [
            {"id": "GO-2026-5932", "summary": "openpgp unmaintained", "details": "unmaintained",
             "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
          ],
          "groups": [{"ids": ["GO-2026-5932"], "max_severity": ""}]
        }
      ]
    }
  ]
}`

func TestParseOSV(t *testing.T) {
	fs, err := parseOSV([]byte(osvJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}

	byID := map[string]model.RawFinding{}
	for _, f := range fs {
		byID[f.RuleID] = f
	}

	// The npm vuln: rule id is the CVE alias (for dedup with trivy), severity is
	// banded from the CVSS score, the fix is surfaced, and the CVE is set.
	lodash, ok := byID["CVE-2019-10744"]
	if !ok {
		t.Fatalf("npm vuln not keyed by its CVE alias: %v", byID)
	}
	if lodash.Tool != "osv-scanner" || lodash.Category != model.CategorySCA {
		t.Errorf("tool/category wrong: %s/%s", lodash.Tool, lodash.Category)
	}
	if lodash.RawSeverity != "critical" {
		t.Errorf("severity = %q, want critical (score 9.1)", lodash.RawSeverity)
	}
	if lodash.Package != "lodash@4.17.11" {
		t.Errorf("package = %q", lodash.Package)
	}
	if lodash.CVE != "CVE-2019-10744" {
		t.Errorf("cve = %q", lodash.CVE)
	}
	if lodash.Remediation != "Upgrade lodash to 4.17.12" {
		t.Errorf("remediation = %q", lodash.Remediation)
	}
	if lodash.Meta["ecosystem"] != "npm" || lodash.Meta["source"] != "package-lock.json" {
		t.Errorf("meta = %v", lodash.Meta)
	}

	// The Go advisory: no CVE alias, so the rule id falls back to the OSV id;
	// no CVSS, so severity is empty (the pipeline will treat it as medium); no
	// fix, so no remediation.
	goVuln, ok := byID["GO-2026-5932"]
	if !ok {
		t.Fatalf("go advisory not keyed by its OSV id: %v", byID)
	}
	if goVuln.RawSeverity != "" {
		t.Errorf("severity = %q, want empty", goVuln.RawSeverity)
	}
	if goVuln.CVE != "" {
		t.Errorf("cve = %q, want empty (no CVE alias)", goVuln.CVE)
	}
	if goVuln.Remediation != "" {
		t.Errorf("remediation = %q, want empty (no fix)", goVuln.Remediation)
	}
}

func TestParseOSVEmpty(t *testing.T) {
	fs, err := parseOSV([]byte(`{"results":[]}`))
	if err != nil || len(fs) != 0 {
		t.Fatalf("empty results: err=%v n=%d", err, len(fs))
	}
}

func TestBandFromScore(t *testing.T) {
	cases := map[string]string{"9.8": "critical", "7.0": "high", "5.5": "medium", "2.1": "low", "0": "", "": "", "bad": ""}
	for in, want := range cases {
		if got := bandFromScore(in); got != want {
			t.Errorf("bandFromScore(%q) = %q, want %q", in, got, want)
		}
	}
}
