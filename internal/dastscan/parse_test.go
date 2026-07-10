package dastscan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

// realLine is a nuclei -jsonl record captured verbatim from a live scan
// (v3.9.0), trimmed to the fields the parser reads plus the sensitive fields
// it must ignore (request/response/curl-command/template-encoded/
// extracted-results). It pins the parser to nuclei's actual schema.
const realLine = `{"template":"http/misconfiguration/http-missing-security-headers.yaml","template-id":"http-missing-security-headers","template-encoded":"aWQ6IGh0dHAtbWlzc2luZy1zZWN1cml0eS1oZWFkZXJz","info":{"name":"HTTP Missing Security Headers","author":["socketz"],"tags":["misconfig","headers","generic"],"description":"This template searches for missing HTTP security headers.\n","severity":"info","classification":{"cve-id":null,"cwe-id":["cwe-693"]}},"matcher-name":"content-security-policy","type":"http","host":"127.0.0.1","port":"8889","scheme":"http","url":"http://127.0.0.1:8889/","matched-at":"http://127.0.0.1:8889/","request":"GET / HTTP/1.1\r\nHost: 127.0.0.1:8889\r\n\r\n","response":"HTTP/1.1 200 OK\r\nSet-Cookie: SESSION=super-secret-token\r\n\r\n<html>nginx</html>","curl-command":"curl http://127.0.0.1:8889/","extracted-results":["leaked-value-from-response"],"ip":"127.0.0.1"}`

func TestParseNucleiRealRecord(t *testing.T) {
	fs, err := parseNuclei([]byte(realLine), false)
	if err != nil {
		t.Fatalf("parseNuclei: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	f := fs[0]
	if f.Tool != "nuclei" || f.Category != model.CategoryDAST {
		t.Errorf("tool/category = %q/%q", f.Tool, f.Category)
	}
	// matcher-name folds into the rule id and title so per-matcher hits stay
	// distinct.
	if f.RuleID != "http-missing-security-headers:content-security-policy" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if !strings.Contains(f.Title, "content-security-policy") {
		t.Errorf("title missing matcher: %q", f.Title)
	}
	if f.RawSeverity != "info" {
		t.Errorf("rawSeverity = %q", f.RawSeverity)
	}
	if f.URL != "http://127.0.0.1:8889/" {
		t.Errorf("url = %q", f.URL)
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != "cwe-693" {
		t.Errorf("cwes = %v", f.CWEs)
	}
	if f.Meta["tags"] != "misconfig,headers,generic" || f.Meta["nucleiType"] != "http" {
		t.Errorf("meta = %v", f.Meta)
	}
}

// TestParseNucleiNoResponseLeak is the load-bearing security test: the live
// app's response bytes, extracted values, request, and curl command must NOT
// appear anywhere on the finding, including RawPayload.
func TestParseNucleiNoResponseLeak(t *testing.T) {
	fs, err := parseNuclei([]byte(realLine), false)
	if err != nil || len(fs) != 1 {
		t.Fatalf("parseNuclei: %v (n=%d)", err, len(fs))
	}
	f := fs[0]
	blob := f.Title + "\x00" + f.Description + "\x00" + f.RuleID + "\x00" +
		f.URL + "\x00" + f.Remediation + "\x00" + string(f.RawPayload)
	for k, v := range f.Meta {
		blob += "\x00" + k + "\x00" + v
	}
	for _, secret := range []string{
		"super-secret-token", // Set-Cookie in the response
		"leaked-value-from-response",
		"HTTP/1.1 200",       // response status line
		"GET / HTTP/1.1",     // request line
		"curl ",              // curl-command
		"template-encoded",   // the base64 template blob key
		"aWQ6IGh0dHAt",       // its value
	} {
		if strings.Contains(blob, secret) {
			t.Errorf("sensitive content leaked into the finding: %q", secret)
		}
	}
	// RawPayload must be the whitelisted shape, not the raw nuclei object.
	var sp map[string]any
	if err := json.Unmarshal(f.RawPayload, &sp); err != nil {
		t.Fatalf("rawPayload not JSON: %v", err)
	}
	for _, banned := range []string{"request", "response", "curl-command", "extracted-results", "template-encoded"} {
		if _, ok := sp[banned]; ok {
			t.Errorf("rawPayload carries banned key %q", banned)
		}
	}
}

// TestParseNucleiClassificationShapes pins the string|[]string|null variance
// of cve-id/cwe-id/reference across templates.
func TestParseNucleiClassificationShapes(t *testing.T) {
	line := `{"template-id":"CVE-2021-1234","info":{"name":"Example CVE","severity":"high","reference":"https://example.com/adv","classification":{"cve-id":["CVE-2021-1234"],"cwe-id":"cwe-89"}},"matched-at":"https://t/x?p=1","type":"http"}`
	fs, err := parseNuclei([]byte(line), false)
	if err != nil || len(fs) != 1 {
		t.Fatalf("parseNuclei: %v (n=%d)", err, len(fs))
	}
	f := fs[0]
	if f.CVE != "CVE-2021-1234" {
		t.Errorf("cve = %q (from a list)", f.CVE)
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != "cwe-89" {
		t.Errorf("cwes = %v (from a bare string)", f.CWEs)
	}
	if f.Meta["reference"] != "https://example.com/adv" {
		t.Errorf("reference = %q (from a bare string)", f.Meta["reference"])
	}
	if f.RuleID != "CVE-2021-1234" {
		t.Errorf("ruleID with no matcher = %q, want bare template id", f.RuleID)
	}
}

func TestParseNucleiSkipsMalformed(t *testing.T) {
	data := "not json\n" +
		`{"template-id":"","info":{"name":"no id"}}` + "\n" + // empty id -> skip
		`{"template-id":"ok","info":{"name":"Kept","severity":"low"},"matched-at":"http://t/"}` + "\n" +
		"\n" // blank line
	fs, err := parseNuclei([]byte(data), false)
	if err != nil {
		t.Fatalf("parseNuclei: %v", err)
	}
	if len(fs) != 1 || fs[0].RuleID != "ok" {
		t.Fatalf("got %d findings, want 1 (the valid one); %+v", len(fs), fs)
	}
}

func TestParseNucleiEmpty(t *testing.T) {
	fs, err := parseNuclei(nil, false)
	if err != nil || len(fs) != 0 {
		t.Errorf("empty input = %v, %d findings", err, len(fs))
	}
}

func TestValidateURL(t *testing.T) {
	for _, ok := range []string{"http://x", "https://staging.example.com", "https://h:8443/path?q=1"} {
		if err := ValidateURL(ok); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"", "ftp://x", "file:///etc/passwd", "gopher://x", "//x", "example.com",
		"http://", "https://user:pass@host",
	} {
		if err := ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error", bad)
		}
	}
}
