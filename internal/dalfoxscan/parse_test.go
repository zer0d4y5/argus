package dalfoxscan

import (
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// A real dalfox v3 JSONL finding line plus the trailing meta line.
const dalfoxOut = `{"cwe":"CWE-79","data":"http://t/xss_r/?name=%3Csvg%3E","evidence":"DOM verification successful","inject_type":"inHTML","location":"Query","message_id":606,"message_str":"Triggered XSS","method":"GET","param":"name","payload":"<svg onload=alert(1)>","severity":"High","type":"V","type_description":"Verified XSS - payload confirmed executed in parsed DOM"}
{"meta":{"dalfox_version":"3.1.1","findings_count":1,"total_requests":176}}`

func TestParseDalfox(t *testing.T) {
	ep := dastcrawl.Endpoint{URL: "http://t/xss_r/?name=1", Method: "GET"}
	fs := parseDalfox([]byte(dalfoxOut), ep)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Tool != "dalfox" || f.Category != "DAST" {
		t.Errorf("tool/category wrong: %s/%s", f.Tool, f.Category)
	}
	if f.CWEs[0] != "CWE-79" {
		t.Errorf("cwe = %v", f.CWEs)
	}
	if f.Meta["param"] != "name" || f.Meta["method"] != "GET" {
		t.Errorf("meta wrong: %v", f.Meta)
	}
	if f.URL != ep.URL {
		t.Errorf("url = %q, want the endpoint url", f.URL)
	}
	// The raw response/payload must not leak into the finding text.
	blob := f.Title + f.Description
	if strings.Contains(blob, "onload=alert") {
		t.Errorf("payload leaked into finding text: %q", blob)
	}
}

func TestParseDalfoxSkipsMetaAndMalformed(t *testing.T) {
	in := `{"meta":{"findings_count":0}}
not json
{"type":"V"}`
	// meta has no type, "not json" fails, the last has no param -> all skipped.
	if fs := parseDalfox([]byte(in), dastcrawl.Endpoint{URL: "http://t/"}); len(fs) != 0 {
		t.Errorf("want 0 findings, got %d", len(fs))
	}
}

func TestParseDalfoxDedupesPerParam(t *testing.T) {
	// dalfox reports many payloads for one param; we keep one finding per param.
	line := `{"type":"V","param":"name","method":"GET","cwe":"CWE-79","severity":"High","type_description":"Verified XSS"}`
	in := line + "\n" + line + "\n" + line
	if fs := parseDalfox([]byte(in), dastcrawl.Endpoint{URL: "http://t/?name=1"}); len(fs) != 1 {
		t.Errorf("want 1 deduped finding, got %d", len(fs))
	}
}
