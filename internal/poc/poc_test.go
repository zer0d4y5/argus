package poc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/model"
)

func TestCurlGETWithCookiePlaceholder(t *testing.T) {
	got := Curl(Request{Method: "GET", URL: "http://t/app?id=1", CookiePresent: true})
	if !strings.Contains(got, "'http://t/app?id=1'") {
		t.Fatalf("curl missing quoted URL: %q", got)
	}
	if strings.Contains(got, "-X") {
		t.Fatalf("GET should not carry -X: %q", got)
	}
	if !strings.Contains(got, CookiePlaceholder) {
		t.Fatalf("authenticated curl must show the cookie placeholder: %q", got)
	}
}

func TestCurlPOSTWithBody(t *testing.T) {
	got := Curl(Request{Method: "post", URL: "http://t/exec", Body: "ip=127.0.0.1&Submit=go"})
	for _, want := range []string{"-X POST", "'http://t/exec'", "--data 'ip=127.0.0.1&Submit=go'"} {
		if !strings.Contains(got, want) {
			t.Fatalf("curl %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "Cookie:") {
		t.Fatalf("unauthenticated curl must not add a Cookie header: %q", got)
	}
}

func TestShellQuoteEscapesSingleQuote(t *testing.T) {
	got := Curl(Request{Method: "GET", URL: "http://t/?q=a'b"})
	if !strings.Contains(got, `'http://t/?q=a'\''b'`) {
		t.Fatalf("single quote not escaped: %q", got)
	}
}

func TestRawHTTPParsesTargetAndHost(t *testing.T) {
	got := RawHTTP(Request{Method: "GET", URL: "http://example.com/a/b?x=1&y=2", CookiePresent: true})
	for _, want := range []string{"GET /a/b?x=1&y=2 HTTP/1.1", "Host: example.com", "Cookie: " + CookiePlaceholder} {
		if !strings.Contains(got, want) {
			t.Fatalf("raw http %q missing %q", got, want)
		}
	}
}

func TestRawHTTPPostBody(t *testing.T) {
	got := RawHTTP(Request{Method: "POST", URL: "http://example.com/exec", Body: "ip=1"})
	if !strings.Contains(got, "POST /exec HTTP/1.1") ||
		!strings.Contains(got, "Content-Type: application/x-www-form-urlencoded") ||
		!strings.HasSuffix(got, "\n\nip=1") {
		t.Fatalf("raw http post malformed: %q", got)
	}
}

func TestBuildNilOnEmptyURL(t *testing.T) {
	if p := Build("sqli", Request{Method: "GET"}, "id", "x"); p != nil {
		t.Fatalf("expected nil proof for empty URL, got %+v", p)
	}
}

func TestClassForCWEs(t *testing.T) {
	cases := map[string]string{"CWE-89": "sqli", "CWE-79": "xss", "CWE-78": "cmdi", "CWE-200": ""}
	for cwe, want := range cases {
		if got := ClassForCWEs([]string{cwe}); got != want {
			t.Errorf("ClassForCWEs(%s)=%q want %q", cwe, got, want)
		}
	}
}

func TestAttachToRawSQLmapFinding(t *testing.T) {
	raw := []model.RawFinding{{
		Tool:     "sqlmap",
		Category: model.CategoryDAST,
		URL:      "http://t/vuln?id=1",
		CWEs:     []string{"CWE-89"},
		Meta:     map[string]string{"param": "id", "place": "GET", "dbms": "MySQL"},
	}}
	AttachToRaw(raw, nil, true)
	p := raw[0].Proof
	if p == nil {
		t.Fatal("expected a proof for the sqlmap finding")
	}
	if !strings.Contains(p.Curl, CookiePlaceholder) {
		t.Errorf("authenticated proof must show cookie placeholder: %q", p.Curl)
	}
	if !strings.Contains(p.Rationale, "id parameter") {
		t.Errorf("rationale should name the parameter: %q", p.Rationale)
	}
	if !strings.Contains(p.Observed, "MySQL") {
		t.Errorf("observed should carry the DBMS: %q", p.Observed)
	}
}

func TestAttachToRawPostBodyFromMap(t *testing.T) {
	raw := []model.RawFinding{{
		Tool:     "dalfox",
		Category: model.CategoryDAST,
		URL:      "http://t/xss",
		CWEs:     []string{"CWE-79"},
		Meta:     map[string]string{"param": "name", "method": "POST", "dalfoxType": "R"},
	}}
	bodies := BodiesFromEndpoints([]Endpoint{{Method: "POST", URL: "http://t/xss", Body: "name=a&csrf=x"}})
	AttachToRaw(raw, bodies, false)
	p := raw[0].Proof
	if p == nil {
		t.Fatal("expected a proof")
	}
	if !strings.Contains(p.Curl, "--data 'name=a&csrf=x'") {
		t.Errorf("proof should reproduce the POST body: %q", p.Curl)
	}
}

func TestAttachToRawSkipsNonDASTAndPrebuilt(t *testing.T) {
	prebuilt := &model.Proof{Observed: "kept"}
	raw := []model.RawFinding{
		{Category: model.CategorySAST, CWEs: []string{"CWE-89"}, URL: "http://t/?id=1", Meta: map[string]string{"param": "id"}},
		{Category: model.CategoryDAST, CWEs: []string{"CWE-89"}, URL: "http://t/?id=1", Meta: map[string]string{"param": "id"}, Proof: prebuilt},
		{Category: model.CategoryDAST, CWEs: []string{"CWE-200"}, URL: "http://t/", Meta: map[string]string{}},
	}
	AttachToRaw(raw, nil, false)
	if raw[0].Proof != nil {
		t.Error("SAST finding must not get a DAST proof")
	}
	if raw[1].Proof != prebuilt {
		t.Error("a pre-built proof must be left untouched")
	}
	if raw[2].Proof != nil {
		t.Error("a finding with no reproduction class must not get a proof")
	}
}

// TestProofNeverCarriesLiteralCookie is the safety property: the builder is
// given only a boolean, never the live session value, so a rendered proof
// cannot leak a credential by construction.
func TestProofNeverCarriesLiteralCookie(t *testing.T) {
	p := Build("cmdi", Request{Method: "POST", URL: "http://t/exec", Body: "ip=1;id", CookiePresent: true}, "ip", "shell ran")
	blob, _ := json.Marshal(p)
	// The only cookie token present must be the placeholder.
	if strings.Count(string(blob), "Cookie") != strings.Count(string(blob), CookiePlaceholder) {
		t.Fatalf("a Cookie appears without the placeholder: %s", blob)
	}
}
