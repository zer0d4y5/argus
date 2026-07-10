package dastscan

import (
	"strings"
	"testing"
)

const rawReq = "GET /vulnerabilities/sqli/?id=1'&Submit=Submit HTTP/1.1\r\n" +
	"Host: localhost\r\n" +
	"Cookie: security=low; PHPSESSID=SECRETSESSION123\r\n" +
	"Authorization: Bearer SECRETTOKEN\r\n" +
	"User-Agent: nuclei\r\n\r\n"

const rawResp = "HTTP/1.1 200 OK\r\n" +
	"Set-Cookie: PHPSESSID=ANOTHERSECRET; path=/\r\n" +
	"Content-Type: text/html\r\n\r\n" +
	"You have an error in your SQL syntax near '''"

func TestRedactHTTPStripsCredentials(t *testing.T) {
	got := redactHTTP(rawReq, maxRequestBytes)
	for _, secret := range []string{"SECRETSESSION123", "SECRETTOKEN"} {
		if strings.Contains(got, secret) {
			t.Errorf("credential %q leaked through redaction:\n%s", secret, got)
		}
	}
	// The evidence itself (method, path, fuzzed payload) is preserved.
	if !strings.Contains(got, "/vulnerabilities/sqli/?id=1'") {
		t.Errorf("request line lost in redaction:\n%s", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Error("redaction marker missing")
	}
}

func TestRedactHTTPStripsSetCookieKeepsBody(t *testing.T) {
	got := redactHTTP(rawResp, maxResponseBytes)
	if strings.Contains(got, "ANOTHERSECRET") {
		t.Errorf("Set-Cookie value leaked:\n%s", got)
	}
	// The response body IS the evidence and must survive.
	if !strings.Contains(got, "error in your SQL syntax") {
		t.Errorf("response body (the evidence) lost:\n%s", got)
	}
}

func TestRedactHTTPBounds(t *testing.T) {
	big := "HTTP/1.1 200 OK\r\n\r\n" + strings.Repeat("A", 100000)
	got := redactHTTP(big, maxResponseBytes)
	if len(got) > maxResponseBytes+32 {
		t.Errorf("evidence not bounded: %d bytes", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Error("truncation marker missing")
	}
}

func TestBuildEvidenceEmpty(t *testing.T) {
	if buildEvidence(nucleiResult{}) != nil {
		t.Error("empty result should yield nil evidence")
	}
}

// The evidence path is opt-in: with evidence=false the parser must not attach
// any request/response, preserving the metadata-only default.
func TestParseNucleiEvidenceOptIn(t *testing.T) {
	line := `{"template-id":"sqli-error-based","info":{"name":"SQLi","severity":"critical"},` +
		`"matched-at":"http://t/x?id=1","type":"http","request":"GET /x HTTP/1.1\r\nCookie: s=SECRET\r\n\r\n",` +
		`"response":"HTTP/1.1 200 OK\r\n\r\nSQL error","fuzzing_parameter":"id"}`

	off, _ := parseNuclei([]byte(line), false)
	if len(off) != 1 || off[0].Evidence != nil {
		t.Fatalf("evidence attached when disabled: %+v", off[0].Evidence)
	}

	on, _ := parseNuclei([]byte(line), true)
	if len(on) != 1 || on[0].Evidence == nil {
		t.Fatal("evidence not attached when enabled")
	}
	ev := on[0].Evidence
	if ev.FuzzParam != "id" {
		t.Errorf("fuzz param = %q, want id", ev.FuzzParam)
	}
	if strings.Contains(ev.Request, "SECRET") {
		t.Errorf("session cookie leaked into evidence request: %q", ev.Request)
	}
	if !strings.Contains(ev.Response, "SQL error") {
		t.Errorf("response evidence missing: %q", ev.Response)
	}
}
