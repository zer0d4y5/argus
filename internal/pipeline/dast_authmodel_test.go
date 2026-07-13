package pipeline

import (
	"testing"

	"github.com/zer0d4y5/argus/internal/dastauth"
	"github.com/zer0d4y5/argus/internal/model"
)

func TestAuthModelFindings(t *testing.T) {
	m := dastauth.AuthModel{
		SetCookies: []dastauth.CookieInfo{
			{Name: "PHPSESSID", HTTPOnly: false, Secure: false, SameSite: ""}, // all three
			{Name: "csrftoken", HTTPOnly: true, Secure: true, SameSite: "Lax"}, // not a session cookie name -> skipped
			{Name: "theme", HTTPOnly: false},                                   // not session-ish -> skipped
		},
	}

	// Over HTTP, Secure is not expected: HttpOnly + SameSite only.
	http := authModelFindings(m, "http://t/", func(string) {})
	if got := ruleSet(http); got["session-cookie-secure:PHPSESSID"] {
		t.Error("Secure must not be flagged over plain HTTP")
	}
	if !ruleSet(http)["session-cookie-httponly:PHPSESSID"] || !ruleSet(http)["session-cookie-samesite:PHPSESSID"] {
		t.Errorf("expected HttpOnly + SameSite findings over http, got %v", ruleSet(http))
	}
	if len(http) != 2 {
		t.Errorf("expected exactly 2 findings over http (session cookie only), got %d", len(http))
	}

	// Over HTTPS, the missing Secure flag is also a finding.
	https := authModelFindings(m, "https://t/", func(string) {})
	if !ruleSet(https)["session-cookie-secure:PHPSESSID"] {
		t.Error("missing Secure over HTTPS must be flagged")
	}
	if len(https) != 3 {
		t.Errorf("expected 3 findings over https, got %d", len(https))
	}
}

func ruleSet(fs []model.RawFinding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}
