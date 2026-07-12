package engagement

import "testing"

func TestInScope(t *testing.T) {
	eng := &Engagement{
		Scope: Scope{
			InScope: []string{
				"staging.example.com",         // bare host, any port
				"api.example.com:8443",        // host:port
				"10.0.0.0/24",                 // CIDR (IP-literal targets only)
				"https://app.example.com/v2/", // URL-prefix
				"*.corp.example.com",          // subdomain wildcard
			},
			OutOfScope: []string{
				"admin.staging.example.com", // an exclusion inside the wildcard-free host set
				"https://app.example.com/v2/danger",
			},
		},
	}

	cases := []struct {
		name string
		url  string
		want bool
	}{
		{"bare host any port", "https://staging.example.com/login", true},
		{"bare host explicit port", "https://staging.example.com:8080/x", true},
		{"host:port match", "https://api.example.com:8443/data", true},
		{"host:port wrong port", "https://api.example.com:9000/data", false},
		{"host:port default mismatch", "https://api.example.com/data", false},
		{"cidr member", "http://10.0.0.5/x", true},
		{"cidr non-member", "http://10.0.1.5/x", false},
		{"cidr vs hostname never matches", "http://example.com/x", false},
		{"url-prefix under", "https://app.example.com/v2/users?id=1", true},
		{"url-prefix exact", "https://app.example.com/v2", true},
		{"url-prefix sibling not matched", "https://app.example.com/v20/x", false},
		{"url-prefix wrong scheme", "http://app.example.com/v2/users", false},
		{"wildcard subdomain", "https://host1.corp.example.com/x", true},
		{"wildcard deep subdomain", "https://a.b.corp.example.com/x", true},
		{"wildcard apex not matched", "https://corp.example.com/x", false},
		{"exclusion wins over host", "https://admin.staging.example.com/x", false},
		{"exclusion wins over prefix", "https://app.example.com/v2/danger/thing", false},
		{"out of scope entirely", "https://evil.example.org/x", false},
		{"non-http scheme refused", "file:///etc/passwd", false},
		{"gopher refused", "gopher://staging.example.com/", false},
		{"unparseable refused", "://::::", false},
		{"empty refused", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := eng.InScope(c.url); got != c.want {
				t.Errorf("InScope(%q) = %v, want %v", c.url, got, c.want)
			}
		})
	}
}

func TestInScopeExclusionInsidePrefix(t *testing.T) {
	// The /v2/danger exclusion must beat the /v2/ inclusion for a path under it.
	eng := &Engagement{Scope: Scope{
		InScope:    []string{"https://app.example.com/v2/"},
		OutOfScope: []string{"https://app.example.com/v2/danger"},
	}}
	if eng.InScope("https://app.example.com/v2/danger/x") {
		t.Error("path under an excluded prefix must be out of scope")
	}
	if !eng.InScope("https://app.example.com/v2/safe") {
		t.Error("path under the included prefix (not excluded) must be in scope")
	}
}

func TestInScopeNilEngagement(t *testing.T) {
	var e *Engagement
	if e.InScope("https://x/") {
		t.Error("a nil engagement is never in scope")
	}
}

func TestValidateScope(t *testing.T) {
	if err := validateScope(Scope{}); err == nil {
		t.Error("empty in-scope must be rejected")
	}
	good := Scope{InScope: []string{"h.example.com", "10.0.0.0/8", "https://x.example.com/a", "*.y.example.com"}}
	if err := validateScope(good); err != nil {
		t.Errorf("valid scope rejected: %v", err)
	}
	bad := Scope{InScope: []string{"10.0.0.0/999"}}
	if err := validateScope(bad); err == nil {
		t.Error("malformed CIDR must be rejected")
	}
	badURL := Scope{InScope: []string{"https://"}}
	if err := validateScope(badURL); err == nil {
		t.Error("host-less URL-prefix must be rejected")
	}
}
