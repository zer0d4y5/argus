package mitigation

import (
	"strings"
	"testing"
)

// TestDataLoadsAndIsWellFormed loads every embedded entry and enforces the
// invariants the console relies on: an id, a title, at least one CWE and
// snippet, and snippets that actually differ vulnerable-vs-secure.
func TestDataLoadsAndIsWellFormed(t *testing.T) {
	all := List()
	if len(all) < 5 {
		t.Fatalf("expected the library to have several entries, got %d", len(all))
	}
	for _, g := range all {
		if g.Weakness == "" || g.Title == "" || g.Principle == "" {
			t.Errorf("%q: missing id/title/principle", g.Weakness)
		}
		if len(g.CWEs) == 0 {
			t.Errorf("%q: no CWEs (nothing would map to it)", g.Weakness)
		}
		if len(g.Snippets) == 0 {
			t.Errorf("%q: no snippets", g.Weakness)
		}
		for _, s := range g.Snippets {
			if s.Language == "" || s.Vulnerable == "" || s.Secure == "" {
				t.Errorf("%q/%s: snippet missing language/vulnerable/secure", g.Weakness, s.Language)
			}
			if s.Vulnerable == s.Secure {
				t.Errorf("%q/%s: vulnerable and secure are identical", g.Weakness, s.Language)
			}
		}
		for _, r := range g.References {
			if !strings.HasPrefix(r.URL, "https://") {
				t.Errorf("%q: reference %q is not https", g.Weakness, r.Title)
			}
		}
	}
}

func TestLookupByCWEAndLanguage(t *testing.T) {
	// CWE-89 → sqli, and the python snippet is promoted.
	g, ok := Lookup([]string{"CWE-89"}, "python")
	if !ok || g.Weakness != "sqli" {
		t.Fatalf("CWE-89 lookup = %q ok=%v, want sqli", g.Weakness, ok)
	}
	if g.MatchedLanguage != "python" {
		t.Errorf("MatchedLanguage = %q, want python", g.MatchedLanguage)
	}

	// TypeScript folds to the javascript snippet.
	g, ok = Lookup([]string{"CWE-79"}, "typescript")
	if !ok || g.Weakness != "xss" || g.MatchedLanguage != "javascript" {
		t.Errorf("CWE-79/ts = %q lang=%q ok=%v, want xss/javascript", g.Weakness, g.MatchedLanguage, ok)
	}

	// Bare number normalizes; unknown language still returns guidance (no match).
	g, ok = Lookup([]string{"918"}, "cobol")
	if !ok || g.Weakness != "ssrf" || g.MatchedLanguage != "" {
		t.Errorf("918/cobol = %q lang=%q ok=%v, want ssrf/empty", g.Weakness, g.MatchedLanguage, ok)
	}

	// Unmapped CWE → not found.
	if _, ok := Lookup([]string{"CWE-1004"}, "go"); ok {
		t.Error("CWE-1004 should not map to any weakness")
	}
	// First mapped CWE wins when several are present.
	if g, ok := Lookup([]string{"CWE-1004", "CWE-352"}, "go"); !ok || g.Weakness != "csrf" {
		t.Errorf("mixed CWEs = %q, want csrf", g.Weakness)
	}
}

// TestCWEsAreUnique enforces the invariant the load guard now rejects: no two
// weakness classes may claim the same CWE, or Lookup would misroute a finding's
// guidance depending on file read order.
func TestCWEsAreUnique(t *testing.T) {
	if err := ensureLoaded(); err != nil {
		t.Fatalf("library failed to load: %v", err)
	}
	seen := map[string]string{}
	for _, g := range List() {
		for _, c := range g.CWEs {
			nc := normalizeCWE(c)
			if prev, dup := seen[nc]; dup {
				t.Errorf("%s maps to both %q and %q", nc, prev, g.Weakness)
			}
			seen[nc] = g.Weakness
		}
	}
}

// TestOpenRedirectRejectsBackslash is a tripwire: every open-redirect secure
// snippet must guard the "/\evil.com" form (a backslash browsers normalize to
// "/"), not only "//". A revert that drops the backslash check reopens the
// bypass, so each secure snippet must reference a backslash.
func TestOpenRedirectRejectsBackslash(t *testing.T) {
	g, ok := Get("open-redirect")
	if !ok {
		t.Fatal("open-redirect entry missing")
	}
	for _, s := range g.Snippets {
		if !strings.Contains(s.Secure, `\`) {
			t.Errorf("open-redirect/%s secure snippet has no backslash guard: %q", s.Language, s.Secure)
		}
	}
}

func TestLanguageForFile(t *testing.T) {
	cases := map[string]string{
		"app/db.py": "python", "src/x.tsx": "javascript", "Main.java": "java",
		"cmd/s.go": "go", "a.rb": "ruby", "i.php": "php", "P.cs": "csharp", "README.md": "",
	}
	for path, want := range cases {
		if got := LanguageForFile(path); got != want {
			t.Errorf("LanguageForFile(%q) = %q, want %q", path, got, want)
		}
	}
}
