// Package mitigation is Argus's open-source secure-coding library: for each
// common weakness class (SQL injection, XSS, SSRF, CSRF, session management,
// command injection, path traversal, …) it holds hand-curated, per-language
// before/after code, the library to reach for, the one principle that fixes
// the class, and authoritative references.
//
// It is deliberately NOT the LLM remediation seam. That generates a bespoke
// fix per finding and must be reviewed; this is fixed, reviewed-once guidance
// you can trust the way you trust the OWASP cheat sheets it cites. The two
// complement each other: the library tells you the right shape of the fix, the
// LLM adapts it to your exact code.
//
// The data lives in data/*.json, embedded at build time. Adding a weakness or a
// language is a data-only change — drop in JSON, no code — which is the point:
// a growing, contributable countermeasure library.
package mitigation

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

//go:embed data/*.json
var dataFS embed.FS

// Reference is an authoritative source for a weakness class.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Snippet is the fix for one language: the vulnerable shape, the secure shape,
// the library that carries the fix, and a short note.
type Snippet struct {
	Language   string `json:"language"`
	Library    string `json:"library,omitempty"`
	Vulnerable string `json:"vulnerable"`
	Secure     string `json:"secure"`
	Note       string `json:"note,omitempty"`
}

// Guidance is the whole entry for one weakness class.
type Guidance struct {
	Weakness   string      `json:"weakness"`
	Title      string      `json:"title"`
	CWEs       []string    `json:"cwes"`
	Principle  string      `json:"principle"`
	Snippets   []Snippet   `json:"snippets"`
	References []Reference `json:"references"`

	// MatchedLanguage is set by Lookup to the snippet language chosen for the
	// requesting finding (empty if the library has no snippet in that language,
	// in which case the caller shows the principle + all snippets).
	MatchedLanguage string `json:"matchedLanguage,omitempty"`
}

var (
	loadOnce sync.Once
	loadErr  error
	byWeak   map[string]Guidance // weakness id -> entry
	byCWE    map[string]string   // CWE id -> weakness id
	order    []string            // weakness ids, sorted for stable listing
)

func load() {
	entries, err := dataFS.ReadDir("data")
	if err != nil {
		loadErr = fmt.Errorf("mitigation: read data dir: %w", err)
		return
	}
	byWeak = map[string]Guidance{}
	byCWE = map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := dataFS.ReadFile("data/" + e.Name())
		if err != nil {
			loadErr = fmt.Errorf("mitigation: read %s: %w", e.Name(), err)
			return
		}
		var g Guidance
		if err := json.Unmarshal(raw, &g); err != nil {
			loadErr = fmt.Errorf("mitigation: parse %s: %w", e.Name(), err)
			return
		}
		if g.Weakness == "" {
			loadErr = fmt.Errorf("mitigation: %s has no weakness id", e.Name())
			return
		}
		if _, dup := byWeak[g.Weakness]; dup {
			loadErr = fmt.Errorf("mitigation: duplicate weakness id %q", g.Weakness)
			return
		}
		byWeak[g.Weakness] = g
		for _, c := range g.CWEs {
			nc := normalizeCWE(c)
			if prev, dup := byCWE[nc]; dup {
				// Two classes claiming the same CWE would make Lookup depend on
				// file read order and silently misroute a finding's guidance.
				loadErr = fmt.Errorf("mitigation: %s maps to both %q and %q", nc, prev, g.Weakness)
				return
			}
			byCWE[nc] = g.Weakness
		}
		order = append(order, g.Weakness)
	}
	sort.Strings(order)
}

func ensureLoaded() error {
	loadOnce.Do(load)
	return loadErr
}

// Lookup resolves curated guidance for a finding's CWEs, promoting the snippet
// for lang when the library has one. ok is false when no CWE maps to a known
// weakness class.
func Lookup(cwes []string, lang string) (Guidance, bool) {
	if ensureLoaded() != nil {
		return Guidance{}, false
	}
	lang = canonicalLang(lang)
	for _, c := range cwes {
		weak, ok := byCWE[normalizeCWE(c)]
		if !ok {
			continue
		}
		g := byWeak[weak]
		if lang != "" {
			for _, s := range g.Snippets {
				if s.Language == lang {
					g.MatchedLanguage = lang
					break
				}
			}
		}
		return g, true
	}
	return Guidance{}, false
}

// List returns every weakness's guidance, sorted by id, for browsing.
func List() []Guidance {
	if ensureLoaded() != nil {
		return nil
	}
	out := make([]Guidance, 0, len(order))
	for _, w := range order {
		out = append(out, byWeak[w])
	}
	return out
}

// Get returns one weakness entry by id.
func Get(weakness string) (Guidance, bool) {
	if ensureLoaded() != nil {
		return Guidance{}, false
	}
	g, ok := byWeak[strings.ToLower(weakness)]
	return g, ok
}

func normalizeCWE(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	c = strings.TrimPrefix(c, "CWE-")
	return "CWE-" + strings.TrimSpace(c)
}

// canonicalLang folds a language name or synonym to the library's snippet
// language keys. TypeScript shares JavaScript's fixes; C++ shares C's.
func canonicalLang(l string) string {
	switch strings.ToLower(strings.TrimSpace(l)) {
	case "python", "py":
		return "python"
	case "javascript", "js", "jsx", "typescript", "ts", "tsx", "node":
		return "javascript"
	case "java":
		return "java"
	case "go", "golang":
		return "go"
	case "ruby", "rb":
		return "ruby"
	case "php":
		return "php"
	case "csharp", "c#", "cs", "dotnet":
		return "csharp"
	default:
		return ""
	}
}

// LanguageForFile maps a source path to a canonical language, so the console
// can pick the right snippet from a finding's location.
func LanguageForFile(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return "python"
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return "javascript"
	case ".java":
		return "java"
	case ".go":
		return "go"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".cs":
		return "csharp"
	default:
		return ""
	}
}
