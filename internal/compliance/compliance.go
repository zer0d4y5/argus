// Package compliance maps findings to the security-framework controls they
// violate and assesses per-framework control coverage (the gap report).
//
// SECURITY-CRITICAL / REVIEWED DATA: every mapping row in data/*.json is an
// audit claim — a wrong mapping is false audit evidence. The mapping is
// deterministic, hand-curated against the pinned framework text, and versioned
// with the data files. No LLM output enters this path. Same ethos as
// internal/owasp, generalized: conservative, unmapped-is-visible, totals
// reconcile (see docs/compliance.md).
package compliance

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/leaky-hub/argus/internal/model"
)

//go:embed data/*.json
var dataFS embed.FS

// Control is one assessable framework control: a target of at least one
// mapping rule, i.e. a control the scanners can produce evidence against.
type Control struct {
	ID    string `json:"id"` // e.g. "V5.3.4", "6.2.4", "2.1"
	Title string `json:"title"`
}

// NotAssessable is a framework area static scanning cannot assess, declared
// explicitly so the gap report never overclaims coverage.
type NotAssessable struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// Rule maps what findings actually carry to framework controls. Exactly one
// match key (cwes | category | ruleIds | rulePrefixes) must be set.
type Rule struct {
	CWEs         []string `json:"cwes,omitempty"`         // matches any of the finding's normalized CWEs
	Category     string   `json:"category,omitempty"`     // matches the finding category (SAST|SECRET|SCA|IAC)
	RuleIDs      []string `json:"ruleIds,omitempty"`      // exact tool rule IDs
	RulePrefixes []string `json:"rulePrefixes,omitempty"` // tool rule ID prefixes (family defaults)
	Controls     []string `json:"controls"`               // control IDs declared in the framework's controls list
}

// Framework is one embedded framework data file, version-pinned.
type Framework struct {
	ID      string   `json:"id"`      // e.g. "ASVS" — the prefix in complianceControls values
	Name    string   `json:"name"`    // full framework name
	Version string   `json:"version"` // pinned framework version the mappings were reviewed against
	Scope   []string `json:"scope"`   // finding categories this framework can speak to
	// RuleIDScope optionally narrows scope within those categories to rule-ID
	// prefixes. Platform-specific benchmarks need it: a Kubernetes
	// misconfiguration is OUT OF SCOPE for the AWS benchmark, not an AWS
	// mapping gap ("unmapped" must mean "our curation has no answer", never
	// "different platform").
	RuleIDScope []string `json:"ruleIdScope,omitempty"`
	// ProviderScope is RuleIDScope's analogue for CLOUD findings (schema
	// 2.1.0): prowler check IDs carry no provider prefix, but every cloud
	// finding carries meta.provider. An Azure posture finding is OUT OF
	// SCOPE for the AWS benchmark, not unmapped. Applies to CLOUD findings
	// only; empty means every provider is in scope.
	ProviderScope []string        `json:"providerScope,omitempty"`
	Controls      []Control       `json:"controls"`
	NotAssessable []NotAssessable `json:"notAssessable"`
	Rules         []Rule          `json:"rules"`

	controlTitle map[string]string // built by the loader
}

var (
	loadOnce   sync.Once
	frameworks []Framework
	loadErr    error
)

// Frameworks returns all embedded frameworks, loaded and validated once.
// Order is deterministic (data filename order).
func Frameworks() ([]Framework, error) {
	loadOnce.Do(func() { frameworks, loadErr = load() })
	return frameworks, loadErr
}

func load() ([]Framework, error) {
	entries, err := dataFS.ReadDir("data")
	if err != nil {
		return nil, fmt.Errorf("compliance: read embedded data: %w", err)
	}
	var fws []Framework
	seen := map[string]bool{}
	for _, e := range entries {
		raw, err := dataFS.ReadFile("data/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("compliance: read %s: %w", e.Name(), err)
		}
		var fw Framework
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields() // a typo'd key must fail loudly, not silently drop mappings
		if err := dec.Decode(&fw); err != nil {
			return nil, fmt.Errorf("compliance: parse %s: %w", e.Name(), err)
		}
		if err := validate(&fw); err != nil {
			return nil, fmt.Errorf("compliance: %s: %w", e.Name(), err)
		}
		if seen[fw.ID] {
			return nil, fmt.Errorf("compliance: duplicate framework id %q", fw.ID)
		}
		seen[fw.ID] = true
		fws = append(fws, fw)
	}
	if len(fws) == 0 {
		return nil, fmt.Errorf("compliance: no framework data files embedded")
	}
	return fws, nil
}

// validate enforces data integrity: a malformed file is a build defect caught
// here (and by the loader test), never a silently wrong audit claim.
func validate(fw *Framework) error {
	if fw.ID == "" || fw.Name == "" || fw.Version == "" {
		return fmt.Errorf("id, name, and version are required")
	}
	if strings.ContainsAny(fw.ID, ": \t") {
		return fmt.Errorf("framework id %q must not contain colons or spaces", fw.ID)
	}
	if len(fw.Scope) == 0 {
		return fmt.Errorf("scope is required")
	}
	valid := map[string]bool{
		model.CategorySAST: true, model.CategorySecret: true,
		model.CategorySCA: true, model.CategoryIaC: true, model.CategoryDAST: true,
		model.CategoryCloud: true,
	}
	for _, c := range fw.Scope {
		if !valid[c] {
			return fmt.Errorf("unknown category %q in scope", c)
		}
	}
	for _, p := range fw.RuleIDScope {
		if p == "" {
			return fmt.Errorf("ruleIdScope entries must be non-empty")
		}
	}
	for _, p := range fw.ProviderScope {
		if p == "" {
			return fmt.Errorf("providerScope entries must be non-empty")
		}
	}
	fw.controlTitle = make(map[string]string, len(fw.Controls))
	for _, c := range fw.Controls {
		if c.ID == "" || c.Title == "" {
			return fmt.Errorf("control %+v needs id and title", c)
		}
		if _, dup := fw.controlTitle[c.ID]; dup {
			return fmt.Errorf("duplicate control id %q", c.ID)
		}
		fw.controlTitle[c.ID] = c.Title
	}
	referenced := map[string]bool{}
	for i, r := range fw.Rules {
		keys := 0
		if len(r.CWEs) > 0 {
			keys++
		}
		if r.Category != "" {
			keys++
			if !valid[r.Category] {
				return fmt.Errorf("rule %d: unknown category %q", i, r.Category)
			}
		}
		if len(r.RuleIDs) > 0 {
			keys++
		}
		if len(r.RulePrefixes) > 0 {
			keys++
		}
		if keys != 1 {
			return fmt.Errorf("rule %d: exactly one match key required (cwes|category|ruleIds|rulePrefixes), got %d", i, keys)
		}
		if len(r.Controls) == 0 {
			return fmt.Errorf("rule %d: controls must be non-empty", i)
		}
		for _, id := range r.Controls {
			if _, ok := fw.controlTitle[id]; !ok {
				return fmt.Errorf("rule %d: control %q not declared in controls list", i, id)
			}
			referenced[id] = true
		}
	}
	// Every declared control must be reachable by some rule: the controls list
	// is the "assessable by scanning" universe, and an unreachable entry would
	// render as a perpetual, unearned "no violations detected".
	for _, c := range fw.Controls {
		if !referenced[c.ID] {
			return fmt.Errorf("control %q is not referenced by any rule (would always read as clean)", c.ID)
		}
	}
	return nil
}

// inScope reports whether the framework can speak to this finding: category
// must be in Scope, and, when RuleIDScope is set, the rule ID must match one
// of its prefixes (platform benchmarks only speak to their platform's rules).
func (fw *Framework) inScope(f model.Finding) bool {
	ok := false
	for _, c := range fw.Scope {
		if c == f.Category {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if f.Category == model.CategoryCloud {
		// Cloud findings scope by provider (meta.provider), not by rule-ID
		// prefix: prowler check IDs have no provider prefix, and "unmapped"
		// must never mean "different cloud".
		if len(fw.ProviderScope) == 0 {
			return true
		}
		provider := f.Meta["provider"]
		for _, p := range fw.ProviderScope {
			if p == provider {
				return true
			}
		}
		return false
	}
	if len(fw.RuleIDScope) == 0 {
		return true
	}
	for _, p := range fw.RuleIDScope {
		if strings.HasPrefix(f.RuleID, p) {
			return true
		}
	}
	return false
}

// controlsFor returns the control IDs this framework maps the finding to
// (deduplicated, unsorted), or nil. All matching rules contribute (union),
// with one precedence rule: an exact ruleIds match suppresses rulePrefixes
// rules — exact knowledge beats family defaults.
func (fw *Framework) controlsFor(f model.Finding) []string {
	if !fw.inScope(f) {
		return nil
	}
	cweSet := map[string]bool{}
	for _, c := range f.CWEs {
		cweSet[c] = true
	}
	matched := map[string]bool{}
	exactRuleHit := false
	for _, r := range fw.Rules {
		if len(r.RuleIDs) == 0 {
			continue
		}
		for _, id := range r.RuleIDs {
			if id == f.RuleID {
				exactRuleHit = true
				for _, c := range r.Controls {
					matched[c] = true
				}
				break
			}
		}
	}
	for _, r := range fw.Rules {
		switch {
		case len(r.CWEs) > 0:
			for _, c := range r.CWEs {
				if cweSet[c] {
					for _, id := range r.Controls {
						matched[id] = true
					}
					break
				}
			}
		case r.Category != "":
			if r.Category == f.Category {
				for _, id := range r.Controls {
					matched[id] = true
				}
			}
		case len(r.RulePrefixes) > 0:
			if exactRuleHit {
				continue
			}
			for _, p := range r.RulePrefixes {
				if strings.HasPrefix(f.RuleID, p) {
					for _, id := range r.Controls {
						matched[id] = true
					}
					break
				}
			}
		}
	}
	if len(matched) == 0 {
		return nil
	}
	out := make([]string, 0, len(matched))
	for id := range matched {
		out = append(out, id)
	}
	return out
}

// MapFinding returns the finding's mapped controls across all frameworks as
// sorted, deduplicated "<FRAMEWORK>:<control-id>" values (nil if none). For
// CLOUD findings it unions the curated engine mapping (CIS-AWS etc.) with the
// prowler compliance passthrough (CloudControls) — prowler's own per-finding
// mapping across the reviewed framework allow-list.
func MapFinding(f model.Finding) ([]string, error) {
	fws, err := Frameworks()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for i := range fws {
		for _, id := range fws[i].controlsFor(f) {
			add(fws[i].ID + ":" + id)
		}
	}
	for _, v := range CloudControls(f) {
		add(v)
	}
	if len(out) == 0 {
		return nil, nil
	}
	sort.Strings(out)
	return out, nil
}

// Apply populates ComplianceControls on every finding, in place. It is the
// always-on pipeline stage after risk scoring: deterministic, additive only —
// it never drops, reorders, or otherwise modifies findings. A finding mapping
// to no control gets an empty slot and surfaces in the gap report's unmapped
// bucket instead.
func Apply(findings []model.Finding) error {
	if _, err := Frameworks(); err != nil {
		return err
	}
	for i := range findings {
		controls, err := MapFinding(findings[i])
		if err != nil {
			return err
		}
		findings[i].ComplianceControls = controls
	}
	return nil
}
