package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/llm"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/ruleauthor"
	"github.com/zer0d4y5/argus/internal/scanner"
)

// AI-assisted custom rule authoring (admin-only, audited). The local LLM DRAFTS
// or EDITS a semgrep rule; the human validates, tests it against a pasted
// snippet, edits it freely, and only then SAVES it as a custom local rule that
// feeds the custom-rulesets machinery (Workstream C). The LLM never decides a
// rule is safe and never saves anything: every save re-runs the deterministic
// safety linter and semgrep --validate server-side before a rule touches disk.
//
//   POST /api/admin/rules/draft  - LLM drafts/edits a rule (never saved)
//   POST /api/admin/rules/test   - validate + safety-lint + run over a snippet
//   GET  /api/admin/rules        - list saved custom rules
//   POST /api/admin/rules        - save a rule (validated + linted first)
//   DELETE /api/admin/rules/{name} - delete a saved rule

// ruleSlug bounds a saved rule's file name: lowercase alnum and dashes, so it
// can never traverse out of the managed rules directory.
var ruleSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,48}$`)

// rulesDir is the managed directory for saved custom rules under the served
// repo. Entries here are referenced from the console rulesets as
// ".appsec/rules/<name>.yml".
func (s *Server) rulesDir() string { return filepath.Join(s.dir, ".appsec", "rules") }

// ruleRelPath is the ruleset entry a saved rule is referenced by.
func ruleRelPath(name string) string { return ".appsec/rules/" + name + ".yml" }

// llmClientForConsole builds the LLM client from the served repo's effective
// config and pings it, writing the 503 itself when unreachable. Rule authoring
// is not tied to a scan target, so it uses the console's own config (local
// Ollama by default); the request never picks the provider.
func (s *Server) llmClientForConsole(w http.ResponseWriter, r *http.Request) (llm.Client, time.Duration, bool) {
	cfg := s.effectiveConfig(s.dir)
	factory := s.llmFactory
	if factory == nil {
		factory = pipeline.NewLLMClient
	}
	client := factory(cfg)
	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(r.Context()); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "no reachable LLM provider: configure triage (a local Ollama by default) in the served repo's appsec.yml")
			return nil, 0, false
		}
	}
	return client, time.Duration(cfg.Triage.TimeoutSec) * time.Second, true
}

// CatalogPack is one catalog entry with its current state for the console.
type CatalogPack struct {
	scanner.RulePack
	Active    bool `json:"active"`    // currently in the custom rulesets
	InProfile bool `json:"inProfile"` // already run by the standard/max profile
}

// handleRuleCatalog returns the curated registry-pack menu, grouped by
// category, with each pack's active/in-profile state. Admin-only.
func (s *Server) handleRuleCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cs, _ := loadConsoleSettings(s.dir)
	active := map[string]bool{}
	for _, e := range cs.SemgrepRulesets {
		active[e] = true
	}
	packs := make([]CatalogPack, 0, len(scanner.RulePackCatalog))
	for _, p := range scanner.RulePackCatalog {
		packs = append(packs, CatalogPack{RulePack: p, Active: active[p.ID], InProfile: scanner.InDefaultProfile(p.ID)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"categories": scanner.RulePackCategories, "packs": packs})
}

// ToggleRulesetRequest enables or disables one ruleset entry (a catalog pack or
// a saved rule's path) by adding it to or removing it from the custom rulesets.
type ToggleRulesetRequest struct {
	Entry   string `json:"entry"`
	Enabled bool   `json:"enabled"`
}

// handleToggleRuleset is the shared enable/disable for both the catalog packs
// and saved-rule activation: it adds or removes one entry from the console
// custom rulesets. Enabling validates the entry first (a pack must resolve, a
// local rule must exist and pass semgrep --validate) so a scan is never wired
// to a broken ruleset. Admin-only, audited.
func (s *Server) handleToggleRuleset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req ToggleRulesetRequest
	if err := decodeBody(w, r, &req, 8192); err != nil {
		return
	}
	entry := strings.TrimSpace(req.Entry)
	if entry == "" || entry == scanner.AdditiveMarker {
		writeErr(w, http.StatusBadRequest, "a ruleset entry is required")
		return
	}
	if req.Enabled {
		if statuses := scanner.ValidateRulesets(r.Context(), []string{entry}, s.dir); scanner.FirstInvalid(statuses) != nil {
			writeErr(w, http.StatusBadRequest, scanner.FirstInvalid(statuses).Message)
			return
		}
	}
	cs, _ := loadConsoleSettings(s.dir)
	kept := cs.SemgrepRulesets[:0]
	for _, e := range cs.SemgrepRulesets {
		if e != entry {
			kept = append(kept, e)
		}
	}
	if req.Enabled {
		kept = append(kept, entry)
	}
	cs.SemgrepRulesets = kept
	if cs.SemgrepRulesetsAdditive == nil {
		add := true
		cs.SemgrepRulesetsAdditive = &add
	}
	if err := saveConsoleSettings(s.dir, cs); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	s.audit(audit.EventConfigChange, actorFrom(r), map[string]string{"area": "rulesets", "entry": entry, "enabled": boolStr(req.Enabled)})
	writeJSON(w, http.StatusOK, map[string]any{"entry": entry, "enabled": req.Enabled})
}

// handleRules is GET (list) and POST (save) on the collection.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listRules(w, r)
	case http.MethodPost:
		s.saveRule(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleRulesSub routes the sub-paths: /draft, /test, and DELETE /{name}.
func (s *Server) handleRulesSub(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/admin/rules/")
	switch {
	case suffix == "draft" && r.Method == http.MethodPost:
		s.draftRule(w, r)
	case suffix == "test" && r.Method == http.MethodPost:
		s.testRule(w, r)
	case r.Method == http.MethodDelete && suffix != "" && !strings.Contains(suffix, "/"):
		s.deleteRule(w, r, suffix)
	default:
		writeErr(w, http.StatusNotFound, "unknown rules route")
	}
}

// DraftRuleRequest asks the LLM to draft or edit a rule.
type DraftRuleRequest struct {
	Description  string `json:"description"`
	Language     string `json:"language"`
	ExistingRule string `json:"existingRule"`
	Instruction  string `json:"instruction"`
}

func (s *Server) draftRule(w http.ResponseWriter, r *http.Request) {
	var req DraftRuleRequest
	if err := decodeBody(w, r, &req, 64*1024); err != nil {
		return
	}
	if strings.TrimSpace(req.Description) == "" && strings.TrimSpace(req.ExistingRule) == "" {
		writeErr(w, http.StatusBadRequest, "describe what to detect, or paste a rule to edit")
		return
	}
	client, timeout, ok := s.llmClientForConsole(w, r)
	if !ok {
		return
	}
	draft, err := ruleauthor.DraftRule(r.Context(), client, ruleauthor.DraftRequest{
		Description:  req.Description,
		Language:     req.Language,
		ExistingRule: req.ExistingRule,
		Instruction:  req.Instruction,
	}, timeout)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(audit.EventRuleAuthor, actorFrom(r), map[string]string{"action": "draft", "ready": boolStr(draft.Ready)})
	writeJSON(w, http.StatusOK, draft)
}

// TestRuleRequest validates a rule and runs it against a snippet.
type TestRuleRequest struct {
	Rule     string `json:"rule"`
	Snippet  string `json:"snippet"`
	Language string `json:"language"`
}

// TestRuleResponse carries the safety-lint issues plus the validate+run result.
type TestRuleResponse struct {
	Issues []ruleauthor.SafetyIssue `json:"issues"`
	Safe   bool                     `json:"safe"`
	scanner.RuleTestResult
}

func (s *Server) testRule(w http.ResponseWriter, r *http.Request) {
	var req TestRuleRequest
	if err := decodeBody(w, r, &req, 128*1024); err != nil {
		return
	}
	if strings.TrimSpace(req.Rule) == "" {
		writeErr(w, http.StatusBadRequest, "no rule to test")
		return
	}
	issues, safe := ruleauthor.LintRule(req.Rule)
	resp := TestRuleResponse{Issues: issues, Safe: safe}
	// Only run the rule against the snippet when a language was given and a
	// snippet was pasted; the safety lint alone is still useful without them.
	if strings.TrimSpace(req.Language) != "" && strings.TrimSpace(req.Snippet) != "" {
		tr, err := scanner.TestRuleAgainstSnippet(r.Context(), req.Rule, req.Snippet, req.Language)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		resp.RuleTestResult = tr
	}
	s.audit(audit.EventRuleAuthor, actorFrom(r), map[string]string{"action": "test", "safe": boolStr(safe)})
	writeJSON(w, http.StatusOK, resp)
}

// SaveRuleRequest saves a rule under a slug and (by default) activates it.
type SaveRuleRequest struct {
	Name     string `json:"name"`
	Rule     string `json:"rule"`
	Activate *bool  `json:"activate"` // add to the console rulesets; default true
}

func (s *Server) saveRule(w http.ResponseWriter, r *http.Request) {
	var req SaveRuleRequest
	if err := decodeBody(w, r, &req, 128*1024); err != nil {
		return
	}
	name := strings.TrimSpace(req.Name)
	if !ruleSlug.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "rule name must be lowercase letters, digits, and dashes (max 49 chars)")
		return
	}
	// Deterministic safety gate, server-side: the LLM's opinion never counts.
	if issues, safe := ruleauthor.LintRule(req.Rule); !safe {
		msg := "rule failed the safety check"
		if inv := firstBlocking(issues); inv != "" {
			msg = inv
		}
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	// semgrep must also accept it, so a saved rule can never break a scan.
	if err := os.MkdirAll(s.rulesDir(), 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create rules directory")
		return
	}
	path := filepath.Join(s.rulesDir(), name+".yml")
	// Validate from a temp file that keeps the .yml extension (the validator
	// requires a rule extension), then rename into place atomically.
	tmp := filepath.Join(s.rulesDir(), "."+name+".tmp.yml")
	if err := os.WriteFile(tmp, []byte(req.Rule), 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not write rule")
		return
	}
	if statuses := scanner.ValidateRulesets(r.Context(), []string{tmp}, ""); scanner.FirstInvalid(statuses) != nil {
		msg := scanner.FirstInvalid(statuses).Message
		os.Remove(tmp)
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		writeErr(w, http.StatusInternalServerError, "could not save rule")
		return
	}

	activated := req.Activate == nil || *req.Activate
	if activated {
		s.activateRule(name)
	}
	s.audit(audit.EventRuleAuthor, actorFrom(r), map[string]string{"action": "save", "name": name, "activated": boolStr(activated)})
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "path": ruleRelPath(name), "activated": activated})
}

// activateRule adds a saved rule's path to the console custom rulesets
// (additive) if it is not already present, so the rule participates in scans.
func (s *Server) activateRule(name string) {
	cs, _ := loadConsoleSettings(s.dir)
	entry := ruleRelPath(name)
	for _, e := range cs.SemgrepRulesets {
		if e == entry {
			return
		}
	}
	cs.SemgrepRulesets = append(cs.SemgrepRulesets, entry)
	if cs.SemgrepRulesetsAdditive == nil {
		add := true
		cs.SemgrepRulesetsAdditive = &add
	}
	_ = saveConsoleSettings(s.dir, cs)
}

// SavedRule is one entry in the list response.
type SavedRule struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Active bool   `json:"active"` // currently referenced by the console rulesets
}

func (s *Server) listRules(w http.ResponseWriter, _ *http.Request) {
	entries, _ := os.ReadDir(s.rulesDir())
	cs, _ := loadConsoleSettings(s.dir)
	active := map[string]bool{}
	for _, e := range cs.SemgrepRulesets {
		active[e] = true
	}
	rules := []SavedRule{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yml")
		if !ruleSlug.MatchString(name) {
			continue
		}
		rules = append(rules, SavedRule{Name: name, Path: ruleRelPath(name), Active: active[ruleRelPath(name)]})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, name string) {
	if !ruleSlug.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid rule name")
		return
	}
	path := filepath.Join(s.rulesDir(), name+".yml")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "no such rule")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not delete rule")
		return
	}
	// Drop it from the console rulesets too, so a deleted rule stops running.
	cs, _ := loadConsoleSettings(s.dir)
	entry := ruleRelPath(name)
	kept := cs.SemgrepRulesets[:0]
	for _, e := range cs.SemgrepRulesets {
		if e != entry {
			kept = append(kept, e)
		}
	}
	cs.SemgrepRulesets = kept
	_ = saveConsoleSettings(s.dir, cs)
	s.audit(audit.EventRuleAuthor, actorFrom(r), map[string]string{"action": "delete", "name": name})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

// firstBlocking returns the message of the first blocking safety issue.
func firstBlocking(issues []ruleauthor.SafetyIssue) string {
	for _, i := range issues {
		if i.Blocking {
			return i.Message
		}
	}
	return ""
}
