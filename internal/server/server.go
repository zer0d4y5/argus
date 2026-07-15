// Package server is the `argus serve` web console: a local-first HTTP server
// that exposes saved scan runs as a JSON API, serves the embedded React UI,
// and — once users are configured — authenticates sessions and executes
// scans against registered targets through a strictly serial job queue.
//
// SECURITY POSTURE (docs/console-ops.md is the spec):
//   - Zero users on disk: the console is the pre-auth read-only viewer,
//     loopback-bound by default; every operational endpoint answers 403
//     naming the bootstrap command. One or more users: every /api route
//     requires a session (reads included), enforced by the authz table in
//     authz.go.
//   - Finding data (titles, descriptions, paths, rationales) originates from
//     scanned repositories and an LLM and is therefore HOSTILE. The server
//     never renders it into HTML; it returns strict application/json with
//     X-Content-Type-Options: nosniff, and the frontend escapes on render.
//   - A strict Content-Security-Policy is set on the HTML shell: no inline
//     script, no remote origins. The bundle loads only same-origin assets.
//   - No TLS in-process: the supported way off loopback is a TLS-terminating
//     reverse proxy (docs/console-ops.md §8).
package server

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/cloudremediate"
	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/disposition"
	"github.com/zer0d4y5/argus/internal/jobs"
	"github.com/zer0d4y5/argus/internal/llm"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/report"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/server/auth"
	"github.com/zer0d4y5/argus/internal/targets"
	"github.com/zer0d4y5/argus/internal/threatmodel"
	"github.com/zer0d4y5/argus/internal/ticket"
)

// Server serves the console API and static UI over one repo's run history.
type Server struct {
	store    runstore.Store
	dir      string          // served repo root (the default run history's home)
	gate     *model.Severity // gate threshold for computed pass/fail (nil = never fails)
	gateName string          // human label for the threshold
	static   fs.FS           // embedded UI file system (index.html at root)

	// explains is the bounded single-flight cache behind POST /api/explain —
	// the ONLY place explanations live (never run files, never audit).
	explains explainCache
	// llmFactory overrides the explain client construction IN TESTS ONLY;
	// nil means pipeline.NewLLMClient (provider always from the repo config).
	llmFactory func(config.Config) llm.Client

	// Console-ops components. All nil is the legacy read-only construction
	// and behaves exactly like the zero-users mode (reads open, ops 403).
	users    *auth.Store
	sessions *auth.Sessions
	limiter  *auth.LoginLimiter
	targets  *targets.Registry
	auditLog *audit.Log
	queue    *jobs.Queue
	tickets  *ticket.Store      // nil when the SQLite store isn't wired (legacy mode)
	threats  *threatmodel.Store // nil disables threat-model endpoints

	// githubAPIBase overrides the GitHub API endpoint IN TESTS ONLY; empty
	// means https://api.github.com.
	githubAPIBase string

	// remediateExec overrides the cloud-remediation command executor IN TESTS
	// ONLY; nil means the production child-process executor.
	remediateExec cloudremediate.Executor

	// OIDC (SSO) is built lazily on first use from the effective config so
	// server start never blocks on, or fails because of, IdP reachability;
	// password login always survives an SSO misconfiguration. A mutex (not a
	// sync.Once) guards it so an admin config change can invalidate and rebuild
	// the provider live. The field is an interface so tests can inject a fake.
	oidcMu       sync.Mutex
	oidcProvider oidcAuthenticator
	oidcErr      error
	oidcBuilt    bool // a build was attempted (guards "built but disabled")
}

// oidcAuthenticator is the slice of the OIDC provider the handlers use, made an
// interface so a fake can be injected in tests. *auth.OIDCProvider satisfies it.
type oidcAuthenticator interface {
	AuthURL() string
	Exchange(ctx context.Context, state, code string) (auth.OIDCClaims, error)
	Authorize(auth.OIDCClaims) (auth.Role, error)
}

// Options configure a Server.
type Options struct {
	Store    runstore.Store
	Dir      string // served repo root; empty falls back to the store's parent
	Gate     *model.Severity
	GateName string
	Static   fs.FS

	// Console-ops (optional; see Server field docs).
	Users    *auth.Store
	Sessions *auth.Sessions
	Limiter  *auth.LoginLimiter
	Targets  *targets.Registry
	Audit    *audit.Log
	Queue    *jobs.Queue
	Tickets  *ticket.Store      // the SQLite-backed ticket store; nil disables ticket endpoints
	Threats  *threatmodel.Store // the SQLite-backed threat-model store; nil disables its endpoints
}

// New builds a Server and its routes.
func New(opts Options) *Server {
	dir := opts.Dir
	if dir == "" {
		// Store.Dir is <root>/.appsec/runs; the served root is two up.
		dir = filepath.Dir(filepath.Dir(opts.Store.Dir))
	}
	s := &Server{
		store: opts.Store, dir: dir, gate: opts.Gate, gateName: opts.GateName, static: opts.Static,
		users: opts.Users, sessions: opts.Sessions, limiter: opts.Limiter,
		targets: opts.Targets, auditLog: opts.Audit, queue: opts.Queue,
		tickets: opts.Tickets, threats: opts.Threats,
	}
	return s
}

// Handler returns the fully-wired http.Handler: authz gate over the API,
// then routes, then the defensive headers on everything.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/runs", s.handleRuns)
	mux.HandleFunc("/api/runs/", s.handleRunDetail) // /api/runs/{id}
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/oidc/start", s.handleOIDCStart)       // GET: begin SSO (pre-auth)
	mux.HandleFunc("/api/auth/oidc/callback", s.handleOIDCCallback) // GET: complete SSO (pre-auth)
	mux.HandleFunc("/api/auth/me", s.handleMe)
	mux.HandleFunc("/api/users", s.handleUsers)                                       // GET list, POST create (admin)
	mux.HandleFunc("/api/users/names", s.handleUserNames)                             // GET usernames only (operator, for assignee pickers)
	mux.HandleFunc("/api/users/", s.handleUserByID)                                   // PATCH, DELETE (admin)
	mux.HandleFunc("/api/targets", s.handleTargets)                                   // GET (viewer), POST (admin)
	mux.HandleFunc("/api/targets/", s.handleTargetByID)                               // DELETE (admin)
	mux.HandleFunc("/api/cloud/profiles", s.handleCloudProfiles)                      // GET (admin): discovered profile names
	mux.HandleFunc("/api/scans", s.handleScans)                                       // GET (viewer), POST (operator)
	mux.HandleFunc("/api/scans/", s.handleScanByID)                                   // GET /api/scans/{jobId}
	mux.HandleFunc("/api/frameworks", s.handleFrameworks)                             // GET (viewer)
	mux.HandleFunc("/api/explain", s.handleExplain)                                   // POST (operator)
	mux.HandleFunc("/api/sbom", s.handleSBOM)                                         // POST (operator): generate a CycloneDX/SPDX SBOM
	mux.HandleFunc("/api/remediate", s.handleRemediate)                               // POST (operator): on-demand assisted remediation, never persisted
	mux.HandleFunc("/api/validate", s.handleValidate)                                 // POST (operator): on-demand severity validation + CVSS
	mux.HandleFunc("/api/confirm-impact", s.handleConfirmImpact)                       // POST (admin): bounded impact confirmation, interlocked + audited
	mux.HandleFunc("/api/attack-path", s.handleAttackPath)                             // POST (operator): advisory AI attack-path analysis, never persisted
	mux.HandleFunc("/api/engagements", s.handleEngagements)                            // GET list (operator), POST create (admin)
	mux.HandleFunc("/api/engagements/", s.handleEngagementItem)                        // POST {id}/activate, GET {id}/report (admin)
	mux.HandleFunc("/api/mitigations", s.handleMitigations)                           // GET (viewer): curated secure-coding guidance by CWE
	mux.HandleFunc("/api/dispositions", s.handleDispositions)                         // POST (operator): set a finding's workflow status
	mux.HandleFunc("/api/dispositions/bulk", s.handleDispositionsBulk)                // POST (operator): apply/clear across a selection
	mux.HandleFunc("/api/dispositions/", s.handleDispositionByID)                     // DELETE (operator): clear back to open
	mux.HandleFunc("/api/cloud/posture-summary", s.handlePostureSummary)              // POST (operator): on-demand, never persisted
	mux.HandleFunc("/api/cloud/remediations", s.handleCloudRemediations)              // POST (operator): curated fixes for a cloud finding (no execution)
	mux.HandleFunc("/api/cloud/remediate", s.handleCloudRemediate)                    // POST (admin, gated): dry-run or apply a curated fix
	mux.HandleFunc("/api/tickets", s.handleTickets)                                   // GET list (viewer), POST create (operator)
	mux.HandleFunc("/api/work-summary", s.handleWorkSummary)                          // GET ticket/threat status counts (viewer)
	mux.HandleFunc("/api/tickets/", s.handleTicketByID)                               // GET/PATCH/DELETE + /links, /comments subpaths
	mux.HandleFunc("/api/threat-models", s.handleThreatModels)                        // GET list (viewer), POST create (operator)
	mux.HandleFunc("/api/threat-models/", s.handleThreatModelByID)                    // GET/DELETE + subaction POSTs
	mux.HandleFunc("/api/threat-library", s.handleThreatLibrary)                      // GET (viewer): component types for the picker
	mux.HandleFunc("/api/admin/oidc", s.handleAdminOIDC)                              // GET/PUT SSO config (admin)
	mux.HandleFunc("/api/admin/settings", s.handleAdminSettings)                      // GET/PUT integrations + scanning config (admin)
	mux.HandleFunc("/api/admin/settings/validate-rulesets", s.handleValidateRulesets) // POST: check custom rules without saving (admin)
	mux.HandleFunc("/api/admin/rules", s.handleRules)                                 // GET list, POST save custom rules (admin)
	mux.HandleFunc("/api/admin/rules/", s.handleRulesSub)                             // POST /draft, /test; DELETE /{name} (admin)
	mux.HandleFunc("/api/admin/rule-catalog", s.handleRuleCatalog)                    // GET the registry-pack menu (admin)
	mux.HandleFunc("/api/admin/rulesets/toggle", s.handleToggleRuleset)               // POST enable/disable a pack or saved rule (admin)
	mux.HandleFunc("/api/audit", s.handleAudit)                                       // GET (admin)
	mux.HandleFunc("/", s.handleStatic)
	return securityHeaders(s.authGate(mux))
}

// securityHeaders applies the console's defensive headers to every response.
// The CSP locks the page to same-origin assets with no inline script; the
// nosniff header stops a browser from re-interpreting a JSON body as HTML.
func securityHeaders(next http.Handler) http.Handler {
	// script-src is locked to same-origin with NO unsafe-inline — this is the
	// XSS-defense that matters. style-src additionally allows 'unsafe-inline'
	// because the charting library sets inline style attributes on SVG nodes;
	// inline styles cannot execute script, so this does not weaken the script
	// boundary. No remote origins are permitted anywhere.
	const csp = "default-src 'none'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"base-uri 'none'; " +
		"form-action 'none'; " +
		"frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// writeJSON emits v as application/json with nosniff already set upstream.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true) // escape <, >, & in strings — defense in depth for hostile finding text
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC().Format(rfc3339)})
}

// aggregateTarget is the sentinel target id that means "every target
// combined" — the portfolio Overview. A real target id can never be this.
const aggregateTarget = "@all"

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("target") == aggregateTarget {
		resp, err := s.buildAggregateSummary()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to build summary")
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	store, ok := s.runStoreFor(w, r)
	if !ok {
		return
	}
	resp, err := s.buildSummary(store)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to build summary")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// storesForAggregate is every run history in play: the served repo plus each
// registered target (dir/git repo root, or the cloud per-target store).
func (s *Server) storesForAggregate() []runstore.Store {
	stores := []runstore.Store{s.store}
	if s.targets == nil {
		return stores
	}
	ts, err := s.targets.List()
	if err != nil {
		return stores
	}
	for _, t := range ts {
		if dir, ok := s.targets.NonFSRunStore(t); ok {
			stores = append(stores, runstore.Store{Dir: dir})
		} else {
			stores = append(stores, runstore.ForRepo(s.targets.Root(t)))
		}
	}
	return dedupeStores(stores)
}

// dedupeStores drops run stores that resolve to the same directory, so a target
// registered at the served root (or via a symlink, a trailing slash, or a
// case-differing path on a case-insensitive filesystem) is not counted twice in
// the portfolio aggregate. Identity is the symlink-resolved path, with an
// os.SameFile check to catch aliases a string compare misses.
func dedupeStores(stores []runstore.Store) []runstore.Store {
	out := make([]runstore.Store, 0, len(stores))
	seen := map[string]bool{}
	var kept []os.FileInfo
	for _, st := range stores {
		canon := st.Dir
		if resolved, err := filepath.EvalSymlinks(st.Dir); err == nil {
			canon = resolved
		}
		if seen[canon] {
			continue
		}
		if fi, err := os.Stat(canon); err == nil {
			dup := false
			for _, k := range kept {
				if os.SameFile(fi, k) {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
			kept = append(kept, fi)
		}
		seen[canon] = true
		out = append(out, st)
	}
	return out
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	store, ok := s.runStoreFor(w, r)
	if !ok {
		return
	}
	resp, err := s.buildRuns(store)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to list runs")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRunDetail serves /api/runs/{id} (GET detail, DELETE run) and
// /api/runs/{id}/export (GET, SARIF/JSON download). The run store is resolved
// from ?target= exactly like the list endpoints; the run ID is validated and
// path-confined by runstore before any filesystem access.
func (s *Server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid run id")
		return
	}
	store, ok := s.runStoreFor(w, r)
	if !ok {
		return
	}

	switch {
	case sub == "export" && r.Method == http.MethodGet:
		s.handleRunExport(w, r, store, id)
	case sub == "" && r.Method == http.MethodGet:
		detail, err := s.buildRunDetail(store, id, r.URL.Query().Get("baseline"))
		if err != nil {
			// Load validates the id and confines the path; a failure here is a
			// missing/invalid run, not a server fault.
			writeErr(w, http.StatusNotFound, "run not found")
			return
		}
		writeJSON(w, http.StatusOK, detail)
	case sub == "" && r.Method == http.MethodDelete:
		s.handleRunDelete(w, r, store, id)
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

// handleRunDelete removes a run file (admin, audited). Which target's store
// is already resolved by the caller from ?target=.
func (s *Server) handleRunDelete(w http.ResponseWriter, r *http.Request, store runstore.Store, id string) {
	if err := store.Delete(id); err != nil {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	s.audit(audit.EventRunDelete, actorFrom(r), map[string]string{
		"target": r.URL.Query().Get("target"), "run": id,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleRunExport streams a run as SARIF or JSON for download. The report is
// re-rendered from the stored findings through the same writers the CLI uses,
// so an exported SARIF is byte-for-byte what `argus scan -f sarif` produces.
func (s *Server) handleRunExport(w http.ResponseWriter, r *http.Request, store runstore.Store, id string) {
	doc, err := store.Load(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	format := r.URL.Query().Get("format")
	// A safe download filename derived from the validated run id (no path sep).
	fname := "argus-" + strings.ReplaceAll(id, ":", "-")
	switch format {
	case "sarif":
		w.Header().Set("Content-Type", "application/sarif+json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`.sarif"`)
		if err := report.WriteSARIF(w, doc.Findings); err != nil {
			// Header already sent on success path; on failure log-and-stop.
			return
		}
	case "json", "":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`.json"`)
		if err := report.WriteJSON(w, doc.Findings); err != nil {
			return
		}
	case "html":
		// A professional, print-to-PDF report with the run's gate and workflow
		// context. Served inline so the browser renders (and prints) it.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `inline; filename="`+fname+`.html"`)
		meta := s.htmlMeta(store, id, doc.Findings)
		s.addWorkItemsToReport(&meta, r.URL.Query().Get("target"))
		if err := report.WriteHTML(w, doc.Findings, meta); err != nil {
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "format must be sarif, json, or html")
	}
}

// htmlMeta assembles the presentation context for an exported report: the
// target label, the run's gate outcome (disposition-aware), and the
// per-finding workflow statuses.
func (s *Server) htmlMeta(store runstore.Store, id string, findings []model.Finding) report.HTMLMeta {
	dispMap := map[string]string{}
	if all, err := dispositionStore(store).All(); err == nil {
		for fid, rec := range all {
			dispMap[fid] = rec.Status
		}
	}
	gate := gateFor(findings, mustDispositions(store), s.gate, s.gateName)
	return report.HTMLMeta{
		Target:         s.reportTarget(store),
		RunID:          id,
		GeneratedAt:    time.Now().Format("2006-01-02 15:04 MST"),
		GateThreshold:  s.gateName,
		GateFailed:     gate.Failed,
		GateSuppressed: gate.Suppressed,
		Dispositions:   dispMap,
	}
}

// mustDispositions returns the store's dispositions or an empty map.
func mustDispositions(store runstore.Store) map[string]disposition.Record {
	all, err := dispositionStore(store).All()
	if err != nil {
		return nil
	}
	return all
}

// reportTarget is a human label for the report header: the served repo's base
// name, or the run store's owning directory for a target.
func (s *Server) reportTarget(store runstore.Store) string {
	dir := filepath.Dir(filepath.Dir(store.Dir)) // strip /.appsec/runs
	if base := filepath.Base(dir); base != "" && base != "." && base != "/" {
		return base
	}
	return ""
}

// runStoreFor resolves which run history a read serves: the served repo's
// (default), or — with ?target=<registryID> — a registered target's own
// store (docs/console-ops.md §12.1). The ID resolves through the registry
// server-side; no path ever comes from the browser. On failure it writes
// the response and returns ok=false.
func (s *Server) runStoreFor(w http.ResponseWriter, r *http.Request) (runstore.Store, bool) {
	tid := r.URL.Query().Get("target")
	if tid == "" {
		return s.store, true
	}
	if s.targets == nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return runstore.Store{}, false
	}
	t, err := s.targets.Get(tid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return runstore.Store{}, false
	}
	// Cloud, DAST, and image targets have no filesystem root; their history
	// lives in a per-target store (locked decision 9, extended in 2.2.0).
	if dir, ok := s.targets.NonFSRunStore(t); ok {
		return runstore.Store{Dir: dir}, true
	}
	return runstore.ForRepo(s.targets.Root(t)), true
}

// handleStatic serves the embedded UI with SPA fallback: unknown non-API paths
// return index.html so client-side routing works. Never serves API paths.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		p = "index.html"
	}
	if serveFile(w, s.static, p) {
		return
	}
	// SPA fallback.
	serveFile(w, s.static, "index.html")
}

// serveFile writes the named file from fsys if it exists, setting a correct
// content type. Returns false if the file is absent so the caller can fall back.
func serveFile(w http.ResponseWriter, fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}
	w.Header().Set("Content-Type", contentType(name))
	_, _ = io.Copy(w, f)
	return true
}

// contentType maps a filename to a MIME type. Kept explicit (not
// mime.TypeByExtension) so behavior is identical across platforms.
func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".ico"):
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// ListenAndServe binds addr and serves until the context-less server errors.
// Callers pass a bind address; the CLI defaults it to 127.0.0.1.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}
