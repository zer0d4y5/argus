// Package server is the `appsec serve` web console: a local-first HTTP server
// that exposes saved scan runs as a JSON API and serves the embedded React UI.
//
// SECURITY POSTURE (v1, documented loudly):
//   - Binds 127.0.0.1 by default. Widening the bind address exposes an
//     UNAUTHENTICATED console — there is no auth in v1.
//   - Finding data (titles, descriptions, paths, rationales) originates from
//     scanned repositories and an LLM and is therefore HOSTILE. The server
//     never renders it into HTML; it returns strict application/json with
//     X-Content-Type-Options: nosniff, and the frontend escapes on render.
//   - A strict Content-Security-Policy is set on the HTML shell: no inline
//     script, no remote origins. The bundle loads only same-origin assets.
package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/runstore"
)

// Server serves the console API and static UI over one repo's run history.
type Server struct {
	store    runstore.Store
	gate     *model.Severity // gate threshold for computed pass/fail (nil = never fails)
	gateName string          // human label for the threshold
	static   fs.FS           // embedded UI file system (index.html at root)
}

// Options configure a Server.
type Options struct {
	Store    runstore.Store
	Gate     *model.Severity
	GateName string
	Static   fs.FS
}

// New builds a Server and its routes.
func New(opts Options) *Server {
	s := &Server{store: opts.Store, gate: opts.Gate, gateName: opts.GateName, static: opts.Static}
	return s
}

// Handler returns the fully-wired http.Handler (API + static UI + headers).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/runs", s.handleRuns)
	mux.HandleFunc("/api/runs/", s.handleRunDetail) // /api/runs/{id}
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/", s.handleStatic)
	return securityHeaders(mux)
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

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	resp, err := s.buildSummary()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to build summary")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	resp, err := s.buildRuns()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to list runs")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusBadRequest, "invalid run id")
		return
	}
	detail, err := s.buildRunDetail(id)
	if err != nil {
		// Load validates the id and confines the path; a failure here is a
		// missing/invalid run, not a server fault.
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	writeJSON(w, http.StatusOK, detail)
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
