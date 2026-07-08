package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/compliance"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/targets"
	"github.com/zer0d4y5/argus/internal/triage"
)

// On-demand explain endpoint (docs/console-ops.md S5/§12.6). The prompt and
// output boundary live in internal/triage; this file owns the console
// concerns: authz'd routing (operator+, via the authz table), single-flight,
// a bounded cache, config sourcing from the TARGET repo, and the audit line.
// The explanation exists only in this cache and the HTTP response — nothing
// here has a write path to run files.

const explainCacheCap = 200

// ExplainRequest is POST /api/explain. targetId empty = the served repo's
// run history (same resolution rule as GET /api/runs).
type ExplainRequest struct {
	TargetID  string `json:"targetId"`
	RunID     string `json:"runId"`
	FindingID string `json:"findingId"`
}

// ExplainResponse is the ephemeral explanation.
type ExplainResponse struct {
	Explanation string `json:"explanation"`
	Remediation string `json:"remediation,omitempty"`
	Model       string `json:"model"`
	Cached      bool   `json:"cached"`
}

// explainEntry is one single-flight cache slot: concurrent requests for the
// same finding block on once while the first computes.
type explainEntry struct {
	once sync.Once
	resp ExplainResponse
	err  error
	code int
}

type explainCache struct {
	mu      sync.Mutex
	entries map[string]*explainEntry
	order   []string // FIFO eviction
}

func (c *explainCache) get(key string) (*explainEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*explainEntry)
	}
	if e, ok := c.entries[key]; ok {
		return e, true
	}
	e := &explainEntry{}
	c.entries[key] = e
	c.order = append(c.order, key)
	if len(c.order) > explainCacheCap {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
	return e, false
}

// drop removes a failed computation so a transient provider error does not
// pin the failure until eviction.
func (c *explainCache) drop(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req ExplainRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RunID == "" || req.FindingID == "" {
		writeErr(w, http.StatusBadRequest, "runId and findingId are required")
		return
	}

	// Resolve the run's store: the served repo, or a registered target by
	// opaque ID (never a path from the request). Cloud targets resolve to
	// their per-target cloud store (no filesystem root).
	store := s.store
	root := s.dir
	if req.TargetID != "" {
		if s.targets == nil {
			writeErr(w, http.StatusNotFound, "target not found")
			return
		}
		t, err := s.targets.Get(req.TargetID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "target not found")
			return
		}
		if t.Kind() == targets.TypeCloud {
			store = runstore.Store{Dir: s.targets.CloudRunStore(t)}
			// Cloud findings have no source tree (snippet resolution is moot —
			// Location.File is empty); config for the LLM provider comes from
			// the served repo, so keep root = s.dir.
		} else {
			root = s.targets.Root(t)
			store = runstore.ForRepo(root)
		}
	}

	key := req.TargetID + "|" + req.RunID + "|" + req.FindingID
	entry, cached := s.explains.get(key)
	entry.once.Do(func() {
		entry.resp, entry.code, entry.err = s.computeExplanation(r.Context(), store, root, req)
		if entry.err != nil {
			s.explains.drop(key)
		}
	})

	s.audit(audit.EventScanExplain, actorFrom(r), map[string]string{
		"target": req.TargetID, "run": req.RunID, "finding": req.FindingID,
		"cached": strconv.FormatBool(cached),
	})

	if entry.err != nil {
		writeErr(w, entry.code, entry.err.Error())
		return
	}
	resp := entry.resp
	resp.Cached = cached
	writeJSON(w, http.StatusOK, resp)
}

// computeExplanation loads the finding from the run file and runs the
// explain boundary against the TARGET repo's configured provider. store is
// the run history (repo or cloud); root is the source tree for snippet
// resolution ("" for cloud findings, which have no source and whose config
// falls back to defaults).
func (s *Server) computeExplanation(ctx context.Context, store runstore.Store, root string, req ExplainRequest) (ExplainResponse, int, error) {
	doc, err := store.Load(req.RunID)
	if err != nil {
		return ExplainResponse{}, http.StatusNotFound, errors.New("run not found")
	}
	var found *model.Finding
	for i := range doc.Findings {
		if doc.Findings[i].ID == req.FindingID {
			found = &doc.Findings[i]
			break
		}
	}
	if found == nil {
		return ExplainResponse{}, http.StatusNotFound, errors.New("finding not found in this run")
	}

	// Provider/model/endpoint come from the target tree's own appsec.yml
	// (defaults when absent) — request input cannot influence them (S3/S5).
	cfg := s.effectiveConfig(root)

	factory := s.llmFactory
	if factory == nil {
		factory = pipeline.NewLLMClient
	}
	client := factory(cfg)
	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			return ExplainResponse{}, http.StatusServiceUnavailable,
				errors.New("no reachable LLM provider — configure triage in the target's appsec.yml")
		}
	}

	ex, err := triage.Explain(ctx, client, *found, cfg.Triage.AllowSecretCloud,
		time.Duration(cfg.Triage.TimeoutSec)*time.Second)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, triage.ErrSecretCloud) {
			code = http.StatusConflict
		}
		return ExplainResponse{}, code, err
	}
	return ExplainResponse{
		Explanation: ex.Explanation,
		Remediation: ex.Remediation,
		Model:       ex.Model,
	}, 0, nil
}

// PostureRequest is POST /api/cloud/posture-summary: an on-demand,
// never-persisted narrative over one cloud run's rollup (locked decision
// 10). targetId must be a cloud target; runId names the run.
type PostureRequest struct {
	TargetID string `json:"targetId"`
	RunID    string `json:"runId"`
}

// PostureResponse is the ephemeral, clearly-AI-generated summary.
type PostureResponse struct {
	Summary string `json:"summary"`
	Model   string `json:"model"`
}

// handlePostureSummary generates an on-demand posture summary for one cloud
// run. It is never persisted (no write path to any run file), reads only the
// run's deterministic rollup (counts, risk-signal codes, CIS controls — never
// a credential, never source), and the UI labels it AI-generated. Operator+.
func (s *Server) handlePostureSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req PostureRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TargetID == "" || req.RunID == "" {
		writeErr(w, http.StatusBadRequest, "targetId and runId are required")
		return
	}
	if s.targets == nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return
	}
	t, err := s.targets.Get(req.TargetID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return
	}
	if t.Kind() != targets.TypeCloud {
		writeErr(w, http.StatusBadRequest, "posture summary is only available for cloud targets")
		return
	}

	store := runstore.Store{Dir: s.targets.CloudRunStore(t)}
	doc, err := store.Load(req.RunID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	// Enrich at read time so control gaps show for older runs (idempotent).
	_ = compliance.Apply(doc.Findings)

	cfg := s.effectiveConfig(s.dir)
	factory := s.llmFactory
	if factory == nil {
		factory = pipeline.NewLLMClient
	}
	client := factory(cfg)
	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(r.Context()); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "no reachable LLM provider — configure triage in appsec.yml")
			return
		}
	}

	in := triage.BuildPostureInput(t.Provider, doc.Findings)
	ps, err := triage.Posture(r.Context(), client, in, time.Duration(cfg.Triage.TimeoutSec)*time.Second)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	// Audit the on-demand generation; the summary text itself is never stored.
	s.audit(audit.EventScanExplain, actorFrom(r), map[string]string{
		"target": req.TargetID, "run": req.RunID, "kind": "posture-summary",
	})
	writeJSON(w, http.StatusOK, PostureResponse{Summary: ps.Summary, Model: ps.Model})
}
