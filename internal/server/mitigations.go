package server

import (
	"net/http"

	"github.com/leaky-hub/argus/internal/mitigation"
)

// handleMitigations serves curated secure-coding guidance for a weakness class.
// GET /api/mitigations?cwe=CWE-89&cwe=CWE-943&lang=python — repeatable cwe
// params (a finding's CWEs), optional lang to promote the matching snippet.
// Read-only, static, hostile-input-free content: viewer, and open even in
// zero-users mode like the other read routes. 404 when no CWE maps.
func (s *Server) handleMitigations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	cwes := q["cwe"]
	if len(cwes) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one cwe parameter is required")
		return
	}
	g, ok := mitigation.Lookup(cwes, q.Get("lang"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no curated guidance for these CWEs")
		return
	}
	writeJSON(w, http.StatusOK, g)
}
