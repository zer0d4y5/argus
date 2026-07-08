package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/zer0d4y5/argus/internal/audit"
)

// GitHub issue sync for tickets: create an issue from a ticket, or link an
// existing one. Config-gated (ticketing.github.repo in the served repo's
// appsec.yml) and OFF by default — no config, no button, no network. The
// token is read from the configured env var at call time and exists only in
// the outbound Authorization header; it is never stored, logged, audited, or
// echoed. Only the issue URL and number persist, on the ticket row.

// githubIssueURL accepts exactly a GitHub issue page. Bounded segments keep
// the stored reference boring.
var githubIssueURL = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})/issues/([0-9]{1,10})$`)

// TicketGitHubRequest is POST /api/tickets/{id}/github. With IssueURL set it
// LINKS the existing issue (no network); empty means CREATE one via the API.
type TicketGitHubRequest struct {
	IssueURL string `json:"issueUrl"`
}

func (s *Server) ticketGitHub(w http.ResponseWriter, r *http.Request, id string) {
	var req TicketGitHubRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cfg := s.effectiveConfig(s.dir)
	if !cfg.GitHubEnabled() {
		writeErr(w, http.StatusBadRequest, "GitHub sync is not configured — set ticketing.github.repo in appsec.yml")
		return
	}
	t, err := s.tickets.Get(id)
	if err != nil {
		s.writeTicketErr(w, err)
		return
	}
	actor := actorFrom(r)
	now := time.Now()

	// LINK mode: validate the URL shape and store the reference. No network.
	if req.IssueURL != "" {
		m := githubIssueURL.FindStringSubmatch(req.IssueURL)
		if m == nil {
			writeErr(w, http.StatusBadRequest, "issueUrl must be a GitHub issue URL (https://github.com/owner/repo/issues/N)")
			return
		}
		if err := s.tickets.SetExternal(id, req.IssueURL, m[3], now); err != nil {
			s.writeTicketErr(w, err)
			return
		}
		s.tickets.AddComment(id, "event", actor, "linked GitHub issue #"+m[3], now)
		s.audit(audit.EventTicketUpdate, actor, map[string]string{"ticket": id, "action": "github-link", "issue": m[3]})
		writeJSON(w, http.StatusOK, map[string]string{"externalUrl": req.IssueURL, "externalId": m[3]})
		return
	}

	// CREATE mode: the token is read here, used in one header, and dropped.
	token := os.Getenv(cfg.GitHubTokenEnv())
	if token == "" {
		writeErr(w, http.StatusServiceUnavailable, "no GitHub token in $"+cfg.GitHubTokenEnv()+" — export it for the serve process (referenced, never stored)")
		return
	}
	issueURL, issueNum, err := s.createGitHubIssue(cfg.Ticketing.GitHub.Repo, token, t.Title, t.Description, id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.tickets.SetExternal(id, issueURL, issueNum, now); err != nil {
		s.writeTicketErr(w, err)
		return
	}
	s.tickets.AddComment(id, "event", actor, "created GitHub issue #"+issueNum, now)
	s.audit(audit.EventTicketUpdate, actor, map[string]string{"ticket": id, "action": "github-create", "issue": issueNum})
	writeJSON(w, http.StatusOK, map[string]string{"externalUrl": issueURL, "externalId": issueNum})
}

// createGitHubIssue calls the GitHub REST API. Outbound content is exactly
// the ticket's human-authored title and description plus a provenance footer
// — never finding snippets, never credentials. Errors are bounded and never
// echo the token.
func (s *Server) createGitHubIssue(repo, token, title, description, ticketID string) (url, num string, err error) {
	body := description
	if body != "" {
		body += "\n\n"
	}
	body += "_Opened from Argus ticket " + ticketID + "._"
	payload, _ := json.Marshal(map[string]string{"title": title, "body": body})

	base := s.githubAPIBase
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequest(http.MethodPost, base+"/repos/"+repo+"/issues", bytes.NewReader(payload))
	if err != nil {
		return "", "", fmt.Errorf("github: build request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("github: request failed (network)")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("github: create issue failed (HTTP %d)", resp.StatusCode)
	}
	var out struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.HTMLURL == "" || out.Number == 0 {
		return "", "", fmt.Errorf("github: unexpected response shape")
	}
	// Trust but verify: the URL we store must itself be a GitHub issue URL.
	if !githubIssueURL.MatchString(out.HTMLURL) {
		return "", "", fmt.Errorf("github: response URL is not a GitHub issue URL")
	}
	return out.HTMLURL, fmt.Sprintf("%d", out.Number), nil
}
