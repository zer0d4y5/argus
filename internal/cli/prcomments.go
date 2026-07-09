package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/prcomment"
)

// postPRComments posts the gate-relevant findings (new since the baseline,
// disposition-filtered: exactly the set the severity gate is about to judge)
// as one batched review on the pull request. Advisory only, by design: every
// failure here is a warning on stderr and the exit code stays the gate's.
// The token is read from the configured env var at the last moment and used
// in the Authorization header only (referenced, never stored or logged).
func postPRComments(cmd *cobra.Command, cfg config.Config, findings []model.Finding) {
	flagPR, _ := cmd.Flags().GetInt("pr")
	repo, pr, apiBase, err := prcomment.Resolve(flagPR, cfg.Ticketing.GitHub.Repo)
	if errors.Is(err, prcomment.ErrNotAPullRequest) {
		fmt.Fprintln(os.Stderr, "NOTE: --pr-comments: not a pull request run; nothing to post (pass --pr N outside GitHub Actions)")
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: --pr-comments: %v\n", err)
		return
	}
	token := os.Getenv(cfg.GitHubTokenEnv())
	if token == "" {
		fmt.Fprintf(os.Stderr, "WARN: --pr-comments: no token in $%s; skipping\n", cfg.GitHubTokenEnv())
		return
	}
	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "NOTE: --pr-comments: no new findings; nothing to post on %s#%d\n", repo, pr)
		return
	}
	res, err := prcomment.Post(cmd.Context(), prcomment.Options{Repo: repo, PR: pr, Token: token, APIBase: apiBase}, findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: --pr-comments: %v\n", err)
		return
	}
	if res.Inline == 0 && res.InBody == 0 {
		fmt.Fprintf(os.Stderr, "NOTE: --pr-comments: everything already posted on %s#%d (%s)\n", repo, pr, res)
		return
	}
	fmt.Fprintf(os.Stderr, "==> posted review on %s#%d: %s\n", repo, pr, res)
}
