package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/gitws"
	"github.com/zer0d4y5/argus/internal/jobs"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/server"
	"github.com/zer0d4y5/argus/internal/server/auth"
	"github.com/zer0d4y5/argus/internal/store"
	"github.com/zer0d4y5/argus/internal/targets"
	"github.com/zer0d4y5/argus/internal/threatmodel"
	"github.com/zer0d4y5/argus/internal/ticket"
	"github.com/zer0d4y5/argus/ui"
)

func init() {
	serveCmd.Flags().String("addr", "127.0.0.1:8080", "Address to bind the console (leave loopback unless a TLS reverse proxy fronts it)")
	serveCmd.Flags().StringP("dir", "d", ".", "Repo directory whose .appsec state (runs, users, targets, audit) the console serves")
	serveCmd.Flags().String("gate", "high", "Severity threshold used to compute each run's gate outcome (critical|high|medium|low|info|none)")
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the web console: scan history, and (with users) scan launching",
	Long: `Starts the local-first web console over the scan history saved with
'argus scan --save' (in <dir>/.appsec/runs).

Authentication is decided by <dir>/.appsec/users.json:

  - ZERO users (default): a read-only, unauthenticated viewer — exactly the
    pre-auth console. Operational endpoints answer 403 and name the
    bootstrap command.
  - ONE OR MORE users: every API route requires a login (viewer, operator,
    or admin role). Operators launch scans against registered targets
    ('argus target add' — a local directory or a remote https git repo)
    through a strictly serial job queue, optionally scoped to a subpath or
    focused on compliance frameworks; admins manage users, targets,
    per-target scan configuration, and the audit log. Bootstrap the first
    admin with 'argus user add <name> --role admin'.

Remote git targets are cloned shallowly into <dir>/.appsec/workspace/<id>
(https only; the scanned commit is recorded on the job and in the audit
log). Findings can be explained on demand by the target repo's configured
triage LLM; explanations are never persisted.

The server terminates no TLS. It binds 127.0.0.1 by default; the supported
way to expose it further is a TLS-terminating reverse proxy in front
(docs/console-ops.md).`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func runServe(cmd *cobra.Command, args []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	dir, _ := cmd.Flags().GetString("dir")
	gateStr, _ := cmd.Flags().GetString("gate")

	gate, err := model.ParseGate(gateStr)
	if err != nil {
		return fmt.Errorf("invalid gate: %w", err)
	}

	static, err := ui.Dist()
	if err != nil {
		return fmt.Errorf("load embedded UI: %w", err)
	}

	users := auth.ForRepo(dir)
	registry := targets.ForRepo(dir)
	auditLog := audit.ForRepo(dir)
	queue := jobs.New(server.ScanExecutor(registry, auditLog, gitws.New(), dir))
	queue.Start(cmd.Context())

	// The embedded SQLite store holds the ticketing (and, later, threat-model)
	// tables at <dir>/.appsec/argus.db. It never holds the gate's input.
	db, err := store.Open(filepath.Join(dir, ".appsec"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	srv := server.New(server.Options{
		Store:    runstore.ForRepo(dir),
		Dir:      dir,
		Gate:     gate,
		GateName: gateStr,
		Static:   static,
		Users:    users,
		Sessions: auth.NewSessions(),
		Limiter:  auth.NewLoginLimiter(),
		Targets:  registry,
		Audit:    auditLog,
		Queue:    queue,
		Tickets:  ticket.NewStore(db),
		Threats:  threatmodel.NewStore(db),
	})

	fmt.Fprintf(os.Stderr, "==> appsec console on http://%s  (serving %s/.appsec)\n", addr, dir)
	printAuthStatus(cmd.Context(), users, addr)
	return srv.ListenAndServe(addr)
}

// printAuthStatus tells the operator, truthfully, what security posture this
// process is actually running with — and warns when the bind address makes
// that posture dangerous.
func printAuthStatus(_ context.Context, users *auth.Store, addr string) {
	n, err := users.Count()
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "WARNING: users file unreadable (%v) — all authentication refused until fixed.\n", err)
	case n == 0:
		fmt.Fprintln(os.Stderr, "==> no users configured: read-only console, NO login. Bootstrap ops with `argus user add <name> --role admin`.")
		if !isLoopback(addr) {
			fmt.Fprintf(os.Stderr, "WARNING: %s is not loopback — this console has NO AUTH and is now reachable off-host.\n", addr)
		}
	default:
		fmt.Fprintf(os.Stderr, "==> authentication required (%d user(s)); scan launching enabled for registered targets.\n", n)
		if !isLoopback(addr) {
			fmt.Fprintf(os.Stderr, "WARNING: %s is not loopback and this server terminates no TLS — logins cross the network in CLEARTEXT unless a TLS reverse proxy fronts it (docs/console-ops.md).\n", addr)
		}
	}
}

// isLoopback reports whether addr binds only the loopback interface. A bare
// port or an explicit 127.x / localhost / ::1 host is loopback; anything else
// (0.0.0.0, a LAN IP) is treated as off-host for the warning.
func isLoopback(addr string) bool {
	host := addr
	if i := lastColon(addr); i >= 0 {
		host = addr[:i]
	}
	switch host {
	case "", "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return len(host) >= 4 && host[:4] == "127."
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}
