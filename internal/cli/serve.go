package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/server"
	"github.com/leaky-hub/appsec/ui"
)

func init() {
	serveCmd.Flags().String("addr", "127.0.0.1:8080", "Address to bind the console (widening past 127.0.0.1 exposes an UNAUTHENTICATED server)")
	serveCmd.Flags().StringP("dir", "d", ".", "Repo directory whose .appsec/runs history the console reads")
	serveCmd.Flags().String("gate", "high", "Severity threshold used to compute each run's gate outcome (critical|high|medium|low|info|none)")
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the local web console over saved scan runs",
	Long: `Starts a local-first web console that visualizes the scan history saved with
'appsec scan --save' (in <dir>/.appsec/runs). Three persona views — Overview
(GRC), Findings (AppSec), and Runs (SecOps) — over a read-only JSON API.

The console has NO AUTHENTICATION in this version. It binds 127.0.0.1 by
default; only widen --addr on a trusted network you control.`,
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

	srv := server.New(server.Options{
		Store:    runstore.ForRepo(dir),
		Gate:     gate,
		GateName: gateStr,
		Static:   static,
	})

	fmt.Fprintf(os.Stderr, "==> appsec console on http://%s  (reading %s/.appsec/runs)\n", addr, dir)
	if !isLoopback(addr) {
		fmt.Fprintf(os.Stderr, "WARNING: %s is not loopback — this console has NO AUTH and is now reachable off-host.\n", addr)
	}
	return srv.ListenAndServe(addr)
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
