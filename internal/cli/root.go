// Package cli implements the appsec command-line interface.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bulwark",
	Short: "Bulwark — AppSec + cloud posture, one wall",
	Long: `Bulwark runs the best open-source security scanners against your code and
cloud accounts, merges their output into one unified, risk-scored, compliance-
mapped findings model, gates CI on severity, and serves a three-persona web
console. Code (SAST), secrets, dependencies (SCA), infrastructure-as-code, and
cloud security posture (prowler) — one wall, many stones.`,
	Version: "0.1.0",
	// Errors and usage are handled in Execute: a severity-gate failure is a
	// scan outcome, not a CLI mistake, and must never print usage text.
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command. Exit codes: 0 success, 1 severity gate
// exceeded, 2 any other error.
func Execute() int {
	rootCmd.SetVersionTemplate("bulwark version {{.Version}}\n")
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, errGateFailed) {
			fmt.Fprintln(os.Stderr, "FAIL: severity gate exceeded")
			return 1
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 2
	}
	return 0
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
