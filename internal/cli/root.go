// Package cli implements the appsec command-line interface.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "appsec",
	Short:   "Application security scanning pipeline",
	Long:    `A unified CLI for running multiple security scanners, correlating findings, and enforcing severity gates.`,
	Version: "0.1.0",
	// Errors and usage are handled in Execute: a severity-gate failure is a
	// scan outcome, not a CLI mistake, and must never print usage text.
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command. Exit codes: 0 success, 1 severity gate
// exceeded, 2 any other error.
func Execute() int {
	rootCmd.SetVersionTemplate("appsec version {{.Version}}\n")
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
