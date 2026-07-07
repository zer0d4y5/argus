package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leaky-hub/argus/internal/mitigation"
)

func init() {
	rootCmd.AddCommand(mitigationsCmd)
}

var mitigationsCmd = &cobra.Command{
	Use:   "mitigations [weakness]",
	Short: "Browse the secure-coding library (before/after fixes by weakness and language)",
	Long: `Argus ships a curated, human-vetted library of secure-code fixes: for each
weakness class (SQL injection, XSS, SSRF, CSRF, session management, command
injection, path traversal, …) it holds a fixing principle, before/after code
per language, the library to use, and references.

With no argument it lists the classes. Pass a weakness id to print its fixes.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		if len(args) == 0 {
			fmt.Fprintln(out, "Secure-coding library — run `argus mitigations <id>` for the fixes:")
			for _, g := range mitigation.List() {
				fmt.Fprintf(out, "  %-20s %s (%s)\n", g.Weakness, g.Title, strings.Join(g.CWEs, ", "))
			}
			return nil
		}
		g, ok := mitigation.Get(args[0])
		if !ok {
			return fmt.Errorf("unknown weakness %q; run `argus mitigations` to list them", args[0])
		}
		fmt.Fprintf(out, "# %s (%s)\n\n%s\n\n", g.Title, strings.Join(g.CWEs, ", "), g.Principle)
		for _, s := range g.Snippets {
			fmt.Fprintf(out, "## %s\n", s.Language)
			if s.Library != "" {
				fmt.Fprintf(out, "use: %s\n", s.Library)
			}
			fmt.Fprintf(out, "\n-- vulnerable --\n%s\n\n-- secure --\n%s\n", s.Vulnerable, s.Secure)
			if s.Note != "" {
				fmt.Fprintf(out, "\nnote: %s\n", s.Note)
			}
			fmt.Fprintln(out)
		}
		if len(g.References) > 0 {
			fmt.Fprintln(out, "references:")
			for _, r := range g.References {
				fmt.Fprintf(out, "  %s — %s\n", r.Title, r.URL)
			}
		}
		return nil
	},
}
