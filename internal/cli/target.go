package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leaky-hub/appsec/internal/targets"
)

// Scan-target registry management. Targets are the console's allowlist of
// scannable directories (docs/console-ops.md §7): the browser only ever
// sends a target ID, so registration — here or via the admin API — is the
// single place a filesystem path enters the system, and it is validated
// here (absolute, exists, directory, not /).

func init() {
	targetCmd.PersistentFlags().StringP("dir", "d", ".", "Repo directory whose .appsec/targets.json to manage")
	targetAddCmd.Flags().String("name", "", "Display name for the target (default: path basename)")
	targetAddCmd.Flags().String("scanners", "", "Comma-separated allowed scanners (default: all)")
	targetAddCmd.Flags().String("profile", "", "Default scan profile: fast, standard, or max")
	targetCmd.AddCommand(targetAddCmd, targetListCmd, targetRemoveCmd)
	rootCmd.AddCommand(targetCmd)
}

var targetCmd = &cobra.Command{
	Use:   "target",
	Short: "Manage the registry of directories the console may scan",
	Long: `Manages the scan-target registry (<dir>/.appsec/targets.json).

Console-launched scans run only against registered targets, addressed by
opaque ID — the browser can never supply a filesystem path. Paths are
validated here, at registration time.`,
}

var targetAddCmd = &cobra.Command{
	Use:   "add <path>",
	Short: "Register a directory as a scannable target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		abs, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve path: %w", err)
		}
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			name = filepath.Base(abs)
		}
		var scannerNames []string
		if s, _ := cmd.Flags().GetString("scanners"); s != "" {
			for _, n := range strings.Split(s, ",") {
				scannerNames = append(scannerNames, strings.ToLower(strings.TrimSpace(n)))
			}
		}
		profile, _ := cmd.Flags().GetString("profile")
		t, err := targetRegistry(cmd).Add(name, abs, scannerNames, profile)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "==> registered %s (%s) -> %s\n", t.Name, t.ID, t.Path)
		return nil
	},
}

var targetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered scan targets",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		list, err := targetRegistry(cmd).List()
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Println("no targets registered (appsec target add <path> --name <label>)")
			return nil
		}
		fmt.Printf("%-20s %-20s %-10s %-25s %s\n", "ID", "NAME", "PROFILE", "SCANNERS", "PATH")
		for _, t := range list {
			scanners := "all"
			if len(t.Scanners) > 0 {
				scanners = strings.Join(t.Scanners, ",")
			}
			profile := t.Profile
			if profile == "" {
				profile = "standard"
			}
			fmt.Printf("%-20s %-20s %-10s %-25s %s\n", t.ID, t.Name, profile, scanners, t.Path)
		}
		return nil
	},
}

var targetRemoveCmd = &cobra.Command{
	Use:   "remove <id-or-name>",
	Short: "Remove a registered scan target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		t, err := targetRegistry(cmd).Remove(args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "==> removed %s (%s)\n", t.Name, t.ID)
		return nil
	},
}

func targetRegistry(cmd *cobra.Command) *targets.Registry {
	dir, _ := cmd.Flags().GetString("dir")
	return targets.ForRepo(dir)
}
