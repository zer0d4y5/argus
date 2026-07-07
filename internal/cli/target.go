package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leaky-hub/argus/internal/targets"
)

// Scan-target registry management. Targets are the console's allowlist of
// scannable directories (docs/console-ops.md §7): the browser only ever
// sends a target ID, so registration — here or via the admin API — is the
// single place a filesystem path enters the system, and it is validated
// here (absolute, exists, directory, not /).

func init() {
	targetCmd.PersistentFlags().StringP("dir", "d", ".", "Repo directory whose .appsec/targets.json to manage")
	targetAddCmd.Flags().String("name", "", "Display name for the target (default: path basename / repo name)")
	targetAddCmd.Flags().String("scanners", "", "Comma-separated allowed scanners (default: all)")
	targetAddCmd.Flags().String("profile", "", "Default scan profile: fast, standard, or max")
	targetAddCmd.Flags().String("branch", "", "Branch to track (git targets only; default: remote HEAD)")
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
	Use:   "add <path-or-https-url>",
	Short: "Register a directory or a remote git repo as a scannable target",
	Long: `Registers a scan target: a local directory by path, or a remote git
repository by https URL (cloned shallowly into the server-owned
.appsec/workspace/<id> on each scan; docs/console-ops.md S1). Only https
URLs are accepted — private repos authenticate through the host's ambient
git credential helper.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		var scannerNames []string
		if s, _ := cmd.Flags().GetString("scanners"); s != "" {
			for _, n := range strings.Split(s, ",") {
				scannerNames = append(scannerNames, strings.ToLower(strings.TrimSpace(n)))
			}
		}
		profile, _ := cmd.Flags().GetString("profile")
		branch, _ := cmd.Flags().GetString("branch")

		if strings.HasPrefix(strings.ToLower(args[0]), "https://") {
			if name == "" {
				name = strings.TrimSuffix(filepath.Base(args[0]), ".git")
			}
			t, err := targetRegistry(cmd).AddGit(name, args[0], branch, scannerNames, profile)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "==> registered %s (%s) -> %s\n", t.Name, t.ID, t.URL)
			return nil
		}

		if branch != "" {
			return fmt.Errorf("--branch applies to git targets (https URLs) only")
		}
		abs, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("resolve path: %w", err)
		}
		if name == "" {
			name = filepath.Base(abs)
		}
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
			fmt.Println("no targets registered (argus target add <path> --name <label>)")
			return nil
		}
		fmt.Printf("%-20s %-20s %-5s %-10s %-25s %s\n", "ID", "NAME", "TYPE", "PROFILE", "SCANNERS", "WHERE")
		for _, t := range list {
			scanners := "all"
			if len(t.Scanners) > 0 {
				scanners = strings.Join(t.Scanners, ",")
			}
			profile := t.Profile
			if profile == "" {
				profile = "standard"
			}
			where := t.Path
			if t.Kind() == targets.TypeGit {
				where = t.URL
				if t.Branch != "" {
					where += "@" + t.Branch
				}
			}
			fmt.Printf("%-20s %-20s %-5s %-10s %-25s %s\n", t.ID, t.Name, t.Kind(), profile, scanners, where)
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
