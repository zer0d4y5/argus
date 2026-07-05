package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/leaky-hub/appsec/internal/server/auth"
)

// Console user management. This is the ONLY way to create the first user —
// there is deliberately no open registration endpoint (docs/console-ops.md
// §10): the API's user CRUD is for admins managing others after bootstrap.

func init() {
	userCmd.PersistentFlags().StringP("dir", "d", ".", "Repo directory whose .appsec/users.json to manage")
	userAddCmd.Flags().String("role", "viewer", "Role: viewer, operator, or admin")
	userAddCmd.Flags().Bool("password-stdin", false, "Read the password from stdin (for scripting)")
	userPasswdCmd.Flags().Bool("password-stdin", false, "Read the new password from stdin (for scripting)")
	userCmd.AddCommand(userAddCmd, userListCmd, userPasswdCmd, userRemoveCmd)
	rootCmd.AddCommand(userCmd)
}

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage console users (bootstrap and lifecycle)",
	Long: `Manages the console's user file (<dir>/.appsec/users.json).

The moment at least one user exists, every console API route requires a
login; with zero users the console stays a read-only, unauthenticated
viewer. Create the first admin here — there is no registration endpoint.`,
}

var userAddCmd = &cobra.Command{
	Use:   "add <username>",
	Short: "Add a console user (prompts for a password)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		roleStr, _ := cmd.Flags().GetString("role")
		role, err := auth.ParseRole(roleStr)
		if err != nil {
			return err
		}
		password, err := readPassword(cmd, true)
		if err != nil {
			return err
		}
		u, err := userStore(cmd).Add(args[0], password, role)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "==> added %s (%s) as %s\n", u.Username, u.ID, u.Role)
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List console users",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		users, err := userStore(cmd).List()
		if err != nil {
			return err
		}
		if len(users) == 0 {
			fmt.Println("no users configured — the console runs read-only without login (bootstrap: appsec user add <name> --role admin)")
			return nil
		}
		fmt.Printf("%-20s %-10s %-20s %s\n", "USERNAME", "ROLE", "ID", "CREATED")
		for _, u := range users {
			fmt.Printf("%-20s %-10s %-20s %s\n", u.Username, u.Role, u.ID, u.CreatedAt.Format("2006-01-02 15:04"))
		}
		return nil
	},
}

var userPasswdCmd = &cobra.Command{
	Use:   "passwd <username>",
	Short: "Change a console user's password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readPassword(cmd, true)
		if err != nil {
			return err
		}
		u, err := userStore(cmd).SetPassword(args[0], password)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "==> password updated for %s\n", u.Username)
		fmt.Fprintln(os.Stderr, "NOTE: a running console revokes the user's sessions on its next request")
		return nil
	},
}

var userRemoveCmd = &cobra.Command{
	Use:   "remove <username>",
	Short: "Remove a console user (refuses to remove the last admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		u, err := userStore(cmd).Remove(args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "==> removed %s (%s)\n", u.Username, u.Role)
		return nil
	},
}

func userStore(cmd *cobra.Command) *auth.Store {
	dir, _ := cmd.Flags().GetString("dir")
	return auth.ForRepo(dir)
}

// readPassword obtains a password without echoing it: interactively it
// prompts twice on the controlling terminal; with --password-stdin it reads
// all of stdin (trailing newline trimmed) for scripting.
func readPassword(cmd *cobra.Command, confirm bool) (string, error) {
	if fromStdin, _ := cmd.Flags().GetBool("password-stdin"); fromStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	if !term.IsTerminal(int(syscall.Stdin)) {
		return "", errors.New("stdin is not a terminal — use --password-stdin for non-interactive use")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm password: ")
		pw2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		if string(pw) != string(pw2) {
			return "", errors.New("passwords do not match")
		}
	}
	return string(pw), nil
}
