package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/store"
	"github.com/zer0d4y5/argus/internal/ticket"
)

// Ticket management from the CLI, over the same SQLite store the console uses
// (<dir>/.appsec/argus.db). Consistent with `argus target` / `argus comply`.
// The actor for CLI writes is "cli"; the console records real usernames.

func init() {
	ticketCmd.PersistentFlags().StringP("dir", "d", ".", "Repo directory whose .appsec/argus.db to use")
	ticketCreateCmd.Flags().String("title", "", "Ticket title (required)")
	ticketCreateCmd.Flags().String("priority", "medium", "Priority: low, medium, high, urgent")
	ticketCreateCmd.Flags().String("target", "", "Target id the linked findings belong to")
	ticketCreateCmd.Flags().StringSlice("finding", nil, "Finding fingerprint to link (repeatable)")
	ticketListCmd.Flags().String("status", "", "Filter by status: open, in-progress, blocked, done")
	ticketLinkCmd.Flags().String("finding", "", "Finding fingerprint to link (required)")
	ticketLinkCmd.Flags().String("target", "", "Target id the finding belongs to")
	ticketCmd.AddCommand(ticketListCmd, ticketShowCmd, ticketCreateCmd, ticketCommentCmd, ticketLinkCmd)
	rootCmd.AddCommand(ticketCmd)
}

// openTickets opens the ticket store for the -d directory.
func openTickets(cmd *cobra.Command) (*ticket.Store, func(), error) {
	dir, _ := cmd.Flags().GetString("dir")
	db, err := store.Open(filepath.Join(dir, ".appsec"))
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	return ticket.NewStore(db), func() { db.Close() }, nil
}

var ticketCmd = &cobra.Command{
	Use:   "ticket",
	Short: "Manage work-tracking tickets over findings",
	Long: `Manages tickets in the local database (<dir>/.appsec/argus.db) — the
same store the console uses. A ticket gathers findings (by fingerprint),
carries a status and priority, and a comment timeline.`,
}

var ticketListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tickets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ts, done, err := openTickets(cmd)
		if err != nil {
			return err
		}
		defer done()
		list, err := ts.List(ticket.ListFilter{Status: mustString(cmd, "status")})
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Println("No tickets.")
			return nil
		}
		links, _ := ts.AllLinks()
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tPRIORITY\tSTATUS\tLINKS\tTITLE")
		for _, t := range list {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", t.ID, t.Priority, t.Status, len(links[t.ID]), t.Title)
		}
		return w.Flush()
	},
}

var ticketShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show a ticket with its findings and timeline",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ts, done, err := openTickets(cmd)
		if err != nil {
			return err
		}
		defer done()
		t, err := ts.Get(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s  [%s / %s]\n%s\n", t.ID, t.Priority, t.Status, t.Title)
		if t.Description != "" {
			fmt.Printf("\n%s\n", t.Description)
		}
		links, _ := ts.Links(t.ID)
		fmt.Printf("\nLinked findings (%d):\n", len(links))
		for _, l := range links {
			fmt.Printf("  %s%s\n", l.FindingID, targetSuffix(l.TargetID))
		}
		comments, _ := ts.Comments(t.ID)
		fmt.Printf("\nTimeline (%d):\n", len(comments))
		for _, c := range comments {
			fmt.Printf("  [%s] %s — %s\n", c.CreatedAt, c.Body, orDash(c.Author))
		}
		return nil
	},
}

var ticketCreateCmd = &cobra.Command{
	Use:   "create --title <title>",
	Short: "Create a ticket, optionally linking findings",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ts, done, err := openTickets(cmd)
		if err != nil {
			return err
		}
		defer done()
		targetID := mustString(cmd, "target")
		t, err := ts.Create(ticket.CreateInput{
			Title:    mustString(cmd, "title"),
			Priority: mustString(cmd, "priority"),
			TargetID: targetID,
		}, "cli", time.Now())
		if err != nil {
			return err
		}
		findings, _ := cmd.Flags().GetStringSlice("finding")
		for _, fp := range findings {
			if err := ts.Link(t.ID, fp, targetID); err != nil {
				return err
			}
		}
		fmt.Printf("Created %s (%d finding(s) linked)\n", t.ID, len(findings))
		return nil
	},
}

var ticketCommentCmd = &cobra.Command{
	Use:   "comment <id> <text>",
	Short: "Add a comment to a ticket",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ts, done, err := openTickets(cmd)
		if err != nil {
			return err
		}
		defer done()
		if _, err := ts.AddComment(args[0], "comment", "cli", args[1], time.Now()); err != nil {
			return err
		}
		fmt.Println("Comment added.")
		return nil
	},
}

var ticketLinkCmd = &cobra.Command{
	Use:   "link <id> --finding <fingerprint>",
	Short: "Link a finding to a ticket",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ts, done, err := openTickets(cmd)
		if err != nil {
			return err
		}
		defer done()
		fp := mustString(cmd, "finding")
		if fp == "" {
			return fmt.Errorf("--finding is required")
		}
		if err := ts.Link(args[0], fp, mustString(cmd, "target")); err != nil {
			return err
		}
		fmt.Println("Linked.")
		return nil
	},
}

func mustString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}
func targetSuffix(t string) string {
	if t == "" {
		return ""
	}
	return " (" + t + ")"
}
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
