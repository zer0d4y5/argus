package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/engagement"
)

func init() {
	engagementCreateCmd.Flags().String("name", "", "Human label for the engagement (required)")
	engagementCreateCmd.Flags().StringArray("scope", nil, "In-scope host, host:port, CIDR, URL-prefix, or *.domain wildcard (repeatable; at least one required)")
	engagementCreateCmd.Flags().StringArray("exclude", nil, "Out-of-scope exclusion, same grammar as --scope (repeatable; always wins over --scope)")
	engagementCreateCmd.Flags().String("auth-ref", "", "Authorization reference: the CVP ticket / rules-of-engagement id that makes testing lawful (required)")
	engagementCreateCmd.Flags().String("contact", "", "Operator contact of record")
	engagementCreateCmd.Flags().String("window-start", "", "Testing window start (RFC3339, e.g. 2026-07-12T09:00:00Z); empty = no earlier bound")
	engagementCreateCmd.Flags().String("window-end", "", "Testing window end (RFC3339); empty = no later bound")
	engagementCreateCmd.Flags().Float64("rate", 0, "Global request-rate ceiling in req/s (0 = conservative default)")
	engagementCreateCmd.Flags().Int("concurrency", 0, "Per-host concurrency ceiling (0 = conservative default)")
	engagementCreateCmd.Flags().Int64("budget", 0, "Total metered-request budget for the engagement (0 = conservative default)")
	engagementCreateCmd.Flags().Bool("allow-destructive", false, "Arm the engagement-level latch of the destructive interlock (still needs a per-run --i-have-authorization; hard limits always refuse)")
	engagementCreateCmd.Flags().Bool("activate", true, "Make this the active engagement after creating it")

	engagementCmd.AddCommand(engagementCreateCmd)
	engagementCmd.AddCommand(engagementListCmd)
	engagementCmd.AddCommand(engagementActivateCmd)
	engagementCmd.AddCommand(engagementShowCmd)
	engagementCmd.AddCommand(engagementVerifyAuditCmd)
	rootCmd.AddCommand(engagementCmd)
}

var engagementCmd = &cobra.Command{
	Use:   "engagement",
	Short: "Manage authorized testing engagements (scope, intensity ceiling, audit)",
	Long: `An engagement is the authorization spine of Argus's dynamic testing: it declares
the in-scope hosts/CIDRs/URL-prefixes, the out-of-scope exclusions, the
authorization reference that makes testing lawful, a testing window, and an
intensity ceiling. Active DAST modules refuse to send a single request without
one, every request is scope-gated and throttled, and everything is recorded to a
tamper-evident audit trail.

Engagements are stored under .appsec/engagements in the current directory.`,
}

var engagementCreateCmd = &cobra.Command{
	Use:   "create --name <name> --scope <entry> --auth-ref <id>",
	Short: "Create (and by default activate) a testing engagement",
	Long: `Creates a persisted engagement from an in-scope declaration and an authorization
reference. At least one --scope entry and an --auth-ref are required.

  argus engagement create --name "Acme staging" \
    --scope staging.acme.com --scope '*.staging.acme.com' \
    --exclude admin.staging.acme.com \
    --auth-ref CVP-2026-0412 --contact you@acme.com \
    --rate 8 --concurrency 3 --budget 15000`,
	Args: cobra.NoArgs,
	RunE: runEngagementCreate,
}

var engagementListCmd = &cobra.Command{
	Use:   "list",
	Short: "List engagements (the active one is marked)",
	Args:  cobra.NoArgs,
	RunE:  runEngagementList,
}

var engagementActivateCmd = &cobra.Command{
	Use:   "activate <id>",
	Short: "Set the active engagement used by active DAST modules",
	Args:  cobra.ExactArgs(1),
	RunE:  runEngagementActivate,
}

var engagementShowCmd = &cobra.Command{
	Use:   "show [id]",
	Short: "Show an engagement's scope, window, and intensity ceiling (default: the active one)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runEngagementShow,
}

var engagementVerifyAuditCmd = &cobra.Command{
	Use:   "verify-audit [id]",
	Short: "Verify the tamper-evident audit trail's hash chain (default: the active one)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runEngagementVerifyAudit,
}

// engagementStore returns the engagement store rooted at the current
// directory's .appsec, mirroring where DAST runs and dispositions live.
func engagementStore() (*engagement.Store, error) {
	base, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return &engagement.Store{Dir: filepath.Join(base, ".appsec", engagementsDirName)}, nil
}

const engagementsDirName = "engagements"

func runEngagementCreate(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	inScope, _ := cmd.Flags().GetStringArray("scope")
	exclude, _ := cmd.Flags().GetStringArray("exclude")
	authRef, _ := cmd.Flags().GetString("auth-ref")
	contact, _ := cmd.Flags().GetString("contact")
	rate, _ := cmd.Flags().GetFloat64("rate")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	budget, _ := cmd.Flags().GetInt64("budget")
	destructive, _ := cmd.Flags().GetBool("allow-destructive")

	window, err := windowFromFlags(cmd)
	if err != nil {
		return err
	}

	e, err := engagement.New(name, engagement.Scope{InScope: inScope, OutOfScope: exclude}, engagement.Options{
		AuthorizationRef: authRef,
		Contact:          contact,
		Window:           window,
		Intensity:        engagement.Intensity{RatePerSec: rate, PerHostConcurrency: concurrency, RequestBudget: budget},
		Destructive:      destructive,
	})
	if err != nil {
		return err
	}

	store, err := engagementStore()
	if err != nil {
		return err
	}
	if err := store.Save(e); err != nil {
		return err
	}
	// Seed the audit trail with the engagement's creation, so the chain begins
	// at a known, verifiable genesis.
	if audit, err := engagement.OpenAudit(store.AuditPath(e.ID)); err == nil {
		_ = audit.Append(engagement.EventEngagementCreate, map[string]string{
			"id": e.ID, "name": e.Name, "authorizationRef": e.AuthorizationRef,
		})
	}

	if activate, _ := cmd.Flags().GetBool("activate"); activate {
		if err := store.SetActive(e.ID); err != nil {
			return err
		}
	}

	in := e.EffectiveIntensity()
	fmt.Fprintf(os.Stdout, "Created engagement %s (%q)\n", e.ID, e.Name)
	fmt.Fprintf(os.Stdout, "  authorization: %s\n", e.AuthorizationRef)
	fmt.Fprintf(os.Stdout, "  in scope:      %v\n", e.Scope.InScope)
	if len(e.Scope.OutOfScope) > 0 {
		fmt.Fprintf(os.Stdout, "  out of scope:  %v\n", e.Scope.OutOfScope)
	}
	fmt.Fprintf(os.Stdout, "  intensity:     %.0f req/s, %d concurrent/host, %d request budget\n", in.RatePerSec, in.PerHostConcurrency, in.RequestBudget)
	if e.Destructive {
		fmt.Fprintln(os.Stdout, "  destructive:   armed (still needs a per-run --i-have-authorization; hard limits always refuse)")
	}
	return nil
}

// windowFromFlags parses the optional testing-window bounds.
func windowFromFlags(cmd *cobra.Command) (engagement.Window, error) {
	var w engagement.Window
	if s, _ := cmd.Flags().GetString("window-start"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return w, fmt.Errorf("--window-start is not RFC3339: %w", err)
		}
		w.Start = t.UTC()
	}
	if s, _ := cmd.Flags().GetString("window-end"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return w, fmt.Errorf("--window-end is not RFC3339: %w", err)
		}
		w.End = t.UTC()
	}
	return w, nil
}

func runEngagementList(cmd *cobra.Command, _ []string) error {
	store, err := engagementStore()
	if err != nil {
		return err
	}
	list, err := store.List()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stdout, "No engagements. Create one with `argus engagement create`.")
		return nil
	}
	active, _ := store.Active()
	activeID := ""
	if active != nil {
		activeID = active.ID
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ACTIVE\tID\tNAME\tAUTHORIZATION\tSCOPE\tWINDOW")
	for _, e := range list {
		mark := ""
		if e.ID == activeID {
			mark = "*"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d in / %d out\t%s\n",
			mark, e.ID, e.Name, e.AuthorizationRef, len(e.Scope.InScope), len(e.Scope.OutOfScope), windowLabel(e.Window))
	}
	return tw.Flush()
}

func windowLabel(w engagement.Window) string {
	if w.Start.IsZero() && w.End.IsZero() {
		return "open"
	}
	s, en := "-inf", "+inf"
	if !w.Start.IsZero() {
		s = w.Start.Format(time.RFC3339)
	}
	if !w.End.IsZero() {
		en = w.End.Format(time.RFC3339)
	}
	return s + " .. " + en
}

func runEngagementActivate(cmd *cobra.Command, args []string) error {
	store, err := engagementStore()
	if err != nil {
		return err
	}
	if err := store.SetActive(args[0]); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Active engagement is now %s\n", args[0])
	return nil
}

// resolveEngagementArg loads the engagement named by an optional positional arg,
// falling back to the active one.
func resolveEngagementArg(store *engagement.Store, args []string) (*engagement.Engagement, error) {
	if len(args) == 1 {
		return store.Load(args[0])
	}
	e, err := store.Active()
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, fmt.Errorf("no active engagement; pass an id or run `argus engagement activate <id>`")
	}
	return e, nil
}

func runEngagementShow(cmd *cobra.Command, args []string) error {
	store, err := engagementStore()
	if err != nil {
		return err
	}
	e, err := resolveEngagementArg(store, args)
	if err != nil {
		return err
	}
	in := e.EffectiveIntensity()
	fmt.Fprintf(os.Stdout, "Engagement %s\n", e.ID)
	fmt.Fprintf(os.Stdout, "  name:          %s\n", e.Name)
	fmt.Fprintf(os.Stdout, "  authorization: %s\n", e.AuthorizationRef)
	fmt.Fprintf(os.Stdout, "  contact:       %s\n", e.Contact)
	fmt.Fprintf(os.Stdout, "  created:       %s\n", e.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(os.Stdout, "  window:        %s\n", windowLabel(e.Window))
	fmt.Fprintf(os.Stdout, "  in scope:\n")
	for _, s := range e.Scope.InScope {
		fmt.Fprintf(os.Stdout, "    + %s\n", s)
	}
	for _, s := range e.Scope.OutOfScope {
		fmt.Fprintf(os.Stdout, "    - %s (excluded)\n", s)
	}
	fmt.Fprintf(os.Stdout, "  intensity:     %.0f req/s, %d concurrent/host, %d request budget\n", in.RatePerSec, in.PerHostConcurrency, in.RequestBudget)
	fmt.Fprintf(os.Stdout, "  destructive:   %v\n", e.Destructive)
	return nil
}

func runEngagementVerifyAudit(cmd *cobra.Command, args []string) error {
	store, err := engagementStore()
	if err != nil {
		return err
	}
	e, err := resolveEngagementArg(store, args)
	if err != nil {
		return err
	}
	res, err := engagement.Verify(store.AuditPath(e.ID))
	if err != nil {
		return fmt.Errorf("audit trail could not be read: %w", err)
	}
	if res.OK {
		fmt.Fprintf(os.Stdout, "Audit trail for %s is intact: %d entr%s verified.\n", e.ID, res.Entries, plural(res.Entries))
		return nil
	}
	return fmt.Errorf("AUDIT TRAIL BROKEN for %s at sequence %d: %s (%d entr%s before the break)",
		e.ID, res.BadSeq, res.Reason, res.Entries, plural(res.Entries))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
