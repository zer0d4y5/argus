package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/leaky-hub/appsec/internal/store"
	"github.com/leaky-hub/appsec/internal/threatlib"
	"github.com/leaky-hub/appsec/internal/threatmodel"
)

// Threat-model management from the CLI, over the same SQLite store the console
// uses. Consistent with `argus ticket` / `argus comply`.

func init() {
	threatsCmd.PersistentFlags().StringP("dir", "d", ".", "Repo directory whose .appsec/argus.db to use")
	threatsNewCmd.Flags().String("name", "", "Model name (required)")
	threatsNewCmd.Flags().String("target", "", "Target id this model is scoped to")
	threatsComponentCmd.Flags().String("name", "", "Component name (required)")
	threatsComponentCmd.Flags().String("tech", "", "Component tech (see `argus threats library`)")
	threatsEnumerateCmd.Flags().String("component", "", "Component id to enumerate (required)")
	threatsCmd.AddCommand(threatsListCmd, threatsShowCmd, threatsLibraryCmd, threatsNewCmd, threatsComponentCmd, threatsEnumerateCmd)
	rootCmd.AddCommand(threatsCmd)
}

func openThreats(cmd *cobra.Command) (*threatmodel.Store, func(), error) {
	dir, _ := cmd.Flags().GetString("dir")
	db, err := store.Open(filepath.Join(dir, ".appsec"))
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	return threatmodel.NewStore(db), func() { db.Close() }, nil
}

var threatsCmd = &cobra.Command{
	Use:   "threats",
	Short: "Manage threat models and enumerate STRIDE over components",
	Long: `Manages threat models in the local database (<dir>/.appsec/argus.db).
A model holds components; enumerating a component pulls the curated STRIDE
threats for its tech from the library, each wired to a mitigation.`,
}

var threatsLibraryCmd = &cobra.Command{
	Use:   "library",
	Short: "List the component types STRIDE can be enumerated for",
	RunE: func(_ *cobra.Command, _ []string) error {
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "TECH\tTITLE\tTHREATS")
		for _, c := range threatlib.Components() {
			fmt.Fprintf(w, "%s\t%s\t%d\n", c.Tech, c.Title, len(c.Threats))
		}
		return w.Flush()
	},
}

var threatsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List threat models",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ts, done, err := openThreats(cmd)
		if err != nil {
			return err
		}
		defer done()
		models, err := ts.ListModels("")
		if err != nil {
			return err
		}
		if len(models) == 0 {
			fmt.Println("No threat models.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tTARGET\tNAME")
		for _, m := range models {
			fmt.Fprintf(w, "%s\t%s\t%s\n", m.ID, orDash(m.TargetID), m.Name)
		}
		return w.Flush()
	},
}

var threatsShowCmd = &cobra.Command{
	Use:   "show <model-id>",
	Short: "Show a model with its components and threats",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ts, done, err := openThreats(cmd)
		if err != nil {
			return err
		}
		defer done()
		m, err := ts.GetModel(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s  %s\n", m.ID, m.Name)
		comps, _ := ts.Components(m.ID)
		fmt.Printf("\nComponents (%d):\n", len(comps))
		for _, c := range comps {
			fmt.Printf("  %s  %s  [%s]%s\n", c.ID, c.Name, c.Kind, techSuffix(c.Tech))
		}
		threats, _ := ts.Threats(m.ID)
		fmt.Printf("\nThreats (%d):\n", len(threats))
		for _, t := range threats {
			fmt.Printf("  [%s/%s] %s%s\n", t.Category, t.Status, t.Title, fixSuffix(t.Mitigation))
		}
		return nil
	},
}

var threatsNewCmd = &cobra.Command{
	Use:   "new --name <name>",
	Short: "Create a threat model",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ts, done, err := openThreats(cmd)
		if err != nil {
			return err
		}
		defer done()
		m, err := ts.CreateModel(mustString(cmd, "target"), mustString(cmd, "name"), "", "cli", time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Created %s\n", m.ID)
		return nil
	},
}

var threatsComponentCmd = &cobra.Command{
	Use:   "add-component <model-id> --name <name> --tech <tech>",
	Short: "Add a component to a model",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ts, done, err := openThreats(cmd)
		if err != nil {
			return err
		}
		defer done()
		c, err := ts.AddComponent(args[0], "component", mustString(cmd, "name"), mustString(cmd, "tech"), "", "manual", time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Added component %s\n", c.ID)
		return nil
	},
}

var threatsEnumerateCmd = &cobra.Command{
	Use:   "enumerate <model-id> --component <component-id>",
	Short: "Enumerate STRIDE threats for a component from the curated library",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, _ []string) error {
		ts, done, err := openThreats(cmd)
		if err != nil {
			return err
		}
		defer done()
		compID := mustString(cmd, "component")
		if compID == "" {
			return fmt.Errorf("--component is required")
		}
		n, err := ts.EnumerateComponent(compID, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Added %d threat(s).\n", n)
		return nil
	},
}

func techSuffix(t string) string {
	if t == "" {
		return ""
	}
	return " tech=" + t
}
func fixSuffix(m string) string {
	if m == "" {
		return ""
	}
	return "  (fix: " + m + ")"
}
