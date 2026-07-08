package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/scanner"
)

// registryBase is the semgrep registry endpoint that resolves a pack reference
// to its rules as YAML: registryBase + "p/security-audit" returns that pack.
const registryBase = "https://semgrep.dev/c/"

func init() {
	rulesSyncCmd.Flags().String("profile", "", "Profile whose packs to fetch: fast, standard, or max (default: config profile, else standard)")
	rulesSyncCmd.Flags().String("cache-dir", "", "Directory to store cached packs (default: config offline.cache_dir, else <user-cache>/argus/rules)")
	rulesSyncCmd.Flags().StringP("config", "c", "", "Path to argus.yml (or appsec.yml) configuration file")
	rulesCmd.AddCommand(rulesSyncCmd)
	rootCmd.AddCommand(rulesCmd)
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage the local rule-pack cache for offline scanning",
	Long: `Prepare local rule packs so scans can run fully offline.

The curated Argus rules are always embedded in the binary and need no sync;
this command caches the semgrep REGISTRY packs a profile uses so that
` + "`argus scan --offline`" + ` (or offline: true) can run them without network access.`,
}

var rulesSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Fetch the profile's registry packs into the local cache for offline use",
	Long: `Fetches each semgrep registry pack in the selected profile from the semgrep
registry and stores it in the local cache. Run this once on a networked machine;
afterwards ` + "`argus scan --offline`" + ` uses the cache and never touches the network.
The cache directory can be copied to an air-gapped host.`,
	Args: cobra.NoArgs,
	RunE: runRulesSync,
}

func runRulesSync(cmd *cobra.Command, _ []string) error {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	profile, _ := cmd.Flags().GetString("profile")
	if profile == "" {
		profile = cfg.Profile
	}
	if err := scanner.ValidateProfile(profile); err != nil {
		return err
	}

	cacheOverride, _ := cmd.Flags().GetString("cache-dir")
	if cacheOverride == "" {
		cacheOverride = cfg.Offline.CacheDir
	}
	cacheDir := scanner.RulesCacheDir(cacheOverride)

	// The profile's registry packs are exactly what an offline scan needs
	// cached; the curated sentinel and any local BYO paths are already local.
	packs := scanner.RegistryPacksIn(scanner.ResolveSemgrepRulesets(profile, cfg.SemgrepRules))
	if len(packs) == 0 {
		fmt.Fprintf(os.Stderr, "No registry packs to sync for profile %q (curated rules are embedded).\n", profileName(profile))
		return nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("rules sync: create cache dir: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Syncing %d pack(s) for profile %q to %s\n", len(packs), profileName(profile), cacheDir)
	client := &http.Client{Timeout: 90 * time.Second}
	var failed int
	for _, pack := range packs {
		dst := scanner.CachedPackPath(cacheDir, pack)
		if err := fetchPack(cmd.Context(), client, pack, dst); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  ! %s: %v\n", pack, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "  ✓ %s\n", pack)
	}
	if failed > 0 {
		return fmt.Errorf("rules sync: %d of %d pack(s) failed", failed, len(packs))
	}
	fmt.Fprintf(os.Stderr, "Done. `argus scan --offline` will now use these packs.\n")
	return nil
}

// fetchPack downloads one registry pack to dst, validating that it is a
// loadable semgrep config before committing it (so a truncated or error-page
// response never poisons the cache). The write is atomic via a temp file.
func fetchPack(ctx context.Context, client *http.Client, pack, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryBase+pack, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MiB ceiling
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(body) == 0 {
		return fmt.Errorf("empty response")
	}

	// Stage to a temp file and validate with semgrep before publishing, so the
	// cache only ever holds configs semgrep can actually load.
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".pack-*.yml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := scanner.ValidateLocalRuleFile(ctx, tmpName); err != nil {
		return fmt.Errorf("fetched content is not a valid semgrep config: %w", err)
	}
	return os.Rename(tmpName, dst)
}

// profileName renders the effective profile label for messages ("" -> the
// default), without duplicating the resolver's fallback logic.
func profileName(p string) string {
	if p == "" {
		return scanner.DefaultProfile
	}
	return p
}
