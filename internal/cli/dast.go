package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/dastscan"
	"github.com/zer0d4y5/argus/internal/engagement"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/runstore"
)

func init() {
	dastCmd.Flags().StringP("format", "f", "", "Output format: sarif, markdown, or json (default from config)")
	dastCmd.Flags().String("fail-severity", "", "Fail if findings meet or exceed this severity (critical|high|medium|low|info|none)")
	dastCmd.Flags().StringP("config", "c", "", "Path to argus.yml (or appsec.yml) configuration file")
	dastCmd.Flags().StringP("output", "o", "", "Output file path (default is stdout)")
	dastCmd.Flags().String("templates", "", "Comma-separated nuclei templates (files, dirs, or ids); default is nuclei's installed set")
	dastCmd.Flags().String("tags", "", "Comma-separated nuclei tag filter (e.g. misconfig,exposure,cve)")
	dastCmd.Flags().String("severity", "", "Comma-separated nuclei severity filter (info,low,medium,high,critical)")
	dastCmd.Flags().Int("rate-limit", 0, "Max requests per second (0 = nuclei default)")
	dastCmd.Flags().Int("timeout", 0, "Whole-scan timeout in seconds (0 = no limit)")
	dastCmd.Flags().Bool("dast", false, "Enable active fuzzing (nuclei -dast templates): probes parameters for injection")
	dastCmd.Flags().Bool("evidence", true, "Capture the request/response for each finding (redacted; on by default. Pass --evidence=false to record metadata only)")
	dastCmd.Flags().Bool("crawl", false, "Crawl the target (authenticated) to discover endpoints and forms, then fuzz all of them")
	dastCmd.Flags().Bool("dalfox", false, "Also run dalfox: active XSS testing of GET and POST forms (reflected, stored, DOM)")
	dastCmd.Flags().Bool("sqlmap", false, "Also run sqlmap: SQL injection testing incl. boolean/time-based blind, GET and POST")
	dastCmd.Flags().Bool("cmdi", false, "Also test for OS command injection (GET and POST) with benign arithmetic/timing probes")
	dastCmd.Flags().Bool("ssrf", false, "Also test for server-side request forgery: inject callback URLs to a local out-of-band listener (never a third-party service) and probe cloud-metadata reachability")
	dastCmd.Flags().Bool("ssti", false, "Also test for server-side template injection (GET and POST) with benign arithmetic-marker probes per template engine")
	dastCmd.Flags().Bool("file-upload", false, "Also test discovered upload forms for unrestricted file upload: upload a benign marker file of a disallowed type and fetch it back (needs --crawl)")
	dastCmd.Flags().Bool("js-recon", false, "Reverse-engineer the target's client-side JavaScript: recover endpoints/API routes (fed to the fuzzers) and report secrets exposed in served bundles")
	dastCmd.Flags().Bool("fingerprint", false, "Identify the target's technology stack (server/framework/CMS/library versions) and correlate CMS families against the CISA KEV catalog")
	dastCmd.Flags().Bool("api-recon", false, "Reconstruct the API surface from served schemas (OpenAPI/Swagger, GraphQL introspection), fuzz the recovered operations, and report the exposure")
	dastCmd.Flags().Bool("graphql", false, "Also test discovered GraphQL endpoints for query batching and alias amplification (benign probes)")
	dastCmd.Flags().Int("crawl-depth", 0, "Crawl link-follow depth (0 = default 3)")
	dastCmd.Flags().Int("crawl-pages", 0, "Max pages to crawl (0 = default 150)")
	dastCmd.Flags().Bool("auth-auto", false, "Authenticate before scanning: detect the login form and try built-in default credentials")
	dastCmd.Flags().String("auth-user-env", "", "Name of an env var holding the login username (value never stored)")
	dastCmd.Flags().String("auth-pass-env", "", "Name of an env var holding the login password (value never stored)")
	dastCmd.Flags().String("login-url", "", "Login page URL (default: the scan target)")
	dastCmd.Flags().Bool("idor", false, "Also test for IDOR/BOLA: replay the first identity's object ids as a second identity (needs --crawl and a second identity via --auth2-user-env/--auth2-pass-env)")
	dastCmd.Flags().String("auth2-user-env", "", "Name of an env var holding the SECOND identity's username, for IDOR testing (value never stored)")
	dastCmd.Flags().String("auth2-pass-env", "", "Name of an env var holding the SECOND identity's password, for IDOR testing (value never stored)")
	dastCmd.Flags().String("auth2-login-url", "", "Login page URL for the second identity (default: --login-url or the scan target)")
	dastCmd.Flags().Bool("triage", false, "Enable AI triage of findings (config: triage.enabled)")
	dastCmd.Flags().Bool("exclude-fp", false, "Exclude LLM-marked false positives from the report and severity gate (opt-in)")
	dastCmd.Flags().String("engagement", "", "Engagement id to run under (default: the active engagement). Active DAST requires one.")
	dastCmd.Flags().Bool("i-have-authorization", false, "Per-run confirmation of the destructive interlock's second latch (still needs the engagement's destructive flag; hard limits always refuse)")
	dastCmd.Flags().Bool("confirm-impact", false, "Run bounded impact confirmation on confirmed findings (DB banner for SQLi, benign `id` for command injection). Second latch of the confirmation interlock; needs the engagement's --allow-confirmation flag; never dumps data or changes state")
	dastCmd.Flags().Bool("save", false, "Save the run under .appsec/dast/<target>/runs for the console")
	dastCmd.Flags().Bool("strict-gate", false, "Gate on ALL findings, ignoring accepted-risk/false-positive dispositions (default: dispositioned findings don't fail the gate)")
	rootCmd.AddCommand(dastCmd)
}

var dastCmd = &cobra.Command{
	Use:   "dast <url>",
	Short: "Run a dynamic application security test (nuclei) against a running target",
	Long: `Scans a running web target with nuclei and maps the results into the unified
findings model (category DAST): banded severity, risk signals, and compliance
mapping, in the same pipeline as code and cloud findings.

The target is a URL you are authorized to test. nuclei runs with its OOB
callout server and update check disabled, so a scan performs no network
callouts beyond requests to the target itself. Findings carry the weakness
identity and the matched URL, never the target's response bodies.

Use --dast to enable active fuzzing (probe parameters for injection), and
--auth-auto (or --auth-user-env/--auth-pass-env) to log in first so the scan
reaches pages behind authentication. Credentials are referenced by env-var
name, never passed as literal flags, and the session is never stored or logged.

  argus dast https://staging.example.com
  argus dast https://staging.example.com --tags misconfig,exposure --severity medium,high,critical
  argus dast "https://staging.example.com/item?id=1" --dast --fail-severity high
  argus dast https://staging.example.com --auth-auto --dast`,
	Args: cobra.ExactArgs(1),
	RunE: runDAST,
}

func runDAST(cmd *cobra.Command, args []string) error {
	target := args[0]
	if err := dastscan.ValidateURL(target); err != nil {
		return err
	}

	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	gate, err := model.ParseGate(cfg.FailSeverity)
	if err != nil {
		return fmt.Errorf("invalid fail-severity: %w", err)
	}

	timeoutSec, _ := cmd.Flags().GetInt("timeout")
	rateLimit, _ := cmd.Flags().GetInt("rate-limit")
	fuzzing, _ := cmd.Flags().GetBool("dast")
	crawl, _ := cmd.Flags().GetBool("crawl")
	crawlDepth, _ := cmd.Flags().GetInt("crawl-depth")
	crawlPages, _ := cmd.Flags().GetInt("crawl-pages")
	evidence, _ := cmd.Flags().GetBool("evidence")
	dalfox, _ := cmd.Flags().GetBool("dalfox")
	sqlmap, _ := cmd.Flags().GetBool("sqlmap")
	cmdi, _ := cmd.Flags().GetBool("cmdi")
	ssrf, _ := cmd.Flags().GetBool("ssrf")
	ssti, _ := cmd.Flags().GetBool("ssti")
	fileUpload, _ := cmd.Flags().GetBool("file-upload")
	recon, _ := cmd.Flags().GetBool("js-recon")
	fingerprint, _ := cmd.Flags().GetBool("fingerprint")
	apiRecon, _ := cmd.Flags().GetBool("api-recon")
	graphql, _ := cmd.Flags().GetBool("graphql")
	idor, _ := cmd.Flags().GetBool("idor")
	auth, err := dastAuthFromFlags(cmd)
	if err != nil {
		return err
	}
	auth2, err := dastAuth2FromFlags(cmd)
	if err != nil {
		return err
	}
	gov, err := dastGovernor(cmd)
	if err != nil {
		return err
	}
	res, err := pipeline.RunDAST(cmd.Context(), pipeline.DASTOptions{
		URL:         target,
		Governor:    gov,
		Templates:   splitCSV(cmd, "templates"),
		Tags:        splitCSV(cmd, "tags"),
		Severities:  splitCSV(cmd, "severity"),
		RateLimit:   rateLimit,
		TimeoutSec:  timeoutSec,
		Fuzzing:     fuzzing,
		Crawl:       crawl,
		CrawlDepth:  crawlDepth,
		CrawlPages:  crawlPages,
		Evidence:    evidence,
		Dalfox:      dalfox,
		Sqlmap:      sqlmap,
		Cmdi:        cmdi,
		SSRF:        ssrf,
		SSTI:        ssti,
		FileUpload:  fileUpload,
		Recon:       recon,
		Fingerprint: fingerprint,
		APIRecon:    apiRecon,
		GraphQL:     graphql,
		IDOR:        idor,
		Auth:        auth,
		Auth2:       auth2,
		Config:      cfg,
	}, func(line string) { fmt.Fprint(os.Stderr, line) })
	if err != nil {
		return err
	}
	findings := res.Findings

	if err := writeReport(cmd, cfg.Format, findings); err != nil {
		return err
	}

	if save, _ := cmd.Flags().GetBool("save"); save {
		if meta, err := saveDASTRun(target, findings, res.ToolVersion); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: --save failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "==> saved run %s to %s\n", meta.ID, meta.Path)
		}
	}

	printSummary(findings)

	// Disposition suppression, same as code and cloud scans: a risk accepted
	// in the console (stored beside this target's DAST runs) stops failing CI
	// but stays in the report. --strict-gate gates on everything.
	gated := findings
	if strict, _ := cmd.Flags().GetBool("strict-gate"); !strict {
		base, err := os.Getwd()
		if err != nil {
			return err
		}
		dispDir := filepath.Join(base, ".appsec", "dast", dastTargetDir(target))
		var suppressed int
		gated, suppressed = excludeDispositionedAt(dispDir, findings)
		if suppressed > 0 {
			fmt.Fprintf(os.Stderr, "NOTE: %d finding(s) excluded from the gate by disposition (accepted-risk/false-positive); --strict-gate to include them\n", suppressed)
		}
	}

	if model.GateExceeded(gated, gate) {
		return errGateFailed
	}
	return nil
}

// dastGovernor resolves the engagement this scan runs under (--engagement, else
// the active engagement) and builds the enforcement plane: the scope gate,
// intensity governor, and tamper-evident audit trail every active module routes
// through. No engagement is a hard, explanatory error - active DAST never sends
// a packet without authorization.
func dastGovernor(cmd *cobra.Command) (*engagement.Governor, error) {
	store, err := engagementStore()
	if err != nil {
		return nil, err
	}
	var eng *engagement.Engagement
	if id, _ := cmd.Flags().GetString("engagement"); id != "" {
		eng, err = store.Load(id)
		if err != nil {
			return nil, fmt.Errorf("engagement %q: %w", id, err)
		}
	} else {
		eng, err = store.Active()
		if err != nil {
			return nil, err
		}
		if eng == nil {
			return nil, fmt.Errorf("no active engagement: active DAST modules require an authorized engagement.\n" +
				"Create one with `argus engagement create --name ... --scope ... --auth-ref ...`, or pass --engagement <id>.")
		}
	}
	audit, err := engagement.OpenAudit(store.AuditPath(eng.ID))
	if err != nil {
		return nil, err
	}
	destructive, _ := cmd.Flags().GetBool("i-have-authorization")
	confirmImpact, _ := cmd.Flags().GetBool("confirm-impact")
	return engagement.NewGovernor(eng, audit, destructive, confirmImpact), nil
}

// dastAuthFromFlags builds the pre-scan auth config, or nil when no auth flag
// is set. Credentials are read from the NAMED env vars only: a username or
// password never appears as a literal flag (it would land in shell history and
// the process table), and the resolved value is used in memory and never
// stored. Naming an env var that is unset is a clear error, not a silent
// fall-through to an unauthenticated scan.
func dastAuthFromFlags(cmd *cobra.Command) (*pipeline.DASTAuth, error) {
	auto, _ := cmd.Flags().GetBool("auth-auto")
	userEnv, _ := cmd.Flags().GetString("auth-user-env")
	passEnv, _ := cmd.Flags().GetString("auth-pass-env")
	loginURL, _ := cmd.Flags().GetString("login-url")
	if !auto && userEnv == "" && passEnv == "" && loginURL == "" {
		return nil, nil
	}

	a := &pipeline.DASTAuth{LoginURL: loginURL, TryDefaults: auto}
	if userEnv != "" {
		v, ok := os.LookupEnv(userEnv)
		if !ok {
			return nil, fmt.Errorf("--auth-user-env: environment variable %q is not set", userEnv)
		}
		a.Username = v
	}
	if passEnv != "" {
		v, ok := os.LookupEnv(passEnv)
		if !ok {
			return nil, fmt.Errorf("--auth-pass-env: environment variable %q is not set", passEnv)
		}
		a.Password = v
	}
	if a.Username == "" && a.Password == "" && !auto {
		return nil, fmt.Errorf("authentication requested but no credentials: set --auth-auto or --auth-user-env/--auth-pass-env")
	}
	return a, nil
}

// dastAuth2FromFlags builds the second identity for IDOR testing, or nil when
// none is configured. It has no default-credential path: the second identity
// must be a distinct real user, referenced by env-var name only.
func dastAuth2FromFlags(cmd *cobra.Command) (*pipeline.DASTAuth, error) {
	userEnv, _ := cmd.Flags().GetString("auth2-user-env")
	passEnv, _ := cmd.Flags().GetString("auth2-pass-env")
	loginURL, _ := cmd.Flags().GetString("auth2-login-url")
	if loginURL == "" {
		loginURL, _ = cmd.Flags().GetString("login-url")
	}
	if userEnv == "" && passEnv == "" {
		return nil, nil
	}
	a := &pipeline.DASTAuth{LoginURL: loginURL}
	if userEnv != "" {
		v, ok := os.LookupEnv(userEnv)
		if !ok {
			return nil, fmt.Errorf("--auth2-user-env: environment variable %q is not set", userEnv)
		}
		a.Username = v
	}
	if passEnv != "" {
		v, ok := os.LookupEnv(passEnv)
		if !ok {
			return nil, fmt.Errorf("--auth2-pass-env: environment variable %q is not set", passEnv)
		}
		a.Password = v
	}
	return a, nil
}

// splitCSV reads a comma-separated flag into a trimmed, non-empty slice.
func splitCSV(cmd *cobra.Command, name string) []string {
	v, _ := cmd.Flags().GetString(name)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// saveDASTRun stores a DAST run under a per-target directory, mirroring cloud
// runs: there is no filesystem target to own the history, so runs live at
// .appsec/dast/<target>/runs off the current directory.
func saveDASTRun(target string, findings []model.Finding, toolVersion string) (runstore.RunMeta, error) {
	base, err := os.Getwd()
	if err != nil {
		return runstore.RunMeta{}, err
	}
	store := runstore.Store{Dir: filepath.Join(base, ".appsec", "dast", dastTargetDir(target), "runs")}
	var tools map[string]string
	if toolVersion != "" {
		tools = map[string]string{"nuclei": toolVersion}
	}
	return store.SaveWithTools(findings, tools, time.Now())
}

// dastTargetDir is a filesystem-safe per-target directory name derived from
// the URL: every character outside [A-Za-z0-9-_] becomes '_', so no scheme
// slash, port colon, or path separator can escape the runs directory.
func dastTargetDir(target string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, target)
	safe = strings.Trim(safe, "_")
	if safe == "" {
		return "target"
	}
	if len(safe) > 100 {
		safe = safe[:100]
	}
	return safe
}
