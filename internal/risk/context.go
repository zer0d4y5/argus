// Stage 2 of docs/risk-scoring.md: the deterministic, per-category context
// modifier. Every signal here is a named, table-driven, reviewed rule —
// LLM-free, bounded, unknown = neutral. Security-critical and Claude-owned:
// the scorer reads entropy/RuleID/path/Meta and NEVER the secret value (the
// gitleaks adapter scrubbed it; it is gone by design and must stay gone) and
// never re-reads scanned files.
package risk

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
)

// Bounds. The summed context delta is clamped to ±contextCap so no heuristic
// stack can dominate severity; unverifiedCeiling reserves the top of the
// critical band ([9.5, 10]) for credentials explicitly verified live.
const (
	contextCap        = 3.0
	unverifiedCeiling = 9.4
)

// ruleDS0031 is trivy-config's "secret in Dockerfile ENV/ARG" pattern rule.
// It is IAC by category but secret-shaped for scoring: a name-pattern match
// with no detected credential value behind it.
const ruleDS0031 = "DS-0031"

// verified states carried in Meta["verified"] (docs/risk-scoring.md, "the
// verified hook"). Nothing in this codebase writes "live" — only a future
// opt-in verifier or a human does. Unknown values count as unchecked.
const (
	verifiedLive      = "live"
	verifiedInvalid   = "invalid"
	verifiedUnchecked = "unchecked"
)

// testPathTokens is the placeholder / not-prod signal: a path token matching
// any of these marks the finding as test-context. Exact token match after
// splitting on every non-alphanumeric boundary, so "contest.go" never
// matches "test".
var testPathTokens = map[string]bool{
	"test": true, "tests": true, "testing": true, "testdata": true,
	"spec": true, "specs": true, "fixture": true, "fixtures": true,
	"example": true, "examples": true, "sample": true, "samples": true,
	"mock": true, "mocks": true, "dummy": true, "demo": true,
}

// prodPathTokens drives the prod-path *heuristic* — the signal note must say
// so; a path segment is never "verified production".
var prodPathTokens = map[string]bool{"prod": true, "production": true}

// highValueSecretRules: gitleaks rule identities whose match unlocks cloud
// accounts, hosts, databases, or code — the sensitivity tier above generic-*.
var highValueSecretRules = map[string]bool{
	"private-key":            true,
	"jdbc-connection-string": true,
	"stripe-access-token":    true,
	"github-pat":             true,
	"github-oauth":           true,
	"github-app-token":       true,
	"github-refresh-token":   true,
	"gitlab-pat":             true,
}

// highValueSecretRulePrefixes: named-provider rule families (cloud creds).
var highValueSecretRulePrefixes = []string{"aws-", "gcp-", "azure-", "google-"}

// credentialEnvNames: env-var names in a DS-0031 message that identify a
// known cloud/DB credential rather than a generic *_TOKEN pattern match.
var credentialEnvNames = map[string]bool{
	"AWS_SECRET_ACCESS_KEY":          true,
	"AWS_SESSION_TOKEN":              true,
	"AZURE_CLIENT_SECRET":            true,
	"GOOGLE_APPLICATION_CREDENTIALS": true,
	"GCP_SERVICE_ACCOUNT_KEY":        true,
	"GITHUB_TOKEN":                   true,
	"GITLAB_TOKEN":                   true,
	"DATABASE_URL":                   true,
	"DB_PASSWORD":                    true,
	"POSTGRES_PASSWORD":              true,
	"MYSQL_PASSWORD":                 true,
	"MYSQL_ROOT_PASSWORD":            true,
	"MONGODB_URI":                    true,
	"REDIS_PASSWORD":                 true,
	"STRIPE_SECRET_KEY":              true,
	"NPM_TOKEN":                      true,
	"DOCKER_PASSWORD":                true,
}

// publicExposureRules: trivy-config rule IDs (AVD- prefix stripped) that make
// a resource internet-facing — S3 public-access family, world-open ingress,
// default-public IPs. Internal hygiene of equal severity stays on baseline.
var publicExposureRules = map[string]bool{
	"AWS-0086": true, "AWS-0087": true, "AWS-0088": true, "AWS-0091": true,
	"AWS-0092": true, "AWS-0093": true, "AWS-0094": true, "AWS-0107": true,
	"AWS-0164": true,
}

// quotedEnvName pulls the env-var name out of a DS-0031 message, e.g.
// `Possible exposure of secret env "AWS_SECRET_ACCESS_KEY" in ENV`.
var quotedEnvName = regexp.MustCompile(`"([A-Za-z0-9_]+)"`)

// cloudAdminPolicyChecks: prowler check IDs for wildcard/admin policy
// grants and privilege-escalation paths — account-wide blast radius (the
// cloud.iam_wildcard signal). Verified against the prowler 5.31 registry;
// the canonical list lives in docs/risk-scoring.md (CLOUD table).
var cloudAdminPolicyChecks = map[string]bool{
	"iam_aws_attached_policy_no_administrative_privileges":        true,
	"iam_customer_attached_policy_no_administrative_privileges":   true,
	"iam_customer_unattached_policy_no_administrative_privileges": true,
	"iam_inline_policy_no_administrative_privileges":              true,
	"iam_inline_policy_allows_privilege_escalation":               true,
	"iam_policy_allows_privilege_escalation":                      true,
	"iam_group_administrator_access_policy":                       true,
	"iam_role_administratoraccess_policy":                         true,
	"iam_user_administrator_access_policy":                        true,
}

// runContext is the cross-finding evidence Apply precomputes for one run:
// which files carry a DS-0031 exposure pattern and which carry a detected
// secret. Co-location of the two on one file is the genuine "secret baked
// into a shipped image" case.
type runContext struct {
	ds0031Files map[string]bool
	secretFiles map[string]bool
}

func buildRunContext(findings []model.Finding) runContext {
	rc := runContext{ds0031Files: map[string]bool{}, secretFiles: map[string]bool{}}
	for _, f := range findings {
		if f.Location.File == "" {
			continue
		}
		if f.RuleID == ruleDS0031 {
			rc.ds0031Files[f.Location.File] = true
		}
		if f.Category == model.CategorySecret {
			rc.secretFiles[f.Location.File] = true
		}
	}
	return rc
}

// contextSignals routes a finding to its category's signal rules and returns
// the named rows that fired. Deltas and notes are fixed table values — never
// model output, never scanned-file content.
func contextSignals(f model.Finding, rc runContext) []model.RiskSignal {
	switch {
	case secretShaped(f):
		return secretSignals(f, rc)
	case f.Category == model.CategoryIaC:
		return iacSignals(f)
	case f.Category == model.CategorySAST:
		return sastSignals(f)
	case f.Category == model.CategoryCloud:
		return cloudSignals(f)
	}
	return nil
}

// secretShaped: findings that carry leaked-credential risk — detected secrets
// (SECRET category) and the DS-0031 exposure pattern. Both share the
// verified hook and the unverified ceiling.
func secretShaped(f model.Finding) bool {
	return f.Category == model.CategorySecret || f.RuleID == ruleDS0031
}

func secretSignals(f model.Finding, rc runContext) []model.RiskSignal {
	// Precedence 2: a confirmed-dead credential answers exactly the question
	// every heuristic below approximates — nothing else fires.
	if verifiedState(f) == verifiedInvalid {
		return []model.RiskSignal{{
			Code: "secret.verified_invalid", Delta: -3.0,
			Note: "credential verified invalid — deprioritized, kept visible for rotation hygiene",
		}}
	}

	var sig []model.RiskSignal
	isDS := f.RuleID == ruleDS0031
	live := verifiedState(f) == verifiedLive
	testPath := hasPathToken(f.Location.File, testPathTokens)

	if isDS {
		// Precedence 1: verified live answers the "is there a real secret
		// behind this pattern" question the pulldown hedges.
		if !live {
			sig = append(sig, model.RiskSignal{
				Code: "iac.secret_pattern_unverified", Delta: -1.5,
				Note: "secret env-name pattern only — no detected credential value; validity unverified",
			})
		}
		if credentialEnvNames[envVarName(f)] {
			sig = append(sig, model.RiskSignal{
				Code: "iac.secret_env_cloud_name", Delta: 0.5,
				Note: "env name matches a known cloud/DB credential",
			})
		}
		if rc.secretFiles[f.Location.File] {
			sig = append(sig, model.RiskSignal{
				Code: "iac.colocated_secret", Delta: 0.75,
				Note: "a detected secret (SECRET finding) exists on the same file",
			})
		}
	} else {
		if e, ok := entropyOf(f); ok && e < 3.0 {
			sig = append(sig, model.RiskSignal{
				Code: "secret.low_entropy", Delta: -1.0,
				Note: "low-entropy match — structured placeholder, likely not a real credential",
			})
		}
		// Precedence 3: a test-like path suppresses the positive heuristics —
		// a fixtures directory named prod is still fixtures.
		if !testPath && highValueRule(f.RuleID) {
			sig = append(sig, model.RiskSignal{
				Code: "secret.high_value_rule", Delta: 0.75,
				Note: "named high-value provider rule (cloud credential, key material, or DB DSN)",
			})
		}
		if !testPath && hasPathToken(f.Location.File, prodPathTokens) {
			sig = append(sig, model.RiskSignal{
				Code: "secret.prod_path", Delta: 0.5,
				Note: "prod-path heuristic — path names a production-like segment; not verified production",
			})
		}
		if f.Location.File != "" && rc.ds0031Files[f.Location.File] {
			sig = append(sig, model.RiskSignal{
				Code: "secret.colocated_exposure", Delta: 0.75,
				Note: "DS-0031 secret-exposure pattern on the same file",
			})
		}
	}

	if testPath {
		sig = append(sig, model.RiskSignal{
			Code: "secret.test_path", Delta: -2.0,
			Note: "test/fixture-like path — placeholder, not a production leak",
		})
	}
	if live {
		sig = append(sig, model.RiskSignal{
			Code: "secret.verified_live", Delta: 1.5,
			Note: "credential verified live by an explicit opt-in verifier input",
		})
	}
	return sig
}

func iacSignals(f model.Finding) []model.RiskSignal {
	if publicExposureRules[stripAVD(f.RuleID)] || publicExposureRules[stripAVD(f.Meta["avdid"])] {
		return []model.RiskSignal{{
			Code: "iac.public_exposure", Delta: 0.75,
			Note: "rule indicates internet-facing exposure",
		}}
	}
	return nil
}

func sastSignals(f model.Finding) []model.RiskSignal {
	if hasPathToken(f.Location.File, testPathTokens) {
		return []model.RiskSignal{{
			Code: "sast.test_path", Delta: -1.0,
			Note: "finding is in test code — not a reachable production sink",
		}}
	}
	return nil
}

// cloudSignals is the CLOUD stage-2 table (docs/risk-scoring.md, "CLOUD").
// Inputs are the prowler check identity (RuleID) and the check's own
// category tags as written by the cloudscan adapter (Meta["categories"]) —
// never resource contents, never topology, never model output. All deltas
// positive and modest: prowler's grade carries the base signal; these order
// exposure within a grade. Unknown = neutral.
func cloudSignals(f model.Finding) []model.RiskSignal {
	cats := cloudCategorySet(f.Meta["categories"])
	var sig []model.RiskSignal
	if cats["internet-exposed"] {
		sig = append(sig, model.RiskSignal{
			Code: "cloud.public_exposure", Delta: 0.75,
			Note: "prowler categorizes this check internet-exposed — internet-facing misconfiguration",
		})
	}
	if cloudAdminPolicyChecks[f.RuleID] || cats["privilege-escalation"] {
		sig = append(sig, model.RiskSignal{
			Code: "cloud.iam_wildcard", Delta: 0.75,
			Note: "admin-grade policy or privilege-escalation path — account-wide blast radius",
		})
	}
	if cats["encryption"] {
		sig = append(sig, model.RiskSignal{
			Code: "cloud.unencrypted_at_rest", Delta: 0.25,
			Note: "data-at-rest encryption gap",
		})
	}
	if cats["logging"] {
		sig = append(sig, model.RiskSignal{
			Code: "cloud.logging_disabled", Delta: 0.25,
			Note: "audit/access logging gap — degrades detection and forensics",
		})
	}
	return sig
}

// cloudCategorySet splits the adapter's comma-joined prowler check
// categories into a set. Empty input yields an empty set (no signal).
func cloudCategorySet(csv string) map[string]bool {
	set := map[string]bool{}
	for _, c := range strings.Split(csv, ",") {
		if c = strings.TrimSpace(c); c != "" {
			set[c] = true
		}
	}
	return set
}

func verifiedState(f model.Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.Meta["verified"])) {
	case verifiedLive:
		return verifiedLive
	case verifiedInvalid:
		return verifiedInvalid
	default:
		return verifiedUnchecked
	}
}

func entropyOf(f model.Finding) (float64, bool) {
	e, err := strconv.ParseFloat(strings.TrimSpace(f.Meta["entropy"]), 64)
	return e, err == nil
}

func envVarName(f model.Finding) string {
	m := quotedEnvName.FindStringSubmatch(f.Meta["message"])
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func highValueRule(ruleID string) bool {
	id := strings.ToLower(strings.TrimSpace(ruleID))
	if highValueSecretRules[id] {
		return true
	}
	for _, p := range highValueSecretRulePrefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

func stripAVD(id string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(id)), "AVD-")
}

// hasPathToken lowercases the path, splits it into tokens on every
// non-alphanumeric boundary, and checks for an exact token match.
func hasPathToken(path string, tokens map[string]bool) bool {
	if path == "" {
		return false
	}
	for _, tok := range strings.FieldsFunc(strings.ToLower(path), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if tokens[tok] {
			return true
		}
	}
	return false
}
