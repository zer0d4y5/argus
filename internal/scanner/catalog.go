package scanner

// The rule-pack catalog: a curated, categorized menu of semgrep registry packs
// an admin can enable from the console. Enabling a pack adds it to the custom
// rulesets (see customrules.go); the console reads this list and reports which
// entries are already active.
//
// Unlike the default profile packs, catalog packs do NOT have to clear the
// earn-your-slot recall bar (TestProfileRecall). That bar governs the proven
// baseline every scan runs; the catalog is an explicit, user-chosen menu of
// EXTRA coverage for a specific stack. Every pack here is verified to resolve
// against the registry (TestRulePackCatalogResolves), so the menu never offers
// a typo that would break a scan.

// RulePack is one catalog entry.
type RulePack struct {
	ID          string `json:"id"`          // semgrep registry ref, e.g. "p/django"
	Label       string `json:"label"`       // human name for the menu
	Category    string `json:"category"`    // "language" | "framework" | "cloud" | "class"
	Description string `json:"description"` // one line on what it adds
}

// RulePackCategories is the display order of the catalog's category groups.
var RulePackCategories = []string{"language", "framework", "cloud", "class"}

// RulePackCatalog is the curated menu. Additions are a reviewed change: a new
// pack must resolve against the registry (the test enforces it) and belong to
// one of the categories above.
var RulePackCatalog = []RulePack{
	// Language packs: the per-language security audits. Several are already in
	// the standard/max profiles; enabling one here is explicit and harmless
	// (resolution de-duplicates). InDefaultProfile marks those for the UI.
	{"p/python", "Python", "language", "Security audit rules for Python."},
	{"p/javascript", "JavaScript", "language", "Security audit rules for JavaScript."},
	{"p/typescript", "TypeScript", "language", "Security audit rules for TypeScript."},
	{"p/golang", "Go", "language", "Security audit rules for Go."},
	{"p/java", "Java", "language", "Security audit rules for Java."},
	{"p/csharp", "C#", "language", "Security audit rules for C#."},
	{"p/ruby", "Ruby", "language", "Security audit rules for Ruby."},
	{"p/php", "PHP", "language", "Security audit rules for PHP."},
	{"p/kotlin", "Kotlin", "language", "Security audit rules for Kotlin."},
	{"p/rust", "Rust", "language", "Security audit rules for Rust."},
	{"p/scala", "Scala", "language", "Security audit rules for Scala."},

	// Framework and library packs: architecture-specific detections that the
	// language packs do not carry.
	{"p/react", "React", "framework", "React-specific issues: dangerouslySetInnerHTML, unsafe refs, and more."},
	{"p/django", "Django", "framework", "Django-specific issues: raw SQL, unsafe redirects, template autoescape off."},
	{"p/flask", "Flask", "framework", "Flask-specific issues: debug mode, unsafe send_file, missing CSRF."},
	{"p/nodejsscan", "Node.js", "framework", "Node.js server issues from the nodejsscan ruleset."},
	{"p/eslint-plugin-security", "ESLint security", "framework", "The eslint-plugin-security rules ported to semgrep."},

	// Cloud and IaC packs: infrastructure definitions and CI.
	{"p/terraform", "Terraform", "cloud", "Terraform misconfigurations across AWS, Azure, and GCP resources."},
	{"p/kubernetes", "Kubernetes", "cloud", "Kubernetes manifest hardening: privileged pods, host mounts, capabilities."},
	{"p/dockerfile", "Dockerfile", "cloud", "Dockerfile issues: root user, mutable tags, secrets in layers."},
	{"p/docker-compose", "Docker Compose", "cloud", "docker-compose issues: privileged services, host networking."},
	{"p/github-actions", "GitHub Actions", "cloud", "Workflow issues: script injection, unpinned actions, broad permissions."},

	// Weakness-class packs: cross-language, focused on one vulnerability family.
	{"p/sql-injection", "SQL injection", "class", "SQL injection patterns across languages."},
	{"p/xss", "Cross-site scripting", "class", "XSS sinks across languages and templates."},
	{"p/command-injection", "Command injection", "class", "OS command injection patterns across languages."},
	{"p/jwt", "JWT", "class", "JSON Web Token pitfalls: alg confusion, hardcoded secrets, missing verify."},
	{"p/insecure-transport", "Insecure transport", "class", "Cleartext HTTP, disabled TLS verification, weak protocols."},
	{"p/secrets", "Secrets", "class", "Hardcoded credential patterns (complements the gitleaks pass)."},
	{"p/owasp-top-ten", "OWASP Top Ten", "class", "Broad coverage mapped to the OWASP Top Ten."},
	{"p/trailofbits", "Trail of Bits", "class", "Trail of Bits' high-signal rules for Go, Python, and more."},
}

// defaultProfilePacks is the set of packs already present in the standard or
// max profile, so the console can tell an admin a catalog pack is "already in
// your profile" rather than implying they need to enable it.
var defaultProfilePacks = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range append(append([]string{}, standardPacks...), maxOnlyPacks...) {
		m[p] = true
	}
	return m
}()

// InDefaultProfile reports whether a pack is already run by the standard or max
// profile.
func InDefaultProfile(pack string) bool { return defaultProfilePacks[pack] }
