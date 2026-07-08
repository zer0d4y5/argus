package triage

import (
	"regexp"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// The remediation safety linter. AI-generated remediation is ADVICE the user
// runs with their own hands and credentials — the platform never executes it.
// This deterministic gate is the backstop that keeps a hallucinated or
// hostile-influenced remediation from shipping a command that destroys
// infrastructure or embeds a credential. It runs at generation time (the
// endpoint applies it before returning) AND is unit-tested over hand-authored
// good/bad outputs, with no LLM in the loop.
//
// Failure mode is SAFE-BY-DEGRADATION: a remediation whose artifacts trip a
// rule keeps its human steps but has its runnable artifacts WITHHELD and its
// kind forced to "manual", with a warning explaining why. Better a
// follow-the-steps-yourself answer than a copy-paste-me landmine.

// Caps: bounded so a run-away model can't emit a giant or sprawling artifact.
const (
	maxRemediationArtifacts    = 6
	maxRemediationArtifactRune = 6000
	maxRemediationSteps        = 12
	maxRemediationWarnings     = 8
)

// destructivePatterns are command fragments a remediation must never contain.
// Remediation reconfigures a resource toward compliance; it never deletes,
// terminates, or wipes. Matched case-insensitively against artifact content.
// This list is conservative on purpose: a false positive costs a manual step;
// a false negative costs the user their infrastructure.
var destructivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-\S*[rf]`),                    // rm -rf / rm -f / rm -Rf
	regexp.MustCompile(`(?i)\brm\s+--(recursive|force)`),         // rm --recursive --force
	regexp.MustCompile(`(?i)\bmkfs\b`),                           // format a filesystem
	regexp.MustCompile(`(?i)\bdd\b[^\n]*\b(if|of)=/dev/`),        // raw disk read/write, either arg order
	regexp.MustCompile(`(?i)>\s*/dev/sd`),                        // clobber a device
	regexp.MustCompile(`(?i)\b(shutdown|reboot|halt)\b`),         // take the host down
	regexp.MustCompile(`(?i):\(\)\s*\{.*\}\s*;`),                 // classic fork bomb
	regexp.MustCompile(`(?i)\bdrop\s+(table|database|schema)\b`), // destroy data
	regexp.MustCompile(`(?i)\btruncate\s+table\b`),
	// Piping a download straight into an interpreter — curl … | sh, wget … |
	// bash, base64 -d … | sh. Remediation reconfigures; it never fetch-executes.
	regexp.MustCompile(`(?i)\|\s*(sudo\s+)?(ba|z|da|k|c|tc)?sh\b`),
	// Cloud destructive verbs (AWS CLI / az / gcloud): delete/terminate a
	// resource is out of scope for remediation — reconfigure instead.
	regexp.MustCompile(`(?i)\b(aws\s+\w+\s+delete-|delete-bucket|delete-security-group|terminate-instances|delete-db-instance|delete-stack)\b`),
	regexp.MustCompile(`(?i)\baz\s+\w+\s+delete\b`),
	regexp.MustCompile(`(?i)\bgcloud\s+\w+\s+delete\b`),
	regexp.MustCompile(`(?i)\bkubectl\s+delete\b`),
	// Blanket "allow all" permission anti-fixes: chmod 777 / 0777 / a+rwx, with
	// or without flags, in either the octal or symbolic form.
	regexp.MustCompile(`(?i)\bchmod\s+(-\S+\s+)*0?777\b`),
	regexp.MustCompile(`(?i)\bchmod\s+(-\S+\s+)*[augo]*[+=]rwx\b`),
}

// lintNormalizations undo common shell obfuscations before matching so that
// rm${IFS}-rf, r”m -rf, and backslash-newline line continuations can't slip a
// destructive command past the patterns above. Matching runs against both the
// raw artifact and its normalized form.
var (
	ifsExpansion  = regexp.MustCompile(`\$\{IFS\}|\$IFS`)
	emptyQuotes   = regexp.MustCompile(`''|""`)
	lineContinued = regexp.MustCompile(`\\\r?\n`)
)

func normalizeForLint(s string) string {
	s = ifsExpansion.ReplaceAllString(s, " ")
	s = lineContinued.ReplaceAllString(s, "")
	s = emptyQuotes.ReplaceAllString(s, "")
	return s
}

// credentialPatterns catch a literal secret embedded in an artifact — a
// generated script must reference profiles/secret-manager paths, never a
// value. AWS key id, private-key PEM blocks, and inline aws_secret_access_key
// / password assignments to a non-placeholder value.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*[^\s<$]{16,}`),
	// No leading \b: it would miss db_password / FOO_SECRET because "_" is a word
	// char. The value charset admits password punctuation (a "@" broke the old
	// [A-Za-z0-9/+_-] run) but excludes code-structural chars .()[] so a read
	// like os.environ["X"] or getenv("X") is not mistaken for a literal.
	// Placeholders are filtered separately by placeholderRe.
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)["']?\s*[:=]\s*["']?[^\s"'<>${}()\[\].]{8,}`),
}

// placeholderRe recognizes a clearly-marked placeholder the model was told to
// leave when a value is unknown — a credential-pattern hit that is really a
// placeholder is fine.
var placeholderRe = regexp.MustCompile(`(?i)<[A-Z0-9_ -]{2,}>|YOUR[_-]|REPLACE|EXAMPLE|\$\{?[A-Z_]+\}?`)

// lintRemediation validates and, where necessary, defangs a remediation. It
// returns the (possibly degraded) remediation and the list of safety issues
// found. Deterministic; the security boundary is here, not in the model.
func lintRemediation(f model.Finding, r Remediation) (Remediation, []string) {
	var issues []string

	// Bound the collections first (a runaway model).
	if len(r.Steps) > maxRemediationSteps {
		r.Steps = r.Steps[:maxRemediationSteps]
	}
	if len(r.Warnings) > maxRemediationWarnings {
		r.Warnings = r.Warnings[:maxRemediationWarnings]
	}
	if len(r.Artifacts) > maxRemediationArtifacts {
		r.Artifacts = r.Artifacts[:maxRemediationArtifacts]
	}

	unsafe := false
	for i := range r.Artifacts {
		content := r.Artifacts[i].Content
		if len([]rune(content)) > maxRemediationArtifactRune {
			content = string([]rune(content)[:maxRemediationArtifactRune]) + "\n# … (truncated)"
			r.Artifacts[i].Content = content
		}
		normalized := normalizeForLint(content)
		for _, re := range destructivePatterns {
			if re.MatchString(content) || re.MatchString(normalized) {
				issues = append(issues, "artifact contains a potentially destructive command ("+re.String()+")")
				unsafe = true
			}
		}
		for _, re := range credentialPatterns {
			for _, m := range re.FindAllString(content, -1) {
				if placeholderRe.MatchString(m) {
					continue // a placeholder, not a real secret
				}
				issues = append(issues, "artifact appears to embed a credential literal")
				unsafe = true
				break
			}
		}
	}

	// Cloud grounding: a runnable cloud artifact should reference the actual
	// resource (ARN/name) or a clearly-marked placeholder — otherwise it may be
	// hallucinated. Soft signal: a warning, not a withhold.
	if f.Category == model.CategoryCloud && len(r.Artifacts) > 0 {
		res := f.Location.Resource
		name := f.Meta["resourceName"]
		grounded := false
		for _, a := range r.Artifacts {
			if (res != "" && strings.Contains(a.Content, res)) ||
				(name != "" && strings.Contains(a.Content, name)) ||
				placeholderRe.MatchString(a.Content) {
				grounded = true
				break
			}
		}
		if !grounded {
			issues = append(issues, "cloud remediation does not reference the target resource or a placeholder — verify the identifiers before running")
			r.Warnings = append(r.Warnings, "This script does not name the specific resource from the finding — confirm it targets the right resource before running.")
		}
	}

	// SAFE-BY-DEGRADATION: withhold runnable artifacts, keep the steps.
	if unsafe {
		r.Artifacts = nil
		r.Kind = KindManual
		r.Warnings = append([]string{
			"The generated script was withheld: it contained a potentially destructive command or an embedded credential. Follow the steps manually and script the change yourself.",
		}, r.Warnings...)
	}

	return r, issues
}
