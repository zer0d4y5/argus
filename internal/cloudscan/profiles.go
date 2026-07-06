package cloudscan

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// AWS profile discovery: the closed list cloud targets and cloud scans
// validate against. ONLY section headers are parsed — the scanner below
// never retains a non-header line, so credential values in
// ~/.aws/credentials pass through a bufio scanner and nothing else. Names
// are what the platform stores, shows, and places in a child env; values
// stay where the AWS SDK keeps them.

// profileHeader matches INI section headers in both AWS config flavors:
// `[default]`, `[profile name]` (config), `[name]` (credentials).
var profileHeader = regexp.MustCompile(`^\[\s*(?:profile\s+)?([^\]]+?)\s*\]$`)

// profileName bounds accepted profile names: the conservative subset of
// what AWS itself allows. A section name outside this grammar is ignored —
// it can then never be registered as a target nor reach an env var.
var profileName = regexp.MustCompile(`^[A-Za-z0-9_.@/+-]{1,128}$`)

// ListAWSProfiles returns the sorted profile names present in the local AWS
// config and credentials files. Missing files are fine (empty list, no
// error): "no profiles" is an answer, not a failure. The standard
// AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE overrides are honored —
// they are how tests exercise this without a real ~/.aws.
func ListAWSProfiles() ([]string, error) {
	home, _ := os.UserHomeDir()
	configPath := os.Getenv("AWS_CONFIG_FILE")
	if configPath == "" {
		configPath = filepath.Join(home, ".aws", "config")
	}
	credsPath := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if credsPath == "" {
		credsPath = filepath.Join(home, ".aws", "credentials")
	}

	seen := map[string]bool{}
	for _, path := range []string{configPath, credsPath} {
		names, err := profileHeaders(path)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func profileHeaders(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		m := profileHeader.FindStringSubmatch(line)
		if m == nil {
			continue // not a header: never inspected further, never retained
		}
		if name := m[1]; profileName.MatchString(name) {
			names = append(names, name)
		}
	}
	return names, sc.Err()
}
