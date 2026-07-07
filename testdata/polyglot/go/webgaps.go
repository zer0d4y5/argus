// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Web-gap classes caught by argus/curated rules the registry packs miss.
package webgaps

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
)

func ssrf(userURL string) (*http.Response, error) {
	// PLANT(go-ssrf-web, min-profile=standard, CWE-918): request to a variable URL (argus/curated)
	return http.Get(userURL)
}

func read(base, userInput string) ([]byte, error) {
	// PLANT(go-path-web, min-profile=standard, CWE-22): path joined from unsanitized input (argus/curated)
	return os.ReadFile(filepath.Join(base, userInput))
}

func tlsConfig() *tls.Config {
	// PLANT(go-tls-skip-verify, min-profile=standard, CWE-295): certificate verification disabled (argus/curated)
	return &tls.Config{InsecureSkipVerify: true}
}
