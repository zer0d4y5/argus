// Safe-code plants for the FP measurement eval.
package fp

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
)

func safeSSRF() (*http.Response, error) {
	// PLANT-FP(go-safe-ssrf, CWE-918): constant URL, no user-controlled host.
	return http.Get("https://api.example.com/status")
}

func safeRead(base, in string) ([]byte, error) {
	// PLANT-FP(go-safe-path, CWE-22): filepath.Base strips directory components.
	return os.ReadFile(filepath.Join(base, filepath.Base(in)))
}

func safeTLS() *tls.Config {
	// PLANT-FP(go-safe-tls, CWE-295): verification left enabled.
	return &tls.Config{MinVersion: tls.VersionTLS13}
}
