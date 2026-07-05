// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
//
// NOTE: lives under testdata/, which the Go toolchain ignores, so this is
// never compiled by `go build ./...`; it exists only to be scanned by semgrep.
package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"os/exec"
)

func main() {
	userInput := "admin'; DROP TABLE users; --"

	// PLANT(go-sqli, min-profile=standard, CWE-89): SQL injection via fmt.Sprintf into the query string
	db, _ := sql.Open("mysql", "user:pass@/db")
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)
	_, _ = db.Query(query)

	// PLANT-GAP: OS command injection via a shell with concatenated input (CWE-78) — caught by no profile
	cmd := exec.Command("bash", "-c", "echo "+userInput)
	_ = cmd.Run()

	// PLANT(go-weak-hash, min-profile=standard, CWE-328): weak hash (MD5) over sensitive input
	hash := md5.Sum([]byte(userInput))
	_ = hash
}
