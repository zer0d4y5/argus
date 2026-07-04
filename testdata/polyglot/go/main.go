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

	// PLANT: SQL injection via fmt.Sprintf into the query string (CWE-89)
	db, _ := sql.Open("mysql", "user:pass@/db")
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)
	_, _ = db.Query(query)

	// PLANT: OS command injection via a shell with concatenated input (CWE-78)
	cmd := exec.Command("bash", "-c", "echo "+userInput)
	_ = cmd.Run()

	// PLANT: weak hash (MD5) over sensitive input (CWE-328)
	hash := md5.Sum([]byte(userInput))
	_ = hash
}
