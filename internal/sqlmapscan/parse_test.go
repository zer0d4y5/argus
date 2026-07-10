package sqlmapscan

import (
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// A real sqlmap summary block (trimmed), as printed to stdout.
const sqlmapOut = `[INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 146 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: id=1 OR 1=1
    Type: error-based
    Title: MySQL >= 5.1 AND error-based
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
`

func TestParseSqlmap(t *testing.T) {
	ep := dastcrawl.Endpoint{URL: "http://t/sqli/?id=1", Method: "GET"}
	fs := parseSqlmap([]byte(sqlmapOut), ep)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Tool != "sqlmap" || f.CWEs[0] != "CWE-89" {
		t.Errorf("tool/cwe wrong: %s / %v", f.Tool, f.CWEs)
	}
	if f.Meta["param"] != "id" || f.Meta["place"] != "GET" {
		t.Errorf("param/place wrong: %v", f.Meta)
	}
	if f.Meta["dbms"] == "" || !strings.Contains(f.Meta["dbms"], "MySQL") {
		t.Errorf("dbms not parsed: %v", f.Meta)
	}
	// The techniques (including blind) are folded into the title.
	if !strings.Contains(f.Title, "boolean-based blind") || !strings.Contains(f.Title, "time-based blind") {
		t.Errorf("techniques not in title: %q", f.Title)
	}
	if f.RawSeverity != "critical" {
		t.Errorf("severity = %q, want critical", f.RawSeverity)
	}
}

func TestParseSqlmapMultipleParams(t *testing.T) {
	out := `sqlmap identified the following injection point(s) with a total of 200 HTTP(s) requests:
Parameter: id (GET)
    Type: error-based
    Title: err
Parameter: name (POST)
    Type: time-based blind
    Title: blind
back-end DBMS: MySQL`
	fs := parseSqlmap([]byte(out), dastcrawl.Endpoint{URL: "http://t/x"})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	if fs[0].Meta["param"] != "id" || fs[1].Meta["param"] != "name" || fs[1].Meta["place"] != "POST" {
		t.Errorf("params/places wrong: %v %v", fs[0].Meta, fs[1].Meta)
	}
}

func TestParseSqlmapNoInjection(t *testing.T) {
	out := `[INFO] testing 'id'
[WARNING] parameter 'id' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable`
	if fs := parseSqlmap([]byte(out), dastcrawl.Endpoint{URL: "http://t/x"}); len(fs) != 0 {
		t.Errorf("want 0 findings on a clean scan, got %d", len(fs))
	}
}
