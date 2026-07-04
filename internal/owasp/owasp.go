// Package owasp rolls findings up to the OWASP Top 10 (2021) from their CWEs.
//
// SECURITY-CRITICAL / REVIEWED MAP: this is presentation-layer enrichment only.
// It is computed report-side and NEVER written into a finding's
// complianceControls slot (that is reserved for the Phase 5 compliance engine).
// The CWE→category mapping below is hand-curated and intentionally
// conservative: a CWE with no confident mapping falls into A04 (Insecure
// Design) rather than being dropped, so every finding is always accounted for
// in the rollup and the totals reconcile with the finding count.
package owasp

import (
	"sort"

	"github.com/leaky-hub/appsec/internal/model"
)

// Category is one OWASP Top 10 (2021) entry.
type Category struct {
	ID    string `json:"id"`    // e.g. "A03"
	Title string `json:"title"` // e.g. "Injection"
}

// The 2021 Top 10, in rank order.
var (
	A01 = Category{"A01", "Broken Access Control"}
	A02 = Category{"A02", "Cryptographic Failures"}
	A03 = Category{"A03", "Injection"}
	A04 = Category{"A04", "Insecure Design"}
	A05 = Category{"A05", "Security Misconfiguration"}
	A06 = Category{"A06", "Vulnerable and Outdated Components"}
	A07 = Category{"A07", "Identification and Authentication Failures"}
	A08 = Category{"A08", "Software and Data Integrity Failures"}
	A09 = Category{"A09", "Security Logging and Monitoring Failures"}
	A10 = Category{"A10", "Server-Side Request Forgery"}
)

// ordered is the canonical display order.
var ordered = []Category{A01, A02, A03, A04, A05, A06, A07, A08, A09, A10}

// cweToCategory maps a CWE identifier to its OWASP Top 10 (2021) category.
// Sourced from the official OWASP Top 10 2021 CWE mappings, trimmed to the CWEs
// this platform's scanners actually emit plus common neighbors. Unmapped CWEs
// resolve to A04 via Classify.
var cweToCategory = map[string]Category{
	// A01 Broken Access Control
	"CWE-22":  A01, // path traversal
	"CWE-23":  A01,
	"CWE-35":  A01,
	"CWE-59":  A01,
	"CWE-200": A01, // information exposure
	"CWE-201": A01,
	"CWE-284": A01,
	"CWE-285": A01,
	"CWE-352": A01, // CSRF
	"CWE-359": A01,
	"CWE-425": A01,
	"CWE-639": A01,
	"CWE-863": A01,

	// A02 Cryptographic Failures
	"CWE-259": A02,
	"CWE-296": A02,
	"CWE-310": A02,
	"CWE-319": A02, // cleartext transmission
	"CWE-321": A02,
	"CWE-326": A02, // inadequate encryption strength
	"CWE-327": A02, // broken/risky crypto algorithm
	"CWE-328": A02, // weak hash
	"CWE-330": A02, // insufficiently random values
	"CWE-338": A02,
	"CWE-916": A02,

	// A03 Injection
	"CWE-73":  A03,
	"CWE-77":  A03, // command injection
	"CWE-78":  A03, // OS command injection
	"CWE-79":  A03, // XSS
	"CWE-88":  A03,
	"CWE-89":  A03, // SQL injection
	"CWE-90":  A03, // LDAP injection
	"CWE-91":  A03, // XML injection
	"CWE-94":  A03, // code injection
	"CWE-95":  A03, // eval injection
	"CWE-96":  A03,
	"CWE-98":  A03, // PHP file inclusion
	"CWE-113": A03,
	"CWE-116": A03,
	"CWE-564": A03,
	"CWE-643": A03,
	"CWE-917": A03, // expression language injection

	// A05 Security Misconfiguration
	"CWE-16":  A05,
	"CWE-260": A05,
	"CWE-315": A05,
	"CWE-520": A05,
	"CWE-526": A05,
	"CWE-611": A05, // XXE
	"CWE-614": A05,
	"CWE-756": A05,
	"CWE-776": A05,
	"CWE-942": A05,

	// A06 Vulnerable and Outdated Components
	"CWE-1035": A06,
	"CWE-1104": A06,
	"CWE-937":  A06,

	// A07 Identification and Authentication Failures
	"CWE-255": A07,
	"CWE-287": A07, // improper authentication
	"CWE-288": A07,
	"CWE-290": A07,
	"CWE-294": A07,
	"CWE-295": A07, // improper cert validation
	"CWE-297": A07,
	"CWE-306": A07,
	"CWE-307": A07,
	"CWE-384": A07, // session fixation
	"CWE-521": A07, // weak password requirements
	"CWE-613": A07,
	"CWE-620": A07,

	// A08 Software and Data Integrity Failures
	"CWE-345": A08,
	"CWE-353": A08,
	"CWE-426": A08,
	"CWE-494": A08,
	"CWE-502": A08, // deserialization of untrusted data
	"CWE-565": A08,
	"CWE-784": A08,
	"CWE-829": A08,
	"CWE-830": A08,
	"CWE-915": A08,

	// A09 Security Logging and Monitoring Failures
	"CWE-117": A09,
	"CWE-223": A09,
	"CWE-532": A09, // sensitive data in logs
	"CWE-778": A09,

	// A10 Server-Side Request Forgery
	"CWE-918": A10,
}

// Classify returns the OWASP category for a single finding. SCA findings map to
// A06 by nature (vulnerable components) regardless of CWE. Otherwise the
// finding's first mappable CWE wins; if none map, it falls into A04.
func Classify(f model.Finding) Category {
	if f.Category == model.CategorySCA {
		return A06
	}
	for _, cwe := range f.CWEs {
		if cat, ok := cweToCategory[cwe]; ok {
			return cat
		}
	}
	return A04
}

// Bucket is one row of the rollup: a category and the findings in it.
type Bucket struct {
	Category Category `json:"category"`
	Count    int      `json:"count"`
}

// Rollup returns the OWASP Top 10 distribution for a set of findings, in
// canonical A01→A10 order. Categories with zero findings are included (count 0)
// so the UI can render a stable ten-row axis. The bucket counts always sum to
// len(findings) — nothing is silently dropped.
func Rollup(findings []model.Finding) []Bucket {
	counts := map[string]int{}
	for _, f := range findings {
		counts[Classify(f).ID]++
	}
	buckets := make([]Bucket, 0, len(ordered))
	for _, c := range ordered {
		buckets = append(buckets, Bucket{Category: c, Count: counts[c.ID]})
	}
	return buckets
}

// TopNonEmpty returns the non-zero buckets sorted by count descending (ties
// broken by category order), for compact "top categories" displays.
func TopNonEmpty(findings []model.Finding) []Bucket {
	all := Rollup(findings)
	out := make([]Bucket, 0, len(all))
	for _, b := range all {
		if b.Count > 0 {
			out = append(out, b)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}
