package idorscan

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// idParamNames are parameter names that commonly reference an object.
var idParamNames = []string{
	"id", "uid", "uuid", "guid", "userid", "user_id", "user", "account", "acct",
	"order", "order_id", "orderid", "invoice", "doc", "document", "docid",
	"file", "fileid", "file_id", "pid", "ref", "record", "item", "itemid",
	"customer", "cid", "num", "no", "key", "object", "obj", "profile",
}

// looksLikeObjectRef reports whether a parameter is likely an object reference:
// its name suggests one, or its value is a bare integer or a uuid/long-hex id.
func looksLikeObjectRef(name, value string) bool {
	// The value must be an id-shaped token AND the name must look like an object
	// reference. Requiring both keeps pagination/config params (page, limit,
	// offset, year, version) out of the replay, which would otherwise flood the
	// results with false positives on public, id-varying lists.
	if !valueIsRef(value) {
		return false
	}
	l := strings.ToLower(strings.TrimSpace(name))
	if strings.HasSuffix(l, "id") {
		return true
	}
	for _, n := range idParamNames {
		if l == n || strings.HasSuffix(l, "_"+n) {
			return true
		}
	}
	return false
}

// valueIsRef reports whether a value looks like an object id worth replaying:
// a small-to-large integer, or a uuid / long hex string.
func valueIsRef(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if _, err := strconv.Atoi(v); err == nil {
		return true
	}
	if isHexID(v) || isUUID(v) {
		return true
	}
	return false
}

func isHexID(v string) bool {
	if len(v) < 8 {
		return false
	}
	for _, c := range v {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isUUID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// mutateID returns a different id of the same shape, for the control request.
func mutateID(v string) string {
	if n, err := strconv.Atoi(v); err == nil {
		if n == 1 {
			return "2"
		}
		return strconv.Itoa(n + 1)
	}
	// Flip the last character of a hex/uuid id to a different hex digit.
	if v == "" {
		return "1"
	}
	r := []byte(v)
	last := r[len(r)-1]
	if last == '0' {
		r[len(r)-1] = '1'
	} else {
		r[len(r)-1] = '0'
	}
	return string(r)
}

// sameObject reports whether two response bodies represent the same object.
// The bar is deliberately high: identical after normalization, or near-identical
// with only a small contiguous middle difference (a per-request token or a
// single field), measured by how much of the body the shared prefix AND suffix
// cover. Two genuinely different objects diverge across the whole body and fall
// well below the threshold, so shared page chrome cannot make them look "the
// same object".
func sameObject(a, b string) bool {
	a, b = norm(a), norm(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	la, lb := len(a), len(b)
	lo, hi := la, lb
	if lo > hi {
		lo, hi = hi, lo
	}
	if float64(lo)/float64(hi) < 0.95 {
		return false
	}
	// The shared prefix and suffix together must cover almost the whole body,
	// leaving only a small contiguous difference in the middle.
	p := commonPrefixLen(a, b)
	if p >= lo {
		return true
	}
	s := commonSuffixLen(a, b, p)
	return p+s >= (lo*95)/100
}

func norm(s string) string { return strings.Join(strings.Fields(s), " ") }

func commonPrefixLen(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// commonSuffixLen counts matching trailing bytes, not overlapping the prefix
// already counted (so the two regions never double-count on short strings).
func commonSuffixLen(a, b string, prefix int) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	max := n - prefix
	s := 0
	for s < max && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	return s
}

// requestTarget builds the (method, url, body) for a request that sets param to
// value, matching how get issues it.
func requestTarget(ep dastcrawl.Endpoint, base url.Values, param, value string) (method, u, body string) {
	vals := cloneValues(base)
	vals.Set(param, value)
	if ep.Method == http.MethodPost {
		return http.MethodPost, stripQuery(ep.URL), vals.Encode()
	}
	return http.MethodGet, stripQuery(ep.URL) + "?" + vals.Encode(), ""
}

func paramsOf(ep dastcrawl.Endpoint) ([]string, url.Values, error) {
	var vals url.Values
	if ep.Method == http.MethodPost {
		v, err := url.ParseQuery(ep.Body)
		if err != nil {
			return nil, nil, err
		}
		vals = v
	} else {
		u, err := url.Parse(ep.URL)
		if err != nil {
			return nil, nil, err
		}
		vals = u.Query()
	}
	names := make([]string, 0, len(vals))
	for name := range vals {
		names = append(names, name)
	}
	return names, vals, nil
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func stripQuery(raw string) string {
	if i := strings.Index(raw, "?"); i >= 0 {
		return raw[:i]
	}
	return raw
}
