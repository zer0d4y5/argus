// Package poc builds the reproduction proof-of-concept for a confirmed dynamic
// finding: the raw HTTP request, a copy-paste curl, the observed proof, and a
// class-keyed plain-English reason the finding is real. Everything here is a
// deterministic rendering of what an engine already observed. Nothing in this
// package sends traffic.
//
// The session cookie is never rendered literally. When a scan was
// authenticated, the request and curl show a placeholder the operator fills in
// from their own session, so a shared PoC never carries a live credential.
package poc

import (
	"net/url"
	"sort"
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// CookiePlaceholder stands in for the live session cookie in rendered proofs.
// The operator substitutes their own session value to reproduce.
const CookiePlaceholder = "$ARGUS_SESSION"

// Request is the minimal shape of an HTTP request a reproduction renders. URL
// carries any query string already; Body is the form-encoded payload for a
// POST and is empty for a GET.
type Request struct {
	Method        string
	URL           string
	Body          string
	CookiePresent bool
}

// Build assembles the reproduction proof for a finding of the given class
// ("sqli", "xss", or "cmdi"). param is the injectable parameter and observed is
// the concrete proof the engine saw. It returns nil when there is nothing to
// reproduce (no URL).
func Build(class string, r Request, param, observed string) *model.Proof {
	if strings.TrimSpace(r.URL) == "" {
		return nil
	}
	if r.Method == "" {
		r.Method = "GET"
	}
	r.Method = strings.ToUpper(r.Method)
	return &model.Proof{
		Request:   RawHTTP(r),
		Curl:      Curl(r),
		Observed:  strings.TrimSpace(observed),
		Rationale: rationale(class, param),
	}
}

// Curl renders a copy-paste curl command that reissues the request. The session
// cookie, when present, is shown as a placeholder.
func Curl(r Request) string {
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		method = "GET"
	}
	var b strings.Builder
	b.WriteString("curl -sS")
	if method != "GET" {
		b.WriteString(" -X ")
		b.WriteString(method)
	}
	b.WriteString(" ")
	b.WriteString(shellQuote(r.URL))
	if r.Body != "" {
		b.WriteString(" --data ")
		b.WriteString(shellQuote(r.Body))
	}
	if r.CookiePresent {
		b.WriteString(" -H ")
		b.WriteString(shellQuote("Cookie: " + CookiePlaceholder))
	}
	return b.String()
}

// RawHTTP renders the request as a raw HTTP/1.1 message: the request line, a
// Host header, the auth cookie placeholder when authenticated, a content-type
// for a body-bearing method, and the body.
func RawHTTP(r Request) string {
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" {
		// Fall back to a single-line request when the URL will not parse; still
		// useful to a reader, and it never fabricates a host.
		line := method + " " + r.URL + " HTTP/1.1"
		if r.Body != "" {
			line += "\n\n" + r.Body
		}
		return line
	}
	target := u.EscapedPath()
	if target == "" {
		target = "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}
	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" ")
	b.WriteString(target)
	b.WriteString(" HTTP/1.1\n")
	b.WriteString("Host: ")
	b.WriteString(u.Host)
	b.WriteString("\n")
	if r.CookiePresent {
		b.WriteString("Cookie: ")
		b.WriteString(CookiePlaceholder)
		b.WriteString("\n")
	}
	if r.Body != "" {
		b.WriteString("Content-Type: application/x-www-form-urlencoded\n")
	}
	if r.Body != "" {
		b.WriteString("\n")
		b.WriteString(r.Body)
	}
	return b.String()
}

// rationale returns the class-keyed reason a finding is real. The text explains
// the mechanism, so a reviewer can judge it without rerunning the tool.
func rationale(class, param string) string {
	p := strings.TrimSpace(param)
	if p == "" {
		p = "the affected parameter"
	} else {
		p = "the " + p + " parameter"
	}
	switch class {
	case "sqli":
		return "sqlmap changed the query's logic through " + p + " and the response changed to match. That is only possible when the input reaches the database as SQL rather than as data."
	case "xss":
		return "An injected script payload in " + p + " was reflected into the response without output encoding, so it runs in the browser of anyone who loads the page."
	case "cmdi":
		return "A benign probe in " + p + " produced a value the server could only return by running the injected input as a shell command."
	default:
		return "The engine confirmed this dynamically against the running target using " + p + "."
	}
}

// AttachToRaw builds a reproduction proof for each dynamic finding that carries
// enough request context in its Meta (an injectable parameter and a class this
// package renders), using the endpoint bodies map for POST request bodies. A
// finding that already has a Proof (an engine built a fuller one, or a
// confirmation ran) is left untouched. It sends no traffic.
//
// bodies is keyed by requestKey(method, url); an absent entry means no body.
func AttachToRaw(raw []model.RawFinding, bodies map[string]string, cookiePresent bool) {
	for i := range raw {
		r := &raw[i]
		if r.Category != model.CategoryDAST || r.Proof != nil {
			continue
		}
		class := ClassForCWEs(r.CWEs)
		param := strings.TrimSpace(r.Meta["param"])
		if class == "" || param == "" || strings.TrimSpace(r.URL) == "" {
			// Not a reproduction-class finding. If it carries captured evidence
			// (a nuclei finding with request/response), fold that into a Proof so
			// every dynamic finding shows the exchange that produced it.
			if p := proofFromEvidence(r.Evidence); p != nil {
				r.Proof = p
			}
			continue
		}
		method := firstNonEmpty(r.Meta["method"], r.Meta["place"], "GET")
		method = strings.ToUpper(method)
		body := r.Meta["body"]
		if body == "" {
			body = bodies[RequestKey(method, r.URL)]
		}
		req := Request{Method: method, URL: r.URL, Body: body, CookiePresent: cookiePresent}
		p := Build(class, req, param, observedFromMeta(class, r.Meta))
		// The subprocess engines do not expose a raw response; fold captured
		// evidence's response in when present.
		if p != nil && r.Evidence != nil && r.Evidence.Response != "" {
			p.Response = RedactResponse(r.Evidence.Response)
		}
		r.Proof = p
	}
}

// proofFromEvidence builds a minimal proof (request + response) from an engine's
// captured evidence, for findings that are not one of the reproduction classes.
func proofFromEvidence(e *model.Evidence) *model.Proof {
	if e == nil || (e.Request == "" && e.Response == "") {
		return nil
	}
	return &model.Proof{
		Request:  e.Request,
		Response: RedactResponse(e.Response),
	}
}

// RedactResponse bounds a response body and scrubs any credential-bearing header
// lines that appear in it (a response body normally has none; this is defense in
// depth). The body itself is the evidence and is otherwise preserved.
func RedactResponse(body string) string {
	if body == "" {
		return ""
	}
	lines := strings.Split(body, "\n")
	for i, ln := range lines {
		l := strings.ToLower(strings.TrimSpace(ln))
		for _, h := range []string{"set-cookie:", "authorization:", "x-api-key:", "x-auth-token:", "cookie:"} {
			if strings.HasPrefix(l, h) {
				key := strings.SplitN(ln, ":", 2)[0]
				lines[i] = key + ": [redacted]"
				break
			}
		}
	}
	out := strings.Join(lines, "\n")
	if len(out) > maxResponseBytes {
		out = out[:maxResponseBytes] + "\n...[truncated]"
	}
	return out
}

const maxResponseBytes = 16 << 10

// RequestKey is the bodies-map key for AttachToRaw: an uppercased method and the
// URL.
func RequestKey(method, u string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + strings.TrimSpace(u)
}

// ClassForCWEs maps a finding's CWEs to a reproduction class this package
// renders, or "" when none applies.
func ClassForCWEs(cwes []string) string {
	for _, c := range cwes {
		switch strings.ToUpper(strings.TrimSpace(c)) {
		case "CWE-89":
			return "sqli"
		case "CWE-79":
			return "xss"
		case "CWE-78":
			return "cmdi"
		}
	}
	return ""
}

// observedFromMeta composes a concise proof line from the engine's Meta for the
// subprocess engines, which do not expose the exact winning payload.
func observedFromMeta(class string, meta map[string]string) string {
	switch class {
	case "sqli":
		s := "sqlmap confirmed an injectable parameter."
		if dbms := strings.TrimSpace(meta["dbms"]); dbms != "" {
			s = "sqlmap confirmed an injectable parameter. Back-end DBMS: " + dbms + "."
		}
		return s
	case "xss":
		if t := strings.TrimSpace(meta["dalfoxType"]); t != "" {
			return "dalfox reflected an executable payload (" + t + ") for this parameter."
		}
		return "dalfox reflected an executable payload for this parameter."
	case "cmdi":
		if t := strings.TrimSpace(meta["technique"]); t != "" {
			return "Confirmed by a " + t + " probe."
		}
		return "Confirmed by an out-of-band-free benign probe."
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// shellQuote wraps s in single quotes, escaping embedded single quotes, so the
// result is a safe single shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// BodiesFromEndpoints builds the AttachToRaw bodies map from a set of endpoints
// carrying (method, url, body). Later entries win on a key collision, which is
// acceptable for reproduction rendering.
func BodiesFromEndpoints(eps []Endpoint) map[string]string {
	m := make(map[string]string, len(eps))
	keys := make([]string, 0, len(eps))
	for _, ep := range eps {
		if strings.TrimSpace(ep.Body) == "" {
			continue
		}
		k := RequestKey(ep.Method, ep.URL)
		if _, ok := m[k]; !ok {
			keys = append(keys, k)
		}
		m[k] = ep.Body
	}
	sort.Strings(keys)
	return m
}

// Endpoint is the request context BodiesFromEndpoints needs. It mirrors the
// dastcrawl endpoint shape without importing it (this package stays dependency
// light and reusable).
type Endpoint struct {
	Method string
	URL    string
	Body   string
}
