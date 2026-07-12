package engagement

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// InScope is the single gate every active module consults before it sends a
// request. It returns true only when the URL is affirmatively in scope AND not
// excluded: out-of-scope entries always win, an unparseable or host-less URL is
// refused, and a URL matching nothing in scope is refused. Fail closed.
//
// This is the generalization of the crawler's isAuthPath guard: one predicate,
// consulted at one choke point, that decides whether a packet may leave.
func (e *Engagement) InScope(rawurl string) bool {
	if e == nil {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(rawurl))
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	// Exclusions first: an out-of-scope match refuses even something otherwise
	// in scope.
	for _, entry := range e.Scope.OutOfScope {
		if matchEntry(entry, u) {
			return false
		}
	}
	for _, entry := range e.Scope.InScope {
		if matchEntry(entry, u) {
			return true
		}
	}
	return false
}

// effectivePort returns the URL's port, defaulting from the scheme when absent,
// so "https://h" and "h:443" compare equal.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// matchEntry reports whether one scope entry matches the URL. Entry forms:
//
//   - CIDR ("10.0.0.0/8"): matches only when the host is an IP literal inside
//     the prefix (a hostname cannot be range-checked without DNS, which we do
//     not do).
//   - URL-prefix ("https://h/app/"): scheme + host(:port) must match and the
//     URL path must be under the entry path.
//   - "*.domain": matches any strict subdomain of domain.
//   - host or host:port: exact host match; a port in the entry must match the
//     URL's effective port, a bare host matches any port.
func matchEntry(entry string, u *url.URL) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())

	// URL-prefix.
	if strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://") {
		pu, err := url.Parse(entry)
		if err != nil || pu.Host == "" {
			return false
		}
		if pu.Scheme != u.Scheme {
			return false
		}
		if strings.ToLower(pu.Hostname()) != host {
			return false
		}
		if pu.Port() != "" && pu.Port() != effectivePort(u) {
			return false
		}
		return pathUnder(u.Path, pu.Path)
	}

	// CIDR.
	if strings.Contains(entry, "/") {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return false // hostname vs CIDR: never a match without DNS
			}
			return prefix.Contains(addr.Unmap())
		}
		return false
	}

	// Subdomain wildcard.
	if suffix, ok := strings.CutPrefix(entry, "*."); ok {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		return suffix != "" && strings.HasSuffix(host, "."+suffix)
	}

	// host or host:port.
	entry = strings.ToLower(entry)
	if h, p, ok := splitHostPort(entry); ok {
		return h == host && p == effectivePort(u)
	}
	return entry == host
}

// pathUnder reports whether target is at or under prefix. An empty or "/" prefix
// matches any path. Matching is segment-aware so "/app" does not match "/apple".
func pathUnder(target, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	prefix = strings.TrimRight(prefix, "/")
	if target == prefix {
		return true
	}
	return strings.HasPrefix(target, prefix+"/")
}

// splitHostPort splits "host:port" when port is all digits; it deliberately does
// not treat an IPv6 literal or a bare host as host:port.
func splitHostPort(entry string) (host, port string, ok bool) {
	i := strings.LastIndex(entry, ":")
	if i <= 0 || strings.Contains(entry, "]") {
		return "", "", false
	}
	host, port = entry[:i], entry[i+1:]
	if host == "" || port == "" {
		return "", "", false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return "", "", false
		}
	}
	return host, port, true
}

// validateScope rejects an empty or malformed scope at construction time, so a
// persisted engagement never carries an unusable gate.
func validateScope(s Scope) error {
	if len(s.InScope) == 0 {
		return fmt.Errorf("scope must declare at least one in-scope host, CIDR, or URL-prefix")
	}
	if len(s.InScope)+len(s.OutOfScope) > maxScopeEntries {
		return fmt.Errorf("scope has too many entries (max %d)", maxScopeEntries)
	}
	for _, entry := range append(append([]string{}, s.InScope...), s.OutOfScope...) {
		if err := validateEntry(entry); err != nil {
			return err
		}
	}
	return nil
}

// validateEntry checks one scope entry parses as one of the accepted forms.
func validateEntry(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return fmt.Errorf("scope entry is empty")
	}
	switch {
	case strings.HasPrefix(entry, "http://"), strings.HasPrefix(entry, "https://"):
		u, err := url.Parse(entry)
		if err != nil || u.Host == "" {
			return fmt.Errorf("scope URL-prefix %q is not a valid URL", entry)
		}
	case strings.Contains(entry, "/"):
		if _, err := netip.ParsePrefix(entry); err != nil {
			return fmt.Errorf("scope entry %q looks like a CIDR but does not parse: %w", entry, err)
		}
	case strings.HasPrefix(entry, "*."):
		if strings.TrimSpace(strings.TrimPrefix(entry, "*.")) == "" {
			return fmt.Errorf("scope wildcard %q has no domain", entry)
		}
	default:
		if strings.ContainsAny(entry, " \t") {
			return fmt.Errorf("scope host %q contains whitespace", entry)
		}
	}
	return nil
}
