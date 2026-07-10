package dastscan

import (
	"strings"

	"github.com/zer0d4y5/argus/internal/model"
)

// Evidence capture is opt-in and security-sensitive: nuclei's request carries
// the session credentials WE sent, and the response can hold data from the
// scanned app. This file builds a redacted, bounded model.Evidence so a finding
// can show what happened without leaking the session or unbounded app data.

const (
	maxRequestBytes  = 8 << 10  // 8 KiB
	maxResponseBytes = 16 << 10 // 16 KiB
)

// sensitiveHeaders are request/response header names whose VALUES are redacted:
// they carry credentials or session material, never useful as evidence.
var sensitiveHeaders = map[string]bool{
	"cookie":              true,
	"set-cookie":          true,
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-csrf-token":        true,
}

// buildEvidence assembles redacted evidence from a nuclei result, or nil when
// there is nothing to show.
func buildEvidence(r nucleiResult) *model.Evidence {
	req := redactHTTP(r.Request, maxRequestBytes)
	resp := redactHTTP(r.Response, maxResponseBytes)
	if req == "" && resp == "" {
		return nil
	}
	return &model.Evidence{
		Request:   req,
		Response:  resp,
		FuzzParam: strings.TrimSpace(r.FuzzingParameter),
		FuzzPos:   strings.TrimSpace(r.FuzzingPosition),
	}
}

// redactHTTP redacts credential/session header VALUES in a raw HTTP message and
// truncates it to max bytes. Header lines run until the first blank line; the
// body after it is passed through (bounded), since the body is the evidence
// (an error message, a reflected payload, an included file).
func redactHTTP(raw string, max int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Normalize line endings so header splitting is reliable.
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	inHeaders := true
	for i, line := range lines {
		if inHeaders {
			if line == "" {
				inHeaders = false
				continue
			}
			if name, _, ok := splitHeaderLine(line); ok && sensitiveHeaders[strings.ToLower(name)] {
				lines[i] = name + ": [redacted]"
			}
		}
	}
	out := strings.Join(lines, "\n")
	return truncate(out, max)
}

// splitHeaderLine parses "Name: value" from a header line.
func splitHeaderLine(line string) (name, value string, ok bool) {
	i := strings.Index(line, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n...[truncated]"
}
