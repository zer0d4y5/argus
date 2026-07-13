// Package idorscan detects insecure direct object references (IDOR) and broken
// object-level authorization (BOLA) by replaying one identity's object
// references as a second identity. If identity B can retrieve the object that
// identity A referenced, and gets the same response A did, the endpoint is not
// checking that the caller owns the object.
//
// A control request guards against false positives: B also fetches a DIFFERENT
// id. Only when B's response for A's id matches A's object AND differs from the
// control (so the endpoint actually varies by id, not a public page) is a
// finding raised. The cross-read body is never stored: the proof records that
// access succeeded and how many bytes matched, not the other user's data.
package idorscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/poc"
)

const (
	maxBodyBytes   = 512 << 10
	maxParamsPerEP = 6
	minBodyForIDOR = 24 // ignore trivially short responses
)

// Options configure an IDOR scan.
type Options struct {
	Endpoints []dastcrawl.Endpoint
}

// Scan replays each endpoint's object-reference parameters as identity B and
// reports the ones where B reads identity A's object. clientA and clientB carry
// the two identities' sessions.
func Scan(ctx context.Context, clientA, clientB *http.Client, opts Options, progress func(string)) []model.RawFinding {
	if progress == nil {
		progress = func(string) {}
	}
	if clientA == nil || clientB == nil {
		return nil
	}

	var out []model.RawFinding
	seen := map[string]bool{}
	for _, ep := range opts.Endpoints {
		if ctx.Err() != nil {
			break
		}
		names, base, err := paramsOf(ep)
		if err != nil {
			continue
		}
		tested := 0
		for _, name := range names {
			if tested >= maxParamsPerEP {
				break
			}
			original := base.Get(name)
			if !looksLikeObjectRef(name, original) {
				continue
			}
			tested++
			if f, ok := testParam(ctx, clientA, clientB, ep, base, name, original); ok {
				key := f.RuleID + "\x00" + f.URL
				if !seen[key] {
					seen[key] = true
					out = append(out, f)
				}
			}
		}
	}
	progress(fmt.Sprintf("idor: %d IDOR/BOLA finding(s)\n", len(out)))
	return out
}

func testParam(ctx context.Context, clientA, clientB *http.Client, ep dastcrawl.Endpoint, base url.Values, name, original string) (model.RawFinding, bool) {
	// A fetches its own object; B replays A's id; B fetches a different id as a
	// control so a public, id-invariant page is not mistaken for IDOR.
	bodyA, okA := get(ctx, clientA, ep, base, name, original)
	if !okA || len(strings.TrimSpace(bodyA)) < minBodyForIDOR {
		return model.RawFinding{}, false
	}
	bodyBSame, okBSame := get(ctx, clientB, ep, base, name, original)
	if !okBSame {
		return model.RawFinding{}, false // B is denied A's object: access control works
	}
	control := mutateID(original)
	bodyBOther, _ := get(ctx, clientB, ep, base, name, control)

	if !sameObject(bodyA, bodyBSame) {
		return model.RawFinding{}, false // B saw its own object or an error, not A's
	}
	if sameObject(bodyBSame, bodyBOther) {
		return model.RawFinding{}, false // id-invariant response: a public page, not IDOR
	}

	method, u, body := requestTarget(ep, base, name, original)
	f := model.RawFinding{
		Tool:        "argus-idor",
		Category:    model.CategoryDAST,
		RuleID:      "idor:" + strings.ToLower(method) + ":" + name,
		Title:       "Insecure Direct Object Reference (IDOR/BOLA)",
		Description: fmt.Sprintf("Parameter %q (%s) references an object without an ownership check: a second identity retrieved the object belonging to the first and received the same response.", name, method),
		RawSeverity: "high",
		URL:         ep.URL,
		CWEs:        []string{"CWE-639"},
		Meta:        map[string]string{"param": name, "method": method},
	}
	if body != "" {
		f.Meta["body"] = body
	}
	observed := fmt.Sprintf("Identity B requested %s's object (%s=%s) and received the same object identity A did (%d bytes matched). Changing the id to a value B owns returned different content, so the endpoint varies by id but does not check ownership. The cross-read body is redacted.", "identity A", name, original, len(bodyBSame))
	f.Proof = poc.Build("idor", poc.Request{Method: method, URL: u, Body: body, CookiePresent: true}, name, observed)
	if f.Proof != nil {
		// Never store the other identity's data; record only that it matched.
		f.Proof.Response = fmt.Sprintf("[cross-read body redacted: %d bytes, identical to identity A's object]", len(bodyBSame))
	}
	return f, true
}

// get fetches the endpoint with param set to value using the given identity's
// client, returning the body and whether the status was 200.
func get(ctx context.Context, client *http.Client, ep dastcrawl.Endpoint, base url.Values, param, value string) (string, bool) {
	method, u, reqBody := requestTarget(ep, base, param, value)
	var req *http.Request
	var err error
	if method == http.MethodPost {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(reqBody))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	}
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(body), resp.StatusCode == http.StatusOK
}
