package apirecon

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// openAPIDoc is the subset of an OpenAPI 3 / Swagger 2 document this package
// reads: enough to enumerate operations, nothing more.
type openAPIDoc struct {
	OpenAPI  string                                `json:"openapi"`
	Swagger  string                                `json:"swagger"`
	BasePath string                                `json:"basePath"` // Swagger 2
	Servers  []struct{ URL string }                `json:"servers"`  // OpenAPI 3
	Paths    map[string]map[string]json.RawMessage `json:"paths"`
}

// openAPIOp is the subset of a single operation object this package reads.
type openAPIOp struct {
	Parameters []struct {
		Name string `json:"name"`
		In   string `json:"in"`
	} `json:"parameters"`
}

var pathParamRe = regexp.MustCompile(`\{[^/}]+\}`)

// maxRawOperations bounds how many operations are materialized before the final
// per-scan cap, so a document with hundreds of thousands of paths cannot force
// excessive allocation and an O(n log n) sort.
const maxRawOperations = 2000

// parseOpenAPI validates that body is an OpenAPI/Swagger document with paths.
func parseOpenAPI(body []byte) (openAPIDoc, bool) {
	var doc openAPIDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return doc, false
	}
	if doc.OpenAPI == "" && doc.Swagger == "" {
		return doc, false
	}
	if len(doc.Paths) == 0 {
		return doc, false
	}
	return doc, true
}

// openAPIOperations turns a parsed document into fuzzable operations: one per
// (path, fuzzable method). Path parameters are filled with a benign "1", query
// and form parameters are seeded with "1" so the fuzzers have something to
// mutate. The result is sorted for determinism.
func openAPIOperations(doc openAPIDoc, root string) []dastcrawl.Endpoint {
	base := strings.TrimRight(basePath(doc), "/")
	var out []dastcrawl.Endpoint
	for rawPath, methods := range doc.Paths {
		if len(out) >= maxRawOperations {
			break // bound the work a hostile/huge document can force before the final cap
		}
		fullPath := base + templatePath(rawPath)
		if !strings.HasPrefix(fullPath, "/") {
			fullPath = "/" + fullPath
		}
		for m, opRaw := range methods {
			method := strings.ToUpper(m)
			if !fuzzMethods[method] {
				continue
			}
			var op openAPIOp
			_ = json.Unmarshal(opRaw, &op)
			query, form := splitParams(op)
			u := root + fullPath
			if enc := query.Encode(); enc != "" {
				u += "?" + enc
			}
			ep := dastcrawl.Endpoint{URL: u, Method: method}
			if method != "GET" {
				ep.Body = form.Encode()
			}
			out = append(out, ep)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// basePath derives the API base path from a Swagger 2 basePath or an OpenAPI 3
// server URL (path portion only; an absolute server URL to another host is
// ignored, so recovered operations stay on the target).
func basePath(doc openAPIDoc) string {
	if doc.BasePath != "" {
		return doc.BasePath
	}
	if len(doc.Servers) > 0 {
		if u, err := url.Parse(doc.Servers[0].URL); err == nil {
			return u.Path
		}
	}
	return ""
}

// templatePath replaces {param} path templates with a benign concrete value.
func templatePath(p string) string {
	return pathParamRe.ReplaceAllString(p, "1")
}

// splitParams seeds query and form parameters with "1" from an operation's
// declared parameters. Path parameters are already substituted; header, cookie,
// and OpenAPI-3 request bodies are not driven in this version.
func splitParams(op openAPIOp) (query, form url.Values) {
	query, form = url.Values{}, url.Values{}
	for _, p := range op.Parameters {
		if p.Name == "" {
			continue
		}
		switch strings.ToLower(p.In) {
		case "query":
			query.Set(p.Name, "1")
		case "formdata":
			form.Set(p.Name, "1")
		}
	}
	return query, form
}
