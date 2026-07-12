// Package dalfoxscan drives dalfox, an active XSS scanner, over a set of
// discovered endpoints (GET and POST) and maps its verified findings into the
// unified model (category DAST). It complements nuclei's fuzzing: dalfox
// confirms XSS by DOM execution and handles form bodies, so it catches
// reflected and stored XSS on POST forms that URL-parameter fuzzing misses.
//
// SECURITY: the parser reads only dalfox's structured JSONL identity fields
// (type, param, method, cwe, severity); it never copies the raw response. The
// auth cookie is passed to dalfox but never logged or written to a finding.
package dalfoxscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
)

// Available reports whether dalfox is on PATH.
func Available() bool {
	_, err := exec.LookPath("dalfox")
	return err == nil
}

// Options configure a dalfox run.
type Options struct {
	Cookie     string // "name=value; ..." session cookie ("" = unauthenticated)
	Endpoints  []dastcrawl.Endpoint
	PerReqSecs int // per-endpoint timeout in seconds (0 = a sane default)
	Workers    int // concurrent workers per endpoint; 0 = default. The engagement
	// intensity ceiling passes its per-host concurrency here so dalfox tests as
	// considerately as the rest of the scan.
}

// dalfoxFinding is the subset of one dalfox JSONL result we read. The tool also
// emits a trailing {"meta":...} line, which has no "type" and is skipped.
type dalfoxFinding struct {
	Type            string `json:"type"`             // "V" verified, "R" reflected, "G" grep
	TypeDescription string `json:"type_description"` // human summary
	InjectType      string `json:"inject_type"`
	Method          string `json:"method"`
	Param           string `json:"param"`
	Location        string `json:"location"` // Query | Body | ...
	Severity        string `json:"severity"`
	CWE             string `json:"cwe"`
	MessageStr      string `json:"message_str"`
	Data            string `json:"data"` // the request URL (may contain the payload)
}

// Scan runs dalfox against each endpoint and returns unified raw findings.
func Scan(ctx context.Context, opts Options, progress func(string)) ([]model.RawFinding, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !Available() {
		return nil, fmt.Errorf("dalfox not found on PATH")
	}
	timeout := opts.PerReqSecs
	if timeout <= 0 {
		timeout = 90
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = 10
	}

	var out []model.RawFinding
	seen := map[string]bool{}
	for _, ep := range opts.Endpoints {
		raw, err := runOne(ctx, ep, opts.Cookie, timeout, workers)
		if err != nil {
			progress(fmt.Sprintf("  ! dalfox %s: %v\n", ep.URL, err))
			continue
		}
		for _, f := range parseDalfox(raw, ep) {
			key := f.RuleID + "\x00" + f.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	progress(fmt.Sprintf("dalfox: %d XSS finding(s)\n", len(out)))
	return out, nil
}

// runOne invokes dalfox for a single endpoint (GET or POST) and returns its
// JSONL output. dalfox exits non-zero when it finds something, so exit status
// is not treated as an error on its own.
func runOne(ctx context.Context, ep dastcrawl.Endpoint, cookie string, timeoutSecs, workers int) ([]byte, error) {
	tmp, err := os.CreateTemp("", "argus-dalfox-*.jsonl")
	if err != nil {
		return nil, err
	}
	outPath := tmp.Name()
	tmp.Close()
	defer os.Remove(outPath)

	args := []string{
		"url", "--url", ep.URL,
		"-f", "jsonl", "-o", outPath,
		"-S",         // silence the banner/progress
		"--no-color", // machine-readable
		"--workers", itoa(workers),
		"--timeout", "10", // per-request network timeout (seconds)
		"--scan-timeout", itoa(timeoutSecs), // hard wall-clock cap per endpoint
	}
	if ep.Method == "POST" {
		args = append(args, "-X", "POST", "--data", ep.Body)
	}
	if cookie != "" {
		args = append(args, "--cookies", cookie)
	}

	cmd := exec.CommandContext(ctx, "dalfox", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run() // non-zero on findings; the output file is authoritative

	data, readErr := os.ReadFile(outPath)
	if readErr != nil {
		return nil, fmt.Errorf("read dalfox output: %w", readErr)
	}
	return data, nil
}

// parseDalfox maps dalfox JSONL into raw findings. One finding per
// (param, method) so distinct injectable inputs stay distinct; the meta line
// and non-finding lines are skipped.
func parseDalfox(data []byte, ep dastcrawl.Endpoint) []model.RawFinding {
	var out []model.RawFinding
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var f dalfoxFinding
		if err := json.Unmarshal(line, &f); err != nil || f.Type == "" || f.Param == "" {
			continue // the meta line and malformed records
		}
		param := strings.TrimSpace(f.Param)
		key := f.Method + "\x00" + param
		if seen[key] {
			continue // dalfox reports many payloads per param; one finding each
		}
		seen[key] = true

		title := "Cross-Site Scripting"
		if desc := strings.TrimSpace(f.TypeDescription); desc != "" {
			title = desc
		}
		out = append(out, model.RawFinding{
			Tool:        "dalfox",
			Category:    model.CategoryDAST,
			RuleID:      "dalfox-xss:" + strings.ToLower(f.Method) + ":" + param,
			Title:       title,
			Description: fmt.Sprintf("dalfox flagged parameter %q (%s) as XSS-injectable.", param, locationLabel(f)),
			RawSeverity: strings.ToLower(strings.TrimSpace(f.Severity)),
			URL:         ep.URL,
			CWEs:        cweList(f.CWE),
			Meta:        map[string]string{"param": param, "method": f.Method, "dalfoxType": f.Type},
		})
	}
	return out
}

func locationLabel(f dalfoxFinding) string {
	if f.Location != "" {
		return f.Location
	}
	return f.Method
}

func cweList(cwe string) []string {
	cwe = strings.TrimSpace(cwe)
	if cwe == "" {
		return []string{"CWE-79"}
	}
	if !strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
		cwe = "CWE-" + cwe
	}
	return []string{strings.ToUpper(cwe)}
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
