package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/leaky-hub/argus/internal/compliance"
	"github.com/leaky-hub/argus/internal/model"
)

// HTMLMeta is the optional presentation context for a professional report.
// All fields are safe to omit (the CLI passes little; the console passes the
// full run context). Untrusted strings (Target, finding text) are rendered
// through html/template, which auto-escapes — a finding title containing
// "<script>" can never execute in the exported report.
type HTMLMeta struct {
	Target         string
	RunID          string
	GeneratedAt    string
	GateThreshold  string
	GateFailed     bool
	GateSuppressed int
	// Dispositions maps a finding fingerprint to its workflow status
	// (accepted-risk/fixed/…) so the report can show human triage decisions.
	Dispositions map[string]string
	// Tickets and ThreatModels are optional app-level context (the console
	// passes them; the CLI leaves them empty). Plain view structs keep this
	// package decoupled from the SQLite-backed ticket/threatmodel types.
	Tickets      []TicketReport
	ThreatModels []ThreatModelReport
}

// TicketReport is one ticket row in the exported report.
type TicketReport struct {
	ID          string
	Title       string
	Status      string
	Priority    string
	MaxSeverity string // highest linked-finding severity, "" if none
	LinkCount   int
}

// ThreatModelReport is one threat model with its threats, for the report.
type ThreatModelReport struct {
	Name       string
	Components int
	Threats    []ThreatReportRow
}

// ThreatReportRow is one threat line in a model.
type ThreatReportRow struct {
	Category   string
	Title      string
	Status     string
	Mitigation string
}

// WriteHTML renders a branded, print-optimized, fully self-contained HTML
// security report: an executive summary (severity mix + gate outcome),
// compliance posture, and every finding grouped by severity with its location,
// risk, description, remediation, mapped controls and disposition. No external
// assets — it prints to a clean PDF straight from the browser.
func WriteHTML(w io.Writer, findings []model.Finding, meta HTMLMeta) error {
	model.Sort(findings)
	summary := model.Summarize(findings)
	frameworks, _ := compliance.Summarize(findings) // best-effort; nil on error

	sevOrder := []model.Severity{
		model.SeverityCritical, model.SeverityHigh, model.SeverityMedium,
		model.SeverityLow, model.SeverityInfo,
	}

	// Severity mix for the summary bar.
	var mix []sevBar
	for _, sev := range sevOrder {
		n := summary.BySeverity[sev.String()]
		pct := 0.0
		if summary.Total > 0 {
			pct = float64(n) / float64(summary.Total) * 100
		}
		mix = append(mix, sevBar{Name: capitalize(sev.String()), Count: n, Pct: pct, Color: sevHex(sev)})
	}

	// Findings grouped by severity, each as a flat view-model.
	byS := map[model.Severity][]model.Finding{}
	for _, f := range findings {
		byS[f.Severity] = append(byS[f.Severity], f)
	}
	var groups []sevGroup
	for _, sev := range sevOrder {
		fs := byS[sev]
		if len(fs) == 0 {
			continue
		}
		g := sevGroup{Title: capitalize(sev.String()), Color: sevHex(sev), Count: len(fs)}
		for _, f := range fs {
			g.Findings = append(g.Findings, toView(f, meta.Dispositions))
		}
		groups = append(groups, g)
	}

	data := htmlReport{
		Meta:        meta,
		Total:       summary.Total,
		Mix:         mix,
		Frameworks:  frameworks,
		Groups:      groups,
		HasFindings: len(findings) > 0,
		GateLabel:   map[bool]string{true: "FAIL", false: "PASS"}[meta.GateFailed],
	}
	return htmlTemplate.Execute(w, data)
}

type htmlReport struct {
	Meta        HTMLMeta
	Total       int
	Mix         []sevBar
	Frameworks  []compliance.FrameworkSummary
	Groups      []sevGroup
	HasFindings bool
	GateLabel   string
}

type sevBar struct {
	Name  string
	Count int
	Pct   float64
	Color string
}

type sevGroup struct {
	Title    string
	Color    string
	Count    int
	Findings []fView
}

type fView struct {
	Title       string
	Severity    string
	SevColor    string
	Category    string
	Location    string
	Risk        string
	Description string
	Remediation string
	CWECVE      string
	Disposition string
	Tools       string
	Controls    []string
}

func toView(f model.Finding, dispositions map[string]string) fView {
	risk := "—"
	if f.RiskScore != nil {
		risk = fmt.Sprintf("%.1f", *f.RiskScore)
	}
	tools := strings.Join(f.Tools, ", ")
	if tools == "" {
		tools = f.Tool
	}
	dispo := ""
	if dispositions != nil {
		dispo = dispositions[f.ID]
	}
	return fView{
		Title:       f.Title,
		Severity:    capitalize(f.Severity.String()),
		SevColor:    sevHex(f.Severity),
		Category:    f.Category,
		Location:    formatLocation(f),
		Risk:        risk,
		Description: f.Description,
		Remediation: f.Remediation,
		CWECVE:      formatCWECVE(f),
		Disposition: dispositionLabel(dispo),
		Tools:       tools,
		Controls:    f.ComplianceControls,
	}
}

func sevHex(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "#b91c1c"
	case model.SeverityHigh:
		return "#ea580c"
	case model.SeverityMedium:
		return "#d97706"
	case model.SeverityLow:
		return "#2563eb"
	default:
		return "#6b7280"
	}
}

// dispositionLabel is a human label; "" for open/unknown so the report shows
// no badge. Kept in lockstep with internal/disposition's status vocabulary
// without importing it (report stays leaf-level).
func dispositionLabel(status string) string {
	switch status {
	case "in-progress":
		return "In progress"
	case "accepted-risk":
		return "Accepted risk"
	case "false-positive":
		return "False positive"
	case "fixed":
		return "Fixed"
	default:
		return ""
	}
}

// htmlTemplate is the whole report in one parsed template. Every dynamic value
// is auto-escaped by html/template; the only pre-trusted markup is this static
// chrome. Styles are inline so the file opens and prints anywhere offline.
var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus Security Report{{if .Meta.Target}} — {{.Meta.Target}}{{end}}</title>
<style>
  :root { --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --bg:#ffffff; --card:#f8fafc; }
  * { box-sizing: border-box; }
  body { margin:0; color:var(--ink); background:var(--bg); font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .wrap { max-width: 900px; margin: 0 auto; padding: 40px 32px 64px; }
  header { display:flex; align-items:center; justify-content:space-between; border-bottom:3px solid var(--ink); padding-bottom:16px; }
  .brand { display:flex; align-items:center; gap:12px; }
  .brand svg { width:34px; height:34px; }
  .brand .name { font-size:22px; font-weight:800; letter-spacing:-0.02em; }
  .brand .tag { font-size:11px; text-transform:uppercase; letter-spacing:0.14em; color:var(--muted); }
  .meta { text-align:right; font-size:12px; color:var(--muted); }
  .meta strong { color:var(--ink); }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:0.1em; color:var(--muted); margin:36px 0 12px; border-bottom:1px solid var(--line); padding-bottom:6px; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; }
  .card { flex:1 1 150px; background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
  .card .k { font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:var(--muted); }
  .card .v { font-size:26px; font-weight:800; margin-top:2px; }
  .gate { display:inline-block; padding:3px 10px; border-radius:999px; font-weight:700; font-size:13px; }
  .gate.pass { background:#dcfce7; color:#166534; }
  .gate.fail { background:#fee2e2; color:#991b1b; }
  .bar { display:flex; height:14px; border-radius:7px; overflow:hidden; border:1px solid var(--line); margin:6px 0 10px; }
  .bar span { display:block; height:100%; }
  .legend { display:flex; gap:16px; flex-wrap:wrap; font-size:12px; color:var(--muted); }
  .legend i { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:middle; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { font-size:11px; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted); }
  .grp { margin-top:14px; }
  .grp h3 { display:flex; align-items:center; gap:8px; font-size:15px; margin:22px 0 4px; }
  .dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
  .finding { border:1px solid var(--line); border-left-width:4px; border-radius:8px; padding:12px 14px; margin:10px 0; page-break-inside:avoid; }
  .finding .ttl { font-weight:700; font-size:14px; }
  .chips { display:flex; gap:6px; flex-wrap:wrap; margin:6px 0; }
  .chip { font-size:11px; padding:2px 7px; border-radius:999px; background:#eef2f7; color:#334155; }
  .chip.sev { color:#fff; }
  .chip.dispo { background:#fef3c7; color:#92400e; }
  .loc { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:var(--muted); word-break:break-all; }
  .lbl { font-size:11px; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted); margin-top:8px; }
  .body { font-size:13px; white-space:pre-wrap; word-break:break-word; }
  .rem { background:#f0f9ff; border:1px solid #bae6fd; border-radius:6px; padding:8px 10px; font-size:13px; white-space:pre-wrap; word-break:break-word; }
  footer { margin-top:40px; border-top:1px solid var(--line); padding-top:14px; font-size:11px; color:var(--muted); }
  .empty { text-align:center; padding:40px; color:#166534; font-size:18px; font-weight:600; }
  @media (prefers-color-scheme: dark) {
    :root { --ink:#e2e8f0; --muted:#94a3b8; --line:#334155; --bg:#0f172a; --card:#1e293b; }
    .gate.pass { background:#14532d; color:#bbf7d0; } .gate.fail { background:#7f1d1d; color:#fecaca; }
    .chip { background:#334155; color:#cbd5e1; } .rem { background:#0c2a3d; border-color:#155e75; }
  }
  @media print {
    .wrap { max-width:none; padding:0 12px; }
    header { border-color:#000; }
    .finding, .grp { page-break-inside:avoid; }
    a { color:inherit; text-decoration:none; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z" fill="#2563eb"/><path d="M8.5 12l2.4 2.4L15.8 9.5" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <div>
        <div class="name">Argus</div>
        <div class="tag">Application Security Report</div>
      </div>
    </div>
    <div class="meta">
      {{if .Meta.Target}}<div>Target: <strong>{{.Meta.Target}}</strong></div>{{end}}
      {{if .Meta.RunID}}<div>Run: {{.Meta.RunID}}</div>{{end}}
      {{if .Meta.GeneratedAt}}<div>Generated: {{.Meta.GeneratedAt}}</div>{{end}}
    </div>
  </header>

  <h2>Executive summary</h2>
  <div class="cards">
    <div class="card"><div class="k">Total findings</div><div class="v">{{.Total}}</div></div>
    {{if .Meta.GateThreshold}}<div class="card"><div class="k">Gate (≥ {{.Meta.GateThreshold}})</div><div class="v"><span class="gate {{if .Meta.GateFailed}}fail{{else}}pass{{end}}">{{.GateLabel}}</span></div>
      {{if gt .Meta.GateSuppressed 0}}<div class="k" style="margin-top:6px">{{.Meta.GateSuppressed}} accepted / FP excluded</div>{{end}}
    </div>{{end}}
  </div>

  <div class="bar">
    {{range .Mix}}{{if gt .Count 0}}<span style="width:{{printf "%.2f" .Pct}}%;background:{{.Color}}"></span>{{end}}{{end}}
  </div>
  <div class="legend">
    {{range .Mix}}<span><i style="background:{{.Color}}"></i>{{.Name}} {{.Count}}</span>{{end}}
  </div>

  {{if .Frameworks}}
  <h2>Compliance posture</h2>
  <table>
    <thead><tr><th>Framework</th><th>Version</th><th>Violated controls</th><th>Clean</th><th>Unmapped findings</th></tr></thead>
    <tbody>
      {{range .Frameworks}}<tr><td><strong>{{.ID}}</strong></td><td>{{.Version}}</td><td>{{.ViolatedControls}}</td><td>{{.CleanControls}}</td><td>{{.UnmappedFindings}}</td></tr>{{end}}
    </tbody>
  </table>
  {{end}}

  <h2>Findings</h2>
  {{if not .HasFindings}}
    <div class="empty">✓ No findings.</div>
  {{else}}
    {{range .Groups}}
    <div class="grp">
      <h3><span class="dot" style="background:{{.Color}}"></span>{{.Title}} ({{.Count}})</h3>
      {{range .Findings}}
      <div class="finding" style="border-left-color:{{.SevColor}}">
        <div class="ttl">{{.Title}}</div>
        <div class="chips">
          <span class="chip sev" style="background:{{.SevColor}}">{{.Severity}}</span>
          {{if .Category}}<span class="chip">{{.Category}}</span>{{end}}
          {{if .Risk}}<span class="chip">Risk {{.Risk}}</span>{{end}}
          {{if .Tools}}<span class="chip">{{.Tools}}</span>{{end}}
          {{if .Disposition}}<span class="chip dispo">{{.Disposition}}</span>{{end}}
        </div>
        <div class="loc">{{.Location}}</div>
        {{if .Description}}<div class="lbl">Description</div><div class="body">{{.Description}}</div>{{end}}
        {{if .Remediation}}<div class="lbl">Remediation</div><div class="rem">{{.Remediation}}</div>{{end}}
        {{if .CWECVE}}<div class="lbl">References</div><div class="body">{{.CWECVE}}</div>{{end}}
        {{if .Controls}}<div class="lbl">Mapped controls</div><div class="chips">{{range .Controls}}<span class="chip">{{.}}</span>{{end}}</div>{{end}}
      </div>
      {{end}}
    </div>
    {{end}}
  {{end}}

  {{if .Meta.Tickets}}
  <h2>Tickets</h2>
  <table>
    <thead><tr><th>Ticket</th><th>Title</th><th>Priority</th><th>Status</th><th>Severity</th><th>Findings</th></tr></thead>
    <tbody>
      {{range .Meta.Tickets}}<tr><td>{{.ID}}</td><td>{{.Title}}</td><td>{{.Priority}}</td><td>{{.Status}}</td><td>{{if .MaxSeverity}}{{.MaxSeverity}}{{else}}—{{end}}</td><td>{{.LinkCount}}</td></tr>{{end}}
    </tbody>
  </table>
  {{end}}

  {{if .Meta.ThreatModels}}
  <h2>Threat models</h2>
  {{range .Meta.ThreatModels}}
  <div class="grp">
    <h3>{{.Name}} <span class="k">· {{.Components}} component(s), {{len .Threats}} threat(s)</span></h3>
    {{if .Threats}}
    <table>
      <thead><tr><th>STRIDE</th><th>Threat</th><th>Status</th><th>Suggested fix</th></tr></thead>
      <tbody>
        {{range .Threats}}<tr><td>{{.Category}}</td><td>{{.Title}}</td><td>{{.Status}}</td><td>{{if .Mitigation}}{{.Mitigation}}{{else}}—{{end}}</td></tr>{{end}}
      </tbody>
    </table>
    {{end}}
  </div>
  {{end}}
  {{end}}

  <footer>
    Generated by Argus. Findings are assistive evidence; validate before acting. Remediation guidance is suggested, never run automatically.
  </footer>
</div>
</body>
</html>
`))
