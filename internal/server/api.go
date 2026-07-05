package server

import (
	"github.com/leaky-hub/appsec/internal/compliance"
	"github.com/leaky-hub/appsec/internal/coverage"
	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/owasp"
	"github.com/leaky-hub/appsec/internal/report"
	"github.com/leaky-hub/appsec/internal/runstore"
)

// These types are the JSON API contract consumed by the React console. They are
// plain data — every string field ultimately originates from scanned code or an
// LLM and is therefore treated as hostile by the frontend (escaped on render).

// GateInfo is a run's pass/fail against a severity threshold.
type GateInfo struct {
	Threshold string `json:"threshold"`
	Failed    bool   `json:"failed"`
}

// VerdictCounts is the triage rollup for a run.
type VerdictCounts struct {
	TruePositive  int `json:"truePositive"`
	FalsePositive int `json:"falsePositive"`
	Uncertain     int `json:"uncertain"`
	Untriaged     int `json:"untriaged"`
}

// RiskBands buckets findings for the Overview histogram. Since schema 2.0.0
// severity IS the banded deterministic risk score, so the histogram counts
// severities — that is what makes it agree with the finding badges by
// construction (counting the stored stage-3 riskScore instead would drift
// whenever a triage verdict moved a score across a band edge). For pre-2.0.0
// runs this shows tool-normalized severity, which is what their badges show.
type RiskBands struct {
	Info     int `json:"info"`     // det 0.0
	Low      int `json:"low"`      // 0.1 – 3.9
	Medium   int `json:"medium"`   // 4.0 – 6.9
	High     int `json:"high"`     // 7.0 – 8.9
	Critical int `json:"critical"` // >= 9.0
}

// TrendPoint is one run's headline numbers for the Overview trend chart.
type TrendPoint struct {
	ID         string         `json:"id"`
	CreatedAt  string         `json:"createdAt"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
	RiskAvg    float64        `json:"riskAvg"`
}

// RunListItem is a run as shown in the Runs (SecOps) list.
type RunListItem struct {
	ID         string          `json:"id"`
	CreatedAt  string          `json:"createdAt"`
	Total      int             `json:"total"`
	BySeverity map[string]int  `json:"bySeverity"`
	Gate       GateInfo        `json:"gate"`
	Delta      runstore.Counts `json:"delta"`
	Verdicts   VerdictCounts   `json:"verdicts"`
}

// RunsResponse is GET /api/runs.
type RunsResponse struct {
	Runs []RunListItem `json:"runs"`
}

// SummaryResponse is GET /api/summary — the Overview (GRC) payload.
type SummaryResponse struct {
	RunCount   int            `json:"runCount"`
	LatestID   string         `json:"latestId"`
	CreatedAt  string         `json:"createdAt"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
	ByCategory map[string]int `json:"byCategory"`
	OWASP      []owasp.Bucket `json:"owasp"`
	// Compliance is the per-framework control rollup for the latest run,
	// computed report-side like OWASP (stored run files are never rewritten).
	Compliance []compliance.FrameworkSummary `json:"compliance"`
	RiskBands  RiskBands                     `json:"riskBands"`
	Gate       GateInfo                      `json:"gate"`
	Verdicts   VerdictCounts                 `json:"verdicts"`
	Trend      []TrendPoint                  `json:"trend"`
}

// RunDetail is GET /api/runs/{id} — the Findings (AppSec) payload for one run.
type RunDetail struct {
	ID          string                        `json:"id"`
	CreatedAt   string                        `json:"createdAt"`
	Total       int                           `json:"total"`
	BySeverity  map[string]int                `json:"bySeverity"`
	ByCategory  map[string]int                `json:"byCategory"`
	OWASP       []owasp.Bucket                `json:"owasp"`
	Compliance  []compliance.FrameworkSummary `json:"compliance"`
	Gate        GateInfo                      `json:"gate"`
	Verdicts    VerdictCounts                 `json:"verdicts"`
	Delta       runstore.Counts               `json:"delta"`
	NewIDs      []string                      `json:"newIds"`      // finding IDs new vs previous run
	ResolvedIDs []string                      `json:"resolvedIds"` // IDs resolved since previous run
	Findings    []model.Finding               `json:"findings"`
	// Coverage is the run's skip accounting (schema 2.0.0): what the scan
	// did not look at. Absent for runs saved before 2.0.0; the UI
	// feature-detects.
	Coverage *coverage.Accounting `json:"coverage,omitempty"`
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"

// gateFor computes a run's gate outcome against the server's threshold.
func gateFor(findings []model.Finding, gate *model.Severity, threshold string) GateInfo {
	return GateInfo{Threshold: threshold, Failed: model.GateExceeded(findings, gate)}
}

// countVerdicts tallies triage verdicts across findings.
func countVerdicts(findings []model.Finding) VerdictCounts {
	var v VerdictCounts
	for _, f := range findings {
		if f.Triage == nil {
			v.Untriaged++
			continue
		}
		switch f.Triage.Verdict {
		case model.VerdictTruePositive:
			v.TruePositive++
		case model.VerdictFalsePositive:
			v.FalsePositive++
		default:
			v.Uncertain++
		}
	}
	return v
}

// riskBands buckets findings by banded severity (see the RiskBands doc).
func riskBands(findings []model.Finding) RiskBands {
	var b RiskBands
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			b.Critical++
		case model.SeverityHigh:
			b.High++
		case model.SeverityMedium:
			b.Medium++
		case model.SeverityLow:
			b.Low++
		default:
			b.Info++
		}
	}
	return b
}

// riskAvg is the mean risk score over scored findings (0 if none scored).
func riskAvg(findings []model.Finding) float64 {
	var sum float64
	var n int
	for _, f := range findings {
		if f.RiskScore != nil {
			sum += *f.RiskScore
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// complianceSummary computes the per-framework rollup, degrading to nil on a
// data error (a build defect) rather than blanking the whole response.
func complianceSummary(findings []model.Finding) []compliance.FrameworkSummary {
	sums, err := compliance.Summarize(findings)
	if err != nil {
		return nil
	}
	return sums
}

// findingIDs extracts IDs from a slice.
func findingIDs(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

// buildSummary aggregates the latest run plus the full-history trend.
func (s *Server) buildSummary() (SummaryResponse, error) {
	runs, err := s.store.List()
	if err != nil {
		return SummaryResponse{}, err
	}
	resp := SummaryResponse{RunCount: len(runs), BySeverity: map[string]int{}, ByCategory: map[string]int{}, OWASP: owasp.Rollup(nil), Compliance: complianceSummary(nil)}
	if len(runs) == 0 {
		return resp, nil
	}

	// Trend across every run, chronological.
	for _, r := range runs {
		doc, err := s.store.Load(r.ID)
		if err != nil {
			continue // a corrupt run must not blank the whole trend
		}
		resp.Trend = append(resp.Trend, TrendPoint{
			ID:         r.ID,
			CreatedAt:  r.CreatedAt.Format(rfc3339),
			Total:      doc.Summary.Total,
			BySeverity: doc.Summary.BySeverity,
			RiskAvg:    round1(riskAvg(doc.Findings)),
		})
	}

	// Latest run drives the posture panels.
	latest := runs[len(runs)-1]
	doc, err := s.store.Load(latest.ID)
	if err != nil {
		return resp, nil
	}
	resp.LatestID = latest.ID
	resp.CreatedAt = latest.CreatedAt.Format(rfc3339)
	resp.Total = doc.Summary.Total
	resp.BySeverity = doc.Summary.BySeverity
	resp.ByCategory = doc.Summary.ByCategory
	resp.OWASP = owasp.Rollup(doc.Findings)
	resp.Compliance = complianceSummary(doc.Findings)
	resp.RiskBands = riskBands(doc.Findings)
	resp.Gate = gateFor(doc.Findings, s.gate, s.gateName)
	resp.Verdicts = countVerdicts(doc.Findings)
	return resp, nil
}

// buildRuns lists all runs with their delta vs the immediately-previous run.
func (s *Server) buildRuns(store runstore.Store) (RunsResponse, error) {
	runs, err := store.List()
	if err != nil {
		return RunsResponse{}, err
	}
	var out RunsResponse
	var prev *report.Document
	for _, r := range runs {
		doc, err := store.Load(r.ID)
		if err != nil {
			continue
		}
		delta := runstore.ComputeDelta(prev, doc)
		out.Runs = append(out.Runs, RunListItem{
			ID:         r.ID,
			CreatedAt:  r.CreatedAt.Format(rfc3339),
			Total:      doc.Summary.Total,
			BySeverity: doc.Summary.BySeverity,
			Gate:       gateFor(doc.Findings, s.gate, s.gateName),
			Delta:      delta.Counts(),
			Verdicts:   countVerdicts(doc.Findings),
		})
		d := doc // copy for the next iteration's prev pointer
		prev = &d
	}
	// Newest first for the list view.
	reverse(out.Runs)
	return out, nil
}

// buildRunDetail returns one run's findings plus its delta vs the previous run.
func (s *Server) buildRunDetail(store runstore.Store, id string) (RunDetail, error) {
	doc, err := store.Load(id)
	if err != nil {
		return RunDetail{}, err
	}
	prev := previousDoc(store, id)
	delta := runstore.ComputeDelta(prev, doc)

	// Enrich at read time so runs saved before schema 1.2.0 still show control
	// chips. Deterministic and idempotent; the stored file is untouched.
	_ = compliance.Apply(doc.Findings)

	runs, _ := store.List()
	createdAt := id
	for _, r := range runs {
		if r.ID == id {
			createdAt = r.CreatedAt.Format(rfc3339)
			break
		}
	}

	return RunDetail{
		ID:          id,
		CreatedAt:   createdAt,
		Total:       doc.Summary.Total,
		BySeverity:  doc.Summary.BySeverity,
		ByCategory:  doc.Summary.ByCategory,
		OWASP:       owasp.Rollup(doc.Findings),
		Compliance:  complianceSummary(doc.Findings),
		Gate:        gateFor(doc.Findings, s.gate, s.gateName),
		Verdicts:    countVerdicts(doc.Findings),
		Delta:       delta.Counts(),
		NewIDs:      findingIDs(delta.New),
		ResolvedIDs: findingIDs(delta.Resolved),
		Findings:    doc.Findings,
		Coverage:    doc.Coverage,
	}, nil
}

// previousDoc returns the run immediately before id chronologically, or nil.
func previousDoc(store runstore.Store, id string) *report.Document {
	runs, err := store.List()
	if err != nil {
		return nil
	}
	var prevID string
	for _, r := range runs {
		if r.ID == id {
			break
		}
		prevID = r.ID
	}
	if prevID == "" {
		return nil
	}
	doc, err := store.Load(prevID)
	if err != nil {
		return nil
	}
	return &doc
}

func reverse(items []RunListItem) {
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
