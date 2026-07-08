package server

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/zer0d4y5/argus/internal/compliance"
	"github.com/zer0d4y5/argus/internal/coverage"
	"github.com/zer0d4y5/argus/internal/disposition"
	"github.com/zer0d4y5/argus/internal/mitigation"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/owasp"
	"github.com/zer0d4y5/argus/internal/report"
	"github.com/zer0d4y5/argus/internal/runstore"
)

// These types are the JSON API contract consumed by the React console. They are
// plain data — every string field ultimately originates from scanned code or an
// LLM and is therefore treated as hostile by the frontend (escaped on render).

// GateInfo is a run's pass/fail against a severity threshold. Suppressed
// counts findings excluded from the gate by disposition (accepted-risk /
// false-positive) — they stay in the report but no longer fail the build.
type GateInfo struct {
	Threshold  string `json:"threshold"`
	Failed     bool   `json:"failed"`
	Suppressed int    `json:"suppressed,omitempty"`
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
	RunCount int `json:"runCount"`
	// TotalTargets and ScannedTargets are set only for the portfolio aggregate:
	// how many targets the portfolio spans, and how many contributed a readable
	// latest run. ScannedTargets < TotalTargets means some targets are never
	// scanned or their latest run could not be read, so the portfolio is not a
	// clean pass over everything. Unreadable > 0 forces the gate to fail rather
	// than let a target with real findings silently vanish into a green board.
	TotalTargets   int            `json:"totalTargets,omitempty"`
	ScannedTargets int            `json:"scannedTargets,omitempty"`
	LatestID       string         `json:"latestId"`
	CreatedAt      string         `json:"createdAt"`
	Total          int            `json:"total"`
	BySeverity     map[string]int `json:"bySeverity"`
	ByCategory     map[string]int `json:"byCategory"`
	OWASP          []owasp.Bucket `json:"owasp"`
	// Compliance is the per-framework control rollup for the latest run,
	// computed report-side like OWASP (stored run files are never rewritten).
	Compliance []compliance.FrameworkSummary `json:"compliance"`
	RiskBands  RiskBands                     `json:"riskBands"`
	Gate       GateInfo                      `json:"gate"`
	Verdicts   VerdictCounts                 `json:"verdicts"`
	Trend      []TrendPoint                  `json:"trend"`
	// Dispositions is the latest run's finding-workflow rollup: counts by
	// status (open/in-progress/accepted-risk/false-positive/fixed) plus
	// "regression" (fixed but still present). The console renders it as a
	// clickable tile into the filtered Findings view.
	Dispositions map[string]int `json:"dispositions,omitempty"`
}

// dispositionRollup counts the run's findings by workflow status (open when no
// record) and flags regressions (status "fixed" but still present in the run).
func dispositionRollup(all map[string]disposition.Record, findings []model.Finding) map[string]int {
	out := map[string]int{
		disposition.StatusOpen: 0, disposition.StatusInProgress: 0,
		disposition.StatusAcceptedRisk: 0, disposition.StatusFalsePositive: 0,
		disposition.StatusFixed: 0, "regression": 0,
	}
	for _, f := range findings {
		if rec, ok := all[f.ID]; ok {
			out[rec.Status]++
			if rec.Status == disposition.StatusFixed {
				out["regression"]++ // present in the run yet marked fixed
			}
		} else {
			out[disposition.StatusOpen]++
		}
	}
	return out
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
	// Dispositions overlays the target's finding-workflow state (keyed by
	// finding fingerprint) onto this run — human status/note that follows a
	// finding across scans. Only ids present in this run are included. A
	// finding present here with status "fixed" is a REGRESSION (marked fixed
	// but still detected). Never stored in the run file; joined at read time.
	Dispositions map[string]disposition.Record `json:"dispositions,omitempty"`
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"

// gateFor computes a run's gate outcome against the server's threshold,
// excluding findings suppressed by disposition (accepted-risk /
// false-positive) — a human accepting a risk stops it failing CI, but it
// stays in the report. dispositions may be nil (no suppression).
func gateFor(findings []model.Finding, dispositions map[string]disposition.Record, gate *model.Severity, threshold string) GateInfo {
	relevant := findings
	suppressed := 0
	if len(dispositions) > 0 {
		relevant = make([]model.Finding, 0, len(findings))
		for _, f := range findings {
			if rec, ok := dispositions[f.ID]; ok && disposition.GateSuppressed(rec.Status) {
				suppressed++
				continue
			}
			relevant = append(relevant, f)
		}
	}
	return GateInfo{Threshold: threshold, Failed: model.GateExceeded(relevant, gate), Suppressed: suppressed}
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

// buildSummary aggregates the latest run plus the full-history trend for the
// given store — the served repo's default store, or a registered target's own
// store (dir/git/cloud). Selecting a target in the console threads its store
// through here exactly as the Runs and Findings tabs already do, so a run
// launched against a target shows up in the Overview instead of silently
// landing in a store nothing reads.
func (s *Server) buildSummary(store runstore.Store) (SummaryResponse, error) {
	runs, err := store.List()
	if err != nil {
		return SummaryResponse{}, err
	}
	// Trend is a JSON array, never null (empty store → []): the Overview chart
	// maps over it. BySeverity/ByCategory are already non-nil maps.
	resp := SummaryResponse{RunCount: len(runs), BySeverity: map[string]int{}, ByCategory: map[string]int{}, OWASP: owasp.Rollup(nil), Compliance: complianceSummary(nil), Trend: []TrendPoint{}}
	if len(runs) == 0 {
		return resp, nil
	}

	// Trend across every run, chronological.
	for _, r := range runs {
		doc, err := store.Load(r.ID)
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

	// Latest run drives the posture panels. If it can't be read, surface the
	// error rather than returning a zero-value (passing) gate — a corrupt latest
	// run must not read as a clean board.
	latest := runs[len(runs)-1]
	doc, err := store.Load(latest.ID)
	if err != nil {
		return SummaryResponse{}, fmt.Errorf("load latest run %s: %w", latest.ID, err)
	}
	resp.LatestID = latest.ID
	resp.CreatedAt = latest.CreatedAt.Format(rfc3339)
	resp.Total = doc.Summary.Total
	resp.BySeverity = doc.Summary.BySeverity
	resp.ByCategory = doc.Summary.ByCategory
	resp.OWASP = owasp.Rollup(doc.Findings)
	resp.Compliance = complianceSummary(doc.Findings)
	disp, _ := dispositionStore(store).All()
	resp.RiskBands = riskBands(doc.Findings)
	resp.Gate = gateFor(doc.Findings, disp, s.gate, s.gateName)
	resp.Verdicts = countVerdicts(doc.Findings)
	resp.Dispositions = dispositionRollup(disp, doc.Findings)
	return resp, nil
}

// buildAggregateSummary is the portfolio Overview: the union of the LATEST run
// of every target (served repo + registered targets), rolled up as one
// posture. Totals, severity, category, OWASP, compliance, risk bands, the
// disposition rollup, and the gate all span every target; the gate fails if
// any target's latest run does. The per-run trend is per-target, so it is left
// empty here (select a target to see it).
func (s *Server) buildAggregateSummary() (SummaryResponse, error) {
	resp := SummaryResponse{BySeverity: map[string]int{}, ByCategory: map[string]int{}, OWASP: owasp.Rollup(nil), Compliance: complianceSummary(nil), Trend: []TrendPoint{}}
	var all []model.Finding
	rollup := map[string]int{
		disposition.StatusOpen: 0, disposition.StatusInProgress: 0,
		disposition.StatusAcceptedRisk: 0, disposition.StatusFalsePositive: 0,
		disposition.StatusFixed: 0, "regression": 0,
	}
	var latest time.Time
	// The gate and disposition rollup are folded PER TARGET, not over the union.
	// Fingerprints carry no target identity, so a risk accepted on one target
	// would otherwise suppress an identical-fingerprint finding on another, and
	// the portfolio gate must fail if ANY target fails.
	gateFailed := false
	suppressed := 0
	unreadable := 0
	stores := s.storesForAggregate()
	resp.TotalTargets = len(stores)
	for _, store := range stores {
		runs, err := store.List()
		if err != nil {
			unreadable++ // a store we can't read must not silently pass
			continue
		}
		if len(runs) == 0 {
			continue // a never-scanned target: counted in TotalTargets, not scanned
		}
		r := runs[len(runs)-1]
		doc, err := store.Load(r.ID)
		if err != nil {
			unreadable++ // corrupt latest run: don't drop the target into a green board
			continue
		}
		resp.ScannedTargets++
		resp.RunCount += len(runs)
		all = append(all, doc.Findings...)

		storeDisp, _ := dispositionStore(store).All()
		g := gateFor(doc.Findings, storeDisp, s.gate, s.gateName)
		gateFailed = gateFailed || g.Failed
		suppressed += g.Suppressed
		for k, v := range dispositionRollup(storeDisp, doc.Findings) {
			rollup[k] += v
		}
		if r.CreatedAt.After(latest) {
			latest = r.CreatedAt
			resp.LatestID = r.ID
			resp.CreatedAt = r.CreatedAt.Format(rfc3339)
		}
	}
	// Enrich so compliance/OWASP reflect the union even for runs saved before
	// controls were written into the model. Deterministic and idempotent.
	_ = compliance.Apply(all)
	sum := model.Summarize(all)
	resp.Total = sum.Total
	resp.BySeverity = sum.BySeverity
	resp.ByCategory = sum.ByCategory
	resp.OWASP = owasp.Rollup(all)
	resp.Compliance = complianceSummary(all)
	resp.RiskBands = riskBands(all)
	resp.Gate = GateInfo{Threshold: s.gateName, Failed: gateFailed || unreadable > 0, Suppressed: suppressed}
	resp.Verdicts = countVerdicts(all)
	resp.Dispositions = rollup
	return resp, nil
}

// buildRuns lists all runs with their delta vs the immediately-previous run.
func (s *Server) buildRuns(store runstore.Store) (RunsResponse, error) {
	runs, err := store.List()
	if err != nil {
		return RunsResponse{}, err
	}
	// Always a JSON array, never null: an empty run store must serialize to
	// "runs": [] so the frontend can index/iterate it safely.
	out := RunsResponse{Runs: []RunListItem{}}
	// Dispositions are per-target, shared across the target's runs — load once.
	disp, _ := dispositionStore(store).All()
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
			Gate:       gateFor(doc.Findings, disp, s.gate, s.gateName),
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
	setDisplayNames(doc.Findings)

	runs, _ := store.List()
	createdAt := id
	for _, r := range runs {
		if r.ID == id {
			createdAt = r.CreatedAt.Format(rfc3339)
			break
		}
	}

	// Overlay the target's finding-workflow dispositions (keyed by
	// fingerprint), limited to the findings present in this run.
	dispositions := map[string]disposition.Record{}
	if all, err := dispositionStore(store).All(); err == nil {
		for _, f := range doc.Findings {
			if rec, ok := all[f.ID]; ok {
				dispositions[f.ID] = rec
			}
		}
	}

	return RunDetail{
		ID:           id,
		CreatedAt:    createdAt,
		Total:        doc.Summary.Total,
		BySeverity:   doc.Summary.BySeverity,
		ByCategory:   doc.Summary.ByCategory,
		OWASP:        owasp.Rollup(doc.Findings),
		Compliance:   complianceSummary(doc.Findings),
		Gate:         gateFor(doc.Findings, dispositions, s.gate, s.gateName),
		Verdicts:     countVerdicts(doc.Findings),
		Delta:        delta.Counts(),
		NewIDs:       findingIDs(delta.New),
		ResolvedIDs:  findingIDs(delta.Resolved),
		Findings:     doc.Findings,
		Coverage:     doc.Coverage,
		Dispositions: dispositions,
	}, nil
}

// setDisplayNames gives each finding a clean weakness name from the curated
// CWE→weakness map (e.g. "SQL Injection"), so the console can lead with that
// instead of a noisy scanner title. Findings whose CWEs don't map keep their
// title (DisplayName stays empty and the UI falls back).
func setDisplayNames(findings []model.Finding) {
	for i := range findings {
		if g, ok := mitigation.Lookup(findings[i].CWEs, ""); ok {
			findings[i].DisplayName = g.Title
		}
	}
}

// dispositionStore resolves the finding-workflow store that sits beside a run
// store: dispositions.json in the .appsec dir that also holds runs/. Works
// uniformly for the served repo, dir/git targets, and cloud targets, since
// every run store's Dir is `<...>/.appsec[/cloud/<id>]/runs`.
func dispositionStore(store runstore.Store) *disposition.Store {
	return disposition.At(filepath.Dir(store.Dir))
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
