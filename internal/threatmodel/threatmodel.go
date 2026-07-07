// Package threatmodel is Argus's threat-modeling domain: a model scoped to a
// target, its components/boundaries, the STRIDE threats over them, and the links
// that tie a threat to real scan evidence. It persists in the embedded SQLite
// store.
//
// Threat CONTENT is deterministic: Enumerate pulls curated threats from
// internal/threatlib for a component's tech. Risk and status are always human.
// The optional LLM-assisted pass (server side) may only add source="assisted"
// threats that a human confirms; this package never lets a model set status.
//
// Every query is parameterized. Names, descriptions, and notes are rune-bounded
// hostile text, rendered inert by the console.
package threatmodel

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/leaky-hub/appsec/internal/store"
	"github.com/leaky-hub/appsec/internal/threatlib"
)

const (
	nameMax = 200
	textMax = 8000
)

var componentKinds = map[string]bool{"component": true, "asset": true, "boundary": true, "external-entity": true}
var threatStatuses = map[string]bool{"open": true, "mitigated": true, "accepted": true, "transferred": true}

func ValidKind(k string) bool         { return componentKinds[k] }
func ValidThreatStatus(s string) bool { return threatStatuses[s] }

var ErrNotFound = errors.New("threat model not found")

// Model is a threat model scoped to a target (or free-standing).
type Model struct {
	ID          string `json:"id"`
	TargetID    string `json:"targetId,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"createdAt"`
	CreatedBy   string `json:"createdBy,omitempty"`
	UpdatedAt   string `json:"updatedAt"`
}

// Component is one node in the model (component/asset/boundary/external-entity).
// Source records provenance: manual (hand-added), detected (IaC scan), or
// assisted (LLM-proposed, human-confirmed).
type Component struct {
	ID      string `json:"id"`
	ModelID string `json:"modelId"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Tech    string `json:"tech,omitempty"`
	Notes   string `json:"notes,omitempty"`
	Source  string `json:"source"`
}

var componentSources = map[string]bool{"manual": true, "detected": true, "assisted": true}

// Threat is one enumerated or hand-authored STRIDE threat.
type Threat struct {
	ID          string `json:"id"`
	ModelID     string `json:"modelId"`
	ComponentID string `json:"componentId,omitempty"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
	Source      string `json:"source"`
	Mitigation  string `json:"mitigation,omitempty"`
	CreatedAt   string `json:"createdAt"`
	CreatedBy   string `json:"createdBy,omitempty"`
}

// Link ties a threat to a finding, a control, or a mitigation.
type Link struct {
	Kind     string `json:"kind"` // finding | control | mitigation
	Ref      string `json:"ref"`
	TargetID string `json:"targetId,omitempty"`
}

type Store struct{ db *store.DB }

func NewStore(db *store.DB) *Store { return &Store{db: db} }

// dbtx is the subset of database/sql shared by *sql.DB and *sql.Tx, so a
// helper can run standalone or inside a transaction.
type dbtx interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// --- Models ---

func (s *Store) CreateModel(targetID, name, description, actor string, now time.Time) (Model, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Model{}, errors.New("model name is required")
	}
	ts := now.UTC().Format(time.RFC3339)
	m := Model{ID: newID("tm"), TargetID: strings.TrimSpace(targetID), Name: bound(name, nameMax),
		Description: bound(description, textMax), CreatedAt: ts, CreatedBy: actor, UpdatedAt: ts}
	_, err := s.db.Exec(`INSERT INTO threat_models (id, target_id, name, description, created_at, created_by, updated_at) VALUES (?,?,?,?,?,?,?)`,
		m.ID, m.TargetID, m.Name, m.Description, m.CreatedAt, m.CreatedBy, m.UpdatedAt)
	if err != nil {
		return Model{}, fmt.Errorf("threatmodel: create: %w", err)
	}
	return m, nil
}

func (s *Store) GetModel(id string) (Model, error) {
	var m Model
	err := s.db.QueryRow(`SELECT id, target_id, name, description, created_at, created_by, updated_at FROM threat_models WHERE id=?`, id).
		Scan(&m.ID, &m.TargetID, &m.Name, &m.Description, &m.CreatedAt, &m.CreatedBy, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Model{}, ErrNotFound
	}
	return m, err
}

func (s *Store) ListModels(targetID string) ([]Model, error) {
	q := `SELECT id, target_id, name, description, created_at, created_by, updated_at FROM threat_models`
	var args []any
	if targetID != "" {
		q += " WHERE target_id=?"
		args = append(args, targetID)
	}
	q += " ORDER BY updated_at DESC, id DESC"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("threatmodel: list: %w", err)
	}
	defer rows.Close()
	out := []Model{}
	for rows.Next() {
		var m Model
		if err := rows.Scan(&m.ID, &m.TargetID, &m.Name, &m.Description, &m.CreatedAt, &m.CreatedBy, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteModel(id string) error {
	res, err := s.db.Exec(`DELETE FROM threat_models WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func touchModel(q dbtx, id string, now time.Time) {
	q.Exec(`UPDATE threat_models SET updated_at=? WHERE id=?`, now.UTC().Format(time.RFC3339), id)
}

// --- Components ---

// AddComponent inserts a node. source is manual (hand-added), detected (IaC
// scan), or assisted (LLM-proposed, human-confirmed); anything else becomes
// manual so provenance can't be spoofed into a stronger claim.
func (s *Store) AddComponent(modelID, kind, name, tech, notes, source string, now time.Time) (Component, error) {
	if _, err := s.GetModel(modelID); err != nil {
		return Component{}, err
	}
	if kind == "" {
		kind = "component"
	}
	if !componentKinds[kind] {
		return Component{}, fmt.Errorf("invalid component kind %q", kind)
	}
	if strings.TrimSpace(name) == "" {
		return Component{}, errors.New("component name is required")
	}
	if !componentSources[source] {
		source = "manual"
	}
	c := Component{ID: newID("tc"), ModelID: modelID, Kind: kind, Name: bound(name, nameMax),
		Tech: strings.ToLower(strings.TrimSpace(tech)), Notes: bound(notes, textMax), Source: source}
	_, err := s.db.Exec(`INSERT INTO threat_components (id, model_id, kind, name, tech, notes, source) VALUES (?,?,?,?,?,?,?)`,
		c.ID, c.ModelID, c.Kind, c.Name, c.Tech, c.Notes, c.Source)
	if err != nil {
		return Component{}, fmt.Errorf("threatmodel: add component: %w", err)
	}
	touchModel(s.db, modelID, now)
	return c, nil
}

func (s *Store) Components(modelID string) ([]Component, error) {
	rows, err := s.db.Query(`SELECT id, model_id, kind, name, tech, notes, source FROM threat_components WHERE model_id=? ORDER BY name`, modelID)
	if err != nil {
		return nil, fmt.Errorf("threatmodel: components: %w", err)
	}
	defer rows.Close()
	out := []Component{}
	for rows.Next() {
		var c Component
		if err := rows.Scan(&c.ID, &c.ModelID, &c.Kind, &c.Name, &c.Tech, &c.Notes, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteComponent removes a component of modelID and every threat attached to
// it (threat links cascade with their threats). Scoped like the other
// mutators; one transaction so a failure can't half-delete.
func (s *Store) DeleteComponent(modelID, id string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("threatmodel: delete component: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM threat_components WHERE id=? AND model_id=?`, id, modelID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM threats WHERE component_id=? AND model_id=?`, id, modelID); err != nil {
		return err
	}
	touchModel(tx, modelID, now)
	return tx.Commit()
}

// --- Threats ---

// EnumerateComponent inserts the curated STRIDE threats for a component's tech
// that aren't already present (matched by category+title), returning how many
// were added. Deterministic: content comes from threatlib, source is "curated".
// The read (what exists) and the inserts share one transaction so two racing
// enumerations of the same component can't double-insert the curated set.
func (s *Store) EnumerateComponent(componentID string, now time.Time) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("threatmodel: enumerate: %w", err)
	}
	defer tx.Rollback()

	var modelID, tech string
	err = tx.QueryRow(`SELECT model_id, tech FROM threat_components WHERE id=?`, componentID).Scan(&modelID, &tech)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	curated, ok := threatlib.Enumerate(tech)
	if !ok {
		return 0, fmt.Errorf("no curated threats for component tech %q", tech)
	}
	existing, err := threatsOf(tx, modelID)
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, t := range existing {
		if t.ComponentID == componentID {
			seen[t.Category+"\x00"+t.Title] = true
		}
	}
	added := 0
	for _, th := range curated {
		if seen[th.Category+"\x00"+th.Title] {
			continue
		}
		if _, err := addThreatTo(tx, modelID, componentID, th.Category, th.Title, th.Description, "curated", th.Mitigation, "", now); err != nil {
			return 0, err
		}
		added++
	}
	touchModel(tx, modelID, now)
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("threatmodel: enumerate: %w", err)
	}
	return added, nil
}

// AddThreat inserts a hand-authored (source="manual") or human-confirmed
// assisted threat. "curated" is reserved for EnumerateComponent — it means
// "from the threatlib library", and a hand-typed threat claiming it would
// misstate provenance. Any unknown source becomes "manual".
func (s *Store) AddThreat(modelID, componentID, category, title, description, source, mitigation, actor string, now time.Time) (Threat, error) {
	if _, err := s.GetModel(modelID); err != nil {
		return Threat{}, err
	}
	if !threatlib.ValidCategory(category) {
		return Threat{}, fmt.Errorf("invalid STRIDE category %q", category)
	}
	if strings.TrimSpace(title) == "" {
		return Threat{}, errors.New("threat title is required")
	}
	if source != "assisted" && source != "manual" {
		source = "manual"
	}
	// A threat may only point at a component in its own model.
	if componentID != "" {
		var one int
		err := s.db.QueryRow(`SELECT 1 FROM threat_components WHERE id=? AND model_id=?`, componentID, modelID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return Threat{}, fmt.Errorf("component %s is not in this model", componentID)
		}
		if err != nil {
			return Threat{}, err
		}
	}
	return addThreatTo(s.db, modelID, componentID, category, title, description, source, mitigation, actor, now)
}

func addThreatTo(q dbtx, modelID, componentID, category, title, description, source, mitigation, actor string, now time.Time) (Threat, error) {
	t := Threat{ID: newID("th"), ModelID: modelID, ComponentID: componentID, Category: category,
		Title: bound(title, nameMax), Description: bound(description, textMax), Status: "open",
		Source: source, Mitigation: mitigation, CreatedAt: now.UTC().Format(time.RFC3339), CreatedBy: actor}
	_, err := q.Exec(`INSERT INTO threats (id, model_id, component_id, category, title, description, status, source, mitigation, created_at, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.ModelID, t.ComponentID, t.Category, t.Title, t.Description, t.Status, t.Source, t.Mitigation, t.CreatedAt, t.CreatedBy)
	if err != nil {
		return Threat{}, fmt.Errorf("threatmodel: add threat: %w", err)
	}
	return t, nil
}

func (s *Store) Threats(modelID string) ([]Threat, error) {
	return threatsOf(s.db, modelID)
}

func threatsOf(q dbtx, modelID string) ([]Threat, error) {
	rows, err := q.Query(`SELECT id, model_id, component_id, category, title, description, status, source, mitigation, created_at, created_by FROM threats WHERE model_id=? ORDER BY category, title`, modelID)
	if err != nil {
		return nil, fmt.Errorf("threatmodel: threats: %w", err)
	}
	defer rows.Close()
	out := []Threat{}
	for rows.Next() {
		var t Threat
		if err := rows.Scan(&t.ID, &t.ModelID, &t.ComponentID, &t.Category, &t.Title, &t.Description, &t.Status, &t.Source, &t.Mitigation, &t.CreatedAt, &t.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetThreatStatus updates a threat's human status (open/mitigated/accepted/
// transferred). Scoped to modelID so a caller can only move threats of the
// model it addressed (and the audit trail records the right model).
func (s *Store) SetThreatStatus(modelID, threatID, status string, now time.Time) error {
	if !threatStatuses[status] {
		return fmt.Errorf("invalid threat status %q", status)
	}
	res, err := s.db.Exec(`UPDATE threats SET status=? WHERE id=? AND model_id=?`, status, threatID, modelID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteThreat removes one threat of modelID; its links cascade.
func (s *Store) DeleteThreat(modelID, id string, now time.Time) error {
	res, err := s.db.Exec(`DELETE FROM threats WHERE id=? AND model_id=?`, id, modelID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	touchModel(s.db, modelID, now)
	return nil
}

// --- Links ---

// LinkThreat attaches evidence to a threat, scoped to modelID like
// SetThreatStatus: linking through another model's id is refused.
func (s *Store) LinkThreat(modelID, threatID, kind, ref, targetID string) error {
	if kind != "finding" && kind != "control" && kind != "mitigation" {
		return fmt.Errorf("invalid link kind %q", kind)
	}
	if strings.TrimSpace(ref) == "" {
		return errors.New("ref is required")
	}
	if err := s.threatInModel(modelID, threatID); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO threat_links (threat_id, kind, ref, target_id) VALUES (?,?,?,?)`, threatID, kind, ref, targetID)
	return err
}

func (s *Store) UnlinkThreat(modelID, threatID, kind, ref, targetID string) error {
	if err := s.threatInModel(modelID, threatID); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM threat_links WHERE threat_id=? AND kind=? AND ref=? AND target_id=?`, threatID, kind, ref, targetID)
	return err
}

// threatInModel returns ErrNotFound unless threatID belongs to modelID.
func (s *Store) threatInModel(modelID, threatID string) error {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM threats WHERE id=? AND model_id=?`, threatID, modelID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// LinksForModel returns every threat link in the model, grouped by threat id.
func (s *Store) LinksForModel(modelID string) (map[string][]Link, error) {
	rows, err := s.db.Query(`SELECT l.threat_id, l.kind, l.ref, l.target_id FROM threat_links l JOIN threats t ON t.id = l.threat_id WHERE t.model_id=?`, modelID)
	if err != nil {
		return nil, fmt.Errorf("threatmodel: links: %w", err)
	}
	defer rows.Close()
	out := map[string][]Link{}
	for rows.Next() {
		var tid string
		var l Link
		if err := rows.Scan(&tid, &l.Kind, &l.Ref, &l.TargetID); err != nil {
			return nil, err
		}
		out[tid] = append(out[tid], l)
	}
	return out, rows.Err()
}

func bound(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes])
}

func newID(prefix string) string {
	var b [6]byte
	rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}
