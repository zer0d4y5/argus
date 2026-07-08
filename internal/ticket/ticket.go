// Package ticket is Argus's work-tracking layer over findings: a ticket gathers
// evidence (many findings, by stable fingerprint), owns the human workflow
// (status, priority, assignee, due date), and carries a comment/event timeline.
// It persists in the embedded SQLite store (internal/store).
//
// A ticket does NOT change a severity, the gate, or a compliance mapping. The
// gate reads dispositions, which stay file-based. The one bridge is explicit and
// audited: closing a ticket "done" can write a "fixed" disposition through the
// existing store — the server does that on a human action, not this package.
//
// Every query uses placeholders. Titles, descriptions, and comment bodies are
// hostile text (they may quote finding data); they are length-bounded here and
// rendered inert by the console, exactly like disposition notes.
package ticket

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/store"
)

// Field bounds. Human text, so bounded rather than validated for content.
const (
	titleMax   = 200
	descMax    = 8000
	commentMax = 4000
)

// Status is the closed set of ticket work states.
var statuses = map[string]bool{"open": true, "in-progress": true, "blocked": true, "done": true}

// Priority is the closed set of ticket priorities.
var priorities = map[string]bool{"low": true, "medium": true, "high": true, "urgent": true}

// ValidStatus / ValidPriority report membership, exported for the server's
// request validation.
func ValidStatus(s string) bool   { return statuses[s] }
func ValidPriority(p string) bool { return priorities[p] }

// ErrNotFound is returned when a ticket id does not exist.
var ErrNotFound = errors.New("ticket not found")

// ticketCols is the SELECT column list scanTicket expects, in scan order.
const ticketCols = `id, title, description, status, priority, assignee, target_id, due_date, external_url, external_id, created_at, created_by, updated_at`

// Ticket is one work item. Timestamps are RFC3339 strings (as stored).
type Ticket struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Priority    string `json:"priority"`
	Assignee    string `json:"assignee,omitempty"`
	TargetID    string `json:"targetId,omitempty"`
	DueDate     string `json:"dueDate,omitempty"`
	ExternalURL string `json:"externalUrl,omitempty"`
	ExternalID  string `json:"externalId,omitempty"`
	CreatedAt   string `json:"createdAt"`
	CreatedBy   string `json:"createdBy,omitempty"`
	UpdatedAt   string `json:"updatedAt"`
}

// Link ties a finding (by stable fingerprint, target-scoped) to a ticket.
type Link struct {
	FindingID string `json:"findingId"`
	TargetID  string `json:"targetId,omitempty"`
}

// Comment is one timeline entry: a human comment or a system event.
type Comment struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Author    string `json:"author,omitempty"`
	Body      string `json:"body"`
	CreatedAt string `json:"createdAt"`
}

// Store is the ticket data layer over the shared SQLite handle.
type Store struct {
	db *store.DB
}

func NewStore(db *store.DB) *Store { return &Store{db: db} }

// CreateInput is the caller-supplied fields for a new ticket.
type CreateInput struct {
	Title       string
	Description string
	Priority    string
	Assignee    string
	TargetID    string
	DueDate     string
}

// Create validates and inserts a new ticket, returning the stored row.
func (s *Store) Create(in CreateInput, actor string, now time.Time) (Ticket, error) {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return Ticket{}, errors.New("ticket title is required")
	}
	priority := strings.TrimSpace(in.Priority)
	if priority == "" {
		priority = "medium"
	}
	if !priorities[priority] {
		return Ticket{}, fmt.Errorf("invalid priority %q", priority)
	}
	ts := now.UTC().Format(time.RFC3339)
	t := Ticket{
		ID:          newID("tk"),
		Title:       bound(title, titleMax),
		Description: bound(in.Description, descMax),
		Status:      "open",
		Priority:    priority,
		Assignee:    strings.TrimSpace(in.Assignee),
		TargetID:    strings.TrimSpace(in.TargetID),
		DueDate:     strings.TrimSpace(in.DueDate),
		CreatedAt:   ts,
		CreatedBy:   actor,
		UpdatedAt:   ts,
	}
	_, err := s.db.Exec(`INSERT INTO tickets
		(id, title, description, status, priority, assignee, target_id, due_date, created_at, created_by, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Title, t.Description, t.Status, t.Priority, t.Assignee, t.TargetID, t.DueDate, t.CreatedAt, t.CreatedBy, t.UpdatedAt)
	if err != nil {
		return Ticket{}, fmt.Errorf("ticket: create: %w", err)
	}
	return t, nil
}

// UpdateInput patches a ticket: only non-nil fields change.
type UpdateInput struct {
	Title       *string
	Description *string
	Status      *string
	Priority    *string
	Assignee    *string
	DueDate     *string
}

// Update applies a patch and bumps updated_at. Returns the updated ticket.
// The read and the write share one transaction: Update rewrites every column
// from the row it read, so two concurrent patches of different fields would
// otherwise revert each other (lost update). The pool has a single connection,
// so holding the transaction serializes racing updates.
func (s *Store) Update(id string, in UpdateInput, now time.Time) (Ticket, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Ticket{}, fmt.Errorf("ticket: update: %w", err)
	}
	defer tx.Rollback()
	t, err := scanTicket(tx.QueryRow(`SELECT `+ticketCols+` FROM tickets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Ticket{}, ErrNotFound
	}
	if err != nil {
		return Ticket{}, err
	}
	if in.Title != nil {
		title := strings.TrimSpace(*in.Title)
		if title == "" {
			return Ticket{}, errors.New("ticket title cannot be empty")
		}
		t.Title = bound(title, titleMax)
	}
	if in.Description != nil {
		t.Description = bound(*in.Description, descMax)
	}
	if in.Status != nil {
		if !statuses[*in.Status] {
			return Ticket{}, fmt.Errorf("invalid status %q", *in.Status)
		}
		t.Status = *in.Status
	}
	if in.Priority != nil {
		if !priorities[*in.Priority] {
			return Ticket{}, fmt.Errorf("invalid priority %q", *in.Priority)
		}
		t.Priority = *in.Priority
	}
	if in.Assignee != nil {
		t.Assignee = strings.TrimSpace(*in.Assignee)
	}
	if in.DueDate != nil {
		t.DueDate = strings.TrimSpace(*in.DueDate)
	}
	t.UpdatedAt = now.UTC().Format(time.RFC3339)
	_, err = tx.Exec(`UPDATE tickets SET title=?, description=?, status=?, priority=?, assignee=?, due_date=?, updated_at=? WHERE id=?`,
		t.Title, t.Description, t.Status, t.Priority, t.Assignee, t.DueDate, t.UpdatedAt, t.ID)
	if err != nil {
		return Ticket{}, fmt.Errorf("ticket: update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Ticket{}, fmt.Errorf("ticket: update: %w", err)
	}
	return t, nil
}

// Delete removes a ticket; ticket_links and ticket_comments cascade.
func (s *Store) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM tickets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("ticket: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Get returns one ticket by id.
func (s *Store) Get(id string) (Ticket, error) {
	row := s.db.QueryRow(`SELECT `+ticketCols+` FROM tickets WHERE id = ?`, id)
	t, err := scanTicket(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Ticket{}, ErrNotFound
	}
	return t, err
}

// ListFilter narrows List; empty fields are ignored.
type ListFilter struct {
	Status   string
	TargetID string
	Assignee string
	Priority string
}

// List returns tickets newest-updated first, applying any filter fields.
func (s *Store) List(f ListFilter) ([]Ticket, error) {
	q := `SELECT ` + ticketCols + ` FROM tickets`
	var where []string
	var args []any
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.TargetID != "" {
		where = append(where, "target_id = ?")
		args = append(args, f.TargetID)
	}
	if f.Assignee != "" {
		where = append(where, "assignee = ?")
		args = append(args, f.Assignee)
	}
	if f.Priority != "" {
		where = append(where, "priority = ?")
		args = append(args, f.Priority)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY updated_at DESC, id DESC"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("ticket: list: %w", err)
	}
	defer rows.Close()
	out := []Ticket{}
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Link attaches a finding to a ticket (idempotent). The ticket must exist.
func (s *Store) Link(ticketID, findingID, targetID string) error {
	if strings.TrimSpace(findingID) == "" {
		return errors.New("findingId is required")
	}
	if _, err := s.Get(ticketID); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO ticket_links (ticket_id, finding_id, target_id) VALUES (?, ?, ?)`,
		ticketID, findingID, targetID)
	if err != nil {
		return fmt.Errorf("ticket: link: %w", err)
	}
	return nil
}

// Unlink detaches a finding from a ticket.
func (s *Store) Unlink(ticketID, findingID, targetID string) error {
	_, err := s.db.Exec(`DELETE FROM ticket_links WHERE ticket_id=? AND finding_id=? AND target_id=?`, ticketID, findingID, targetID)
	return err
}

// Links returns the findings attached to a ticket.
func (s *Store) Links(ticketID string) ([]Link, error) {
	rows, err := s.db.Query(`SELECT finding_id, target_id FROM ticket_links WHERE ticket_id = ? ORDER BY finding_id`, ticketID)
	if err != nil {
		return nil, fmt.Errorf("ticket: links: %w", err)
	}
	defer rows.Close()
	out := []Link{}
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.FindingID, &l.TargetID); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SetExternal records the linked external issue (URL + id). Only the
// REFERENCE is stored — never credentials, never issue content.
func (s *Store) SetExternal(id, url, extID string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE tickets SET external_url=?, external_id=?, updated_at=? WHERE id=?`,
		bound(url, 500), bound(extID, 100), now.UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("ticket: set external: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// StatusCounts returns how many tickets are in each status, for the Overview
// work widget.
func (s *Store) StatusCounts() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT status, COUNT(*) FROM tickets GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("ticket: counts: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// AllLinks returns every link grouped by ticket id, so the list view can build
// each ticket's severity rollup without a query per ticket.
func (s *Store) AllLinks() (map[string][]Link, error) {
	rows, err := s.db.Query(`SELECT ticket_id, finding_id, target_id FROM ticket_links`)
	if err != nil {
		return nil, fmt.Errorf("ticket: all links: %w", err)
	}
	defer rows.Close()
	out := map[string][]Link{}
	for rows.Next() {
		var tid string
		var l Link
		if err := rows.Scan(&tid, &l.FindingID, &l.TargetID); err != nil {
			return nil, err
		}
		out[tid] = append(out[tid], l)
	}
	return out, rows.Err()
}

// TicketsForFindings maps each finding id (within targetID) to the ticket ids it
// is linked to, so the Findings view can show a finding's tickets. targetID may
// be "" (the served repo's own store).
func (s *Store) TicketsForFindings(targetID string) (map[string][]string, error) {
	rows, err := s.db.Query(`SELECT finding_id, ticket_id FROM ticket_links WHERE target_id = ?`, targetID)
	if err != nil {
		return nil, fmt.Errorf("ticket: finding index: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var fid, tid string
		if err := rows.Scan(&fid, &tid); err != nil {
			return nil, err
		}
		out[fid] = append(out[fid], tid)
	}
	return out, rows.Err()
}

// AddComment appends a timeline entry. kind is "comment" (human) or "event"
// (system); an empty kind defaults to "comment".
func (s *Store) AddComment(ticketID, kind, author, body string, now time.Time) (Comment, error) {
	if _, err := s.Get(ticketID); err != nil {
		return Comment{}, err
	}
	if kind == "" {
		kind = "comment"
	}
	if kind != "comment" && kind != "event" {
		return Comment{}, fmt.Errorf("invalid comment kind %q", kind)
	}
	body = bound(body, commentMax)
	if kind == "comment" && strings.TrimSpace(body) == "" {
		return Comment{}, errors.New("comment body is required")
	}
	c := Comment{ID: newID("c"), Kind: kind, Author: author, Body: body, CreatedAt: now.UTC().Format(time.RFC3339)}
	_, err := s.db.Exec(`INSERT INTO ticket_comments (id, ticket_id, kind, author, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, ticketID, c.Kind, c.Author, c.Body, c.CreatedAt)
	if err != nil {
		return Comment{}, fmt.Errorf("ticket: comment: %w", err)
	}
	return c, nil
}

// Comments returns a ticket's timeline oldest-first.
func (s *Store) Comments(ticketID string) ([]Comment, error) {
	rows, err := s.db.Query(`SELECT id, kind, author, body, created_at FROM ticket_comments WHERE ticket_id = ? ORDER BY created_at, id`, ticketID)
	if err != nil {
		return nil, fmt.Errorf("ticket: comments: %w", err)
	}
	defer rows.Close()
	out := []Comment{}
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.Kind, &c.Author, &c.Body, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanTicket(sc scanner) (Ticket, error) {
	var t Ticket
	err := sc.Scan(&t.ID, &t.Title, &t.Description, &t.Status, &t.Priority, &t.Assignee, &t.TargetID, &t.DueDate, &t.ExternalURL, &t.ExternalID, &t.CreatedAt, &t.CreatedBy, &t.UpdatedAt)
	return t, err
}

// bound trims a string to at most maxRunes runes (rune-safe, not byte-truncated).
func bound(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes])
}

// newID returns an opaque id like tk-<12 hex>, matching the t-/j- convention.
func newID(prefix string) string {
	var b [6]byte
	rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}
