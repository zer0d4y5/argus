// Package jobs is the console's scan job queue: STRICTLY SERIAL execution
// (one job running at any moment — this also protects the single-queue
// Ollama instance during triage), a bounded pending queue that rejects
// rather than buffers, and in-memory job state (a restart loses queue
// history, never completed runs — the audit log is the durable record).
// See docs/console-ops.md §7 / T7.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// maxPending bounds the queue; an Enqueue past this is rejected with
// ErrQueueFull ("reject, don't buffer").
const maxPending = 10

// maxRetained caps remembered finished jobs so the list cannot grow forever.
const maxRetained = 200

// ErrQueueFull is returned by Enqueue when the pending queue is at capacity.
var ErrQueueFull = errors.New("scan queue is full")

// Job status values (the API vocabulary).
const (
	StatusQueued  = "queued"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// Options are the closed-enum per-launch knobs, already validated by the
// server against the target's registry entry before enqueue. No free-form
// strings reach scanner invocation from here.
type Options struct {
	Scanners []string // subset of the target's allowed scanners; empty = target default
	Profile  string   // fast|standard|max; empty = target default
	Triage   *bool    // nil = repo-config default; the provider/model always come from config
}

// Job is one queued/executed scan. Snapshots returned by the queue are
// copies; only the worker mutates the canonical struct, under the queue mu.
type Job struct {
	ID         string    `json:"id"`
	TargetID   string    `json:"targetId"`
	TargetName string    `json:"targetName"`
	LaunchedBy string    `json:"launchedBy"`
	Options    Options   `json:"options"`
	Status     string    `json:"status"`
	QueuedAt   time.Time `json:"queuedAt"`
	StartedAt  time.Time `json:"startedAt,omitzero"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	Progress   []string  `json:"progress"`
	RunID      string    `json:"runId,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// ExecFunc runs one scan. It receives a progress sink (the pipeline
// callback) and returns the saved run ID. It runs on the single worker
// goroutine.
type ExecFunc func(ctx context.Context, job Job, progress func(line string)) (runID string, err error)

// Queue is the serial scan queue.
type Queue struct {
	exec ExecFunc

	mu    sync.Mutex
	jobs  map[string]*Job
	order []string // insertion order, oldest first

	pending chan string
}

// New builds a queue around exec. Call Start to launch the worker.
func New(exec ExecFunc) *Queue {
	return &Queue{
		exec:    exec,
		jobs:    make(map[string]*Job),
		pending: make(chan string, maxPending),
	}
}

// Start launches the single worker goroutine. It exits when ctx is
// cancelled; queued jobs left behind stay "queued" in memory, which dies
// with the process anyway.
func (q *Queue) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case id := <-q.pending:
				q.run(ctx, id)
			}
		}
	}()
}

// Enqueue adds a job, rejecting when the pending buffer is full.
func (q *Queue) Enqueue(targetID, targetName, launchedBy string, opts Options) (Job, error) {
	j := &Job{
		ID:         newID(),
		TargetID:   targetID,
		TargetName: targetName,
		LaunchedBy: launchedBy,
		Options:    opts,
		Status:     StatusQueued,
		QueuedAt:   time.Now().UTC(),
	}
	q.mu.Lock()
	select {
	case q.pending <- j.ID:
		q.jobs[j.ID] = j
		q.order = append(q.order, j.ID)
		q.trimLocked()
		snap := *j
		q.mu.Unlock()
		return snap, nil
	default:
		q.mu.Unlock()
		return Job{}, ErrQueueFull
	}
}

// run executes one job on the worker goroutine.
func (q *Queue) run(ctx context.Context, id string) {
	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok { // trimmed while queued (queue depth > retention would need that, impossible today)
		q.mu.Unlock()
		return
	}
	j.Status = StatusRunning
	j.StartedAt = time.Now().UTC()
	snap := *j
	q.mu.Unlock()

	progress := func(line string) {
		q.mu.Lock()
		if jj, ok := q.jobs[id]; ok {
			jj.Progress = append(jj.Progress, line)
		}
		q.mu.Unlock()
	}

	runID, err := q.exec(ctx, snap, progress)

	q.mu.Lock()
	if jj, ok := q.jobs[id]; ok {
		jj.FinishedAt = time.Now().UTC()
		if err != nil {
			jj.Status = StatusFailed
			jj.Error = err.Error()
		} else {
			jj.Status = StatusDone
			jj.RunID = runID
		}
	}
	q.mu.Unlock()
}

// Get returns a snapshot of one job.
func (q *Queue) Get(id string) (Job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok {
		return Job{}, false
	}
	return snapshot(j), true
}

// List returns snapshots of all retained jobs, newest first.
func (q *Queue) List() []Job {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Job, 0, len(q.order))
	for i := len(q.order) - 1; i >= 0; i-- {
		if j, ok := q.jobs[q.order[i]]; ok {
			out = append(out, snapshot(j))
		}
	}
	return out
}

// trimLocked drops the oldest FINISHED jobs beyond the retention cap.
// Queued/running jobs are never dropped. Callers hold q.mu.
func (q *Queue) trimLocked() {
	excess := len(q.order) - maxRetained
	if excess <= 0 {
		return
	}
	kept := q.order[:0]
	for _, id := range q.order {
		j := q.jobs[id]
		if excess > 0 && j != nil && (j.Status == StatusDone || j.Status == StatusFailed) {
			delete(q.jobs, id)
			excess--
			continue
		}
		kept = append(kept, id)
	}
	q.order = kept
}

// snapshot deep-copies a job (Progress is the only reference field).
func snapshot(j *Job) Job {
	c := *j
	c.Progress = append([]string(nil), j.Progress...)
	return c
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("jobs: crypto/rand unavailable: " + err.Error())
	}
	return "j-" + hex.EncodeToString(b[:])
}
