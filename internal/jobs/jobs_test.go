package jobs

import (
	"context"
	"testing"
	"time"
)

// TestStrictlySerial pins T7: with two jobs enqueued, the second stays
// queued until the first finishes — never two running at once.
func TestStrictlySerial(t *testing.T) {
	started := make(chan string, 4)
	release := make(chan struct{})

	q := New(func(ctx context.Context, job Job, progress func(string)) (string, error) {
		started <- job.ID
		<-release
		return "run-" + job.ID, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)

	j1, err := q.Enqueue("t-1", "one", "alice", Options{})
	if err != nil {
		t.Fatal(err)
	}
	j2, err := q.Enqueue("t-1", "one", "alice", Options{})
	if err != nil {
		t.Fatal(err)
	}

	// First job starts...
	select {
	case id := <-started:
		if id != j1.ID {
			t.Fatalf("started %s first, want %s", id, j1.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first job never started")
	}
	// ...and while it runs, the second must still be queued.
	time.Sleep(50 * time.Millisecond)
	if got, _ := q.Get(j2.ID); got.Status != StatusQueued {
		t.Fatalf("second job status = %q while first is running, want queued", got.Status)
	}
	select {
	case <-started:
		t.Fatal("second job started while first still running")
	default:
	}

	// Release both; both must finish with run IDs.
	close(release)
	deadline := time.After(2 * time.Second)
	for {
		g1, _ := q.Get(j1.ID)
		g2, _ := q.Get(j2.ID)
		if g1.Status == StatusDone && g2.Status == StatusDone {
			if g1.RunID == "" || g2.RunID == "" {
				t.Fatalf("missing run IDs: %q %q", g1.RunID, g2.RunID)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("jobs did not finish: %s=%s %s=%s", j1.ID, g1.Status, j2.ID, g2.Status)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestQueueBoundRejects pins "reject, don't buffer": with the worker wedged,
// the 11th pending submission fails with ErrQueueFull.
func TestQueueBoundRejects(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	q := New(func(ctx context.Context, job Job, progress func(string)) (string, error) {
		<-block
		return "", nil
	})
	// No Start: nothing drains the channel, so exactly maxPending fit.
	for i := 0; i < maxPending; i++ {
		if _, err := q.Enqueue("t", "t", "alice", Options{}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if _, err := q.Enqueue("t", "t", "alice", Options{}); err != ErrQueueFull {
		t.Fatalf("over-capacity enqueue: err=%v, want ErrQueueFull", err)
	}
}

func TestFailedJobRecordsError(t *testing.T) {
	q := New(func(ctx context.Context, job Job, progress func(string)) (string, error) {
		progress("==> running gitleaks (SECRET)\n")
		return "", context.DeadlineExceeded
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)

	j, _ := q.Enqueue("t", "t", "alice", Options{})
	deadline := time.After(2 * time.Second)
	for {
		g, _ := q.Get(j.ID)
		if g.Status == StatusFailed {
			if g.Error == "" || len(g.Progress) != 1 {
				t.Fatalf("failed job: error=%q progress=%v", g.Error, g.Progress)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("job stuck in %q", g.Status)
		case <-time.After(10 * time.Millisecond):
		}
	}
}
