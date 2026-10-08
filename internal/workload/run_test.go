package workload

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureOverlay struct {
	ready  atomic.Bool
	closed chan struct{}
	run    func(context.Context, <-chan struct{}) error
}

func (f *fixtureOverlay) Ready() bool { return f.ready.Load() }
func (f *fixtureOverlay) Run(c context.Context, complete <-chan struct{}) error {
	defer close(f.closed)
	return f.run(c, complete)
}

func TestChildWaitsForReadinessAndJoinsBeforeCleanup(t *testing.T) {
	childDone := make(chan struct{})
	started := make(chan struct{})
	f := &fixtureOverlay{closed: make(chan struct{})}
	f.run = func(ctx context.Context, complete <-chan struct{}) error {
		select {
		case <-started:
			t.Error("child started before readiness")
		case <-time.After(50 * time.Millisecond):
		}
		f.ready.Store(true)
		<-complete
		select {
		case <-childDone:
		default:
			t.Error("cleanup preceded joined child")
		}
		return nil
	}
	err := Run(context.Background(), f, func(context.Context) error { close(started); close(childDone); return nil }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.closed:
	default:
		t.Fatal("overlay not joined")
	}
}
func TestChildFailureStillCompletesCleanupAndFailsJob(t *testing.T) {
	f := &fixtureOverlay{closed: make(chan struct{})}
	f.ready.Store(true)
	f.run = func(ctx context.Context, complete <-chan struct{}) error { <-complete; return nil }
	err := Run(context.Background(), f, func(context.Context) error { return errors.New("private command text") }, time.Second)
	if err == nil || err.Error() != "workload failed" {
		t.Fatal(err)
	}
	select {
	case <-f.closed:
	default:
		t.Fatal("cleanup not joined")
	}
}
func TestCleanupFailureCannotBecomeSuccess(t *testing.T) {
	f := &fixtureOverlay{closed: make(chan struct{})}
	f.ready.Store(true)
	f.run = func(ctx context.Context, complete <-chan struct{}) error {
		<-complete
		return errors.New("identity release unconfirmed")
	}
	if e := Run(context.Background(), f, func(context.Context) error { return nil }, time.Second); e == nil {
		t.Fatal("cleanup failure hidden")
	}
}
func TestOverlayLossCancelsAndJoinsChild(t *testing.T) {
	started := make(chan struct{})
	joined := make(chan struct{})
	f := &fixtureOverlay{closed: make(chan struct{})}
	f.ready.Store(true)
	f.run = func(context.Context, <-chan struct{}) error { <-started; return errors.New("identity ownership lost") }
	e := Run(context.Background(), f, func(c context.Context) error { close(started); <-c.Done(); close(joined); return c.Err() }, time.Second)
	if e == nil {
		t.Fatal("lease loss hidden")
	}
	select {
	case <-joined:
	default:
		t.Fatal("orphan child")
	}
}
func TestCancellationDuringStartupNeverStartsChild(t *testing.T) {
	f := &fixtureOverlay{closed: make(chan struct{})}
	f.run = func(c context.Context, _ <-chan struct{}) error { <-c.Done(); return nil }
	var starts atomic.Int32
	e := Run(context.Background(), f, func(context.Context) error { starts.Add(1); return nil }, 40*time.Millisecond)
	if e == nil || starts.Load() != 0 {
		t.Fatal(e, starts.Load())
	}
	select {
	case <-f.closed:
	default:
		t.Fatal("startup not joined")
	}
}
func TestTimeoutJoinsChildBeforeOverlayCompletion(t *testing.T) {
	joined := make(chan struct{})
	f := &fixtureOverlay{closed: make(chan struct{})}
	f.ready.Store(true)
	f.run = func(c context.Context, complete <-chan struct{}) error {
		<-complete
		select {
		case <-joined:
		default:
			t.Error("released before termination")
		}
		return nil
	}
	e := Run(context.Background(), f, func(c context.Context) error { <-c.Done(); close(joined); return c.Err() }, 40*time.Millisecond)
	if e == nil {
		t.Fatal("timeout hidden")
	}
}
