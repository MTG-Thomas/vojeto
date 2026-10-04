package runtime

import (
	"context"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthGatesAdmissionRecoversAndJoins(t *testing.T) {
	log := &events{}
	p := &testProvider{log: log, loss: make(chan struct{})}
	n := &testTransport{log: log}
	var healthy, admitted atomic.Bool
	r, err := New(p, func(context.Context, []byte) (Transport, error) { return n, nil }, func(context.Context, network.Network) ([]Session, error) { admitted.Store(true); return nil, nil }, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	r.HealthInterval = time.Millisecond
	r.CheckHealth = func(ctx context.Context, _ network.Network) (bool, bool) {
		return healthy.Load() && ctx.Err() == nil, healthy.Load() && ctx.Err() == nil
	}
	complete := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background(), complete) }()
	time.Sleep(10 * time.Millisecond)
	if admitted.Load() || r.Status().OverlayReady {
		t.Fatal("admitted before verified health")
	}
	healthy.Store(true)
	waitHealth(t, r, true)
	healthy.Store(false)
	waitHealth(t, r, false)
	healthy.Store(true)
	waitHealth(t, r, true)
	close(complete)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r.Status().OverlayReady {
		t.Fatal("ready after exit")
	}
}
func waitHealth(t *testing.T, r *Runner, want bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s := r.Status()
		if (s.OverlayReady && s.DependenciesReady) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("health state did not converge")
}
func TestSignalGraceKeepsAdmissionButLeaseLossWins(t *testing.T) {
	for _, leaseLost := range []bool{false, true} {
		log := &events{}
		p := &testProvider{log: log, loss: make(chan struct{})}
		n := &testTransport{log: log}
		r, err := New(p, func(context.Context, []byte) (Transport, error) { return n, nil }, func(context.Context, network.Network) ([]Session, error) { return nil, nil }, testConfig())
		if err != nil {
			t.Fatal(err)
		}
		r.SignalGrace = time.Hour
		complete := make(chan struct{})
		done := make(chan error, 1)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { done <- r.Run(ctx, complete) }()
		awaitState(t, r, "ready")
		cancel()
		deadline := time.Now().Add(time.Second)
		for r.Status().State != "draining" && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if r.Status().State != "draining" {
			t.Fatal("signal did not withdraw readiness")
		}
		if n.closedCount.Load() != 0 {
			t.Fatal("overlay stopped before native drain")
		}
		if leaseLost {
			close(p.loss)
		} else {
			close(complete)
		}
		select {
		case err := <-done:
			if (err != nil) != leaseLost {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("completion or lease loss waited for grace")
		}
		if leaseLost && p.released.Load() != 0 {
			t.Fatal("lost identity released cleanly")
		}
	}
}
