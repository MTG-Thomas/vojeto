package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestCompletionOrderingAndIdempotence(t *testing.T) {
	m := New()
	m.Transition(AcquiringIdentity)
	m.Transition(Connecting)
	m.Transition(Ready)
	var calls []string
	hook := func(s string) func(context.Context) error {
		return func(context.Context) error { calls = append(calls, s); return nil }
	}
	h := Hooks{func() { calls = append(calls, "admission") }, hook("drain"), hook("checkpoint"), hook("transport"), hook("release"), hook("flush")}
	for i := 0; i < 2; i++ {
		if e := m.Complete(context.Background(), h); e != nil {
			t.Fatal(e)
		}
	}
	if m.State() != Stopped || !reflect.DeepEqual(calls, []string{"admission", "drain", "checkpoint", "transport", "release", "flush"}) {
		t.Fatal(calls, m.State())
	}
}
func TestCheckpointFailureNeverReleases(t *testing.T) {
	m := New()
	released := false
	ok := func(context.Context) error { return nil }
	h := Hooks{func() {}, ok, func(context.Context) error { return errors.New("failure") }, ok, func(context.Context) error { released = true; return nil }, ok}
	if m.Complete(context.Background(), h) == nil || released {
		t.Fatal("unsafe release")
	}
}
func TestLeaseLossNotReady(t *testing.T) {
	m := New()
	for _, s := range []State{AcquiringIdentity, Connecting, Ready, LeaseLost, NotReady} {
		if e := m.Transition(s); e != nil {
			t.Fatal(e)
		}
	}
	if m.Transition(Ready) == nil {
		t.Fatal("ambiguous ownership resumed")
	}
}
