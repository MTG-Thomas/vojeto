// Package lifecycle implements the same completion sequence for services and jobs.
package lifecycle

import (
	"context"
	"errors"
	"sync"
)

type State string

const (
	Starting          State = "starting"
	AcquiringIdentity State = "acquiring_identity"
	Connecting        State = "connecting"
	Ready             State = "ready"
	Reconnecting      State = "reconnecting"
	Rotating          State = "rotating"
	Draining          State = "draining"
	ReleasingIdentity State = "releasing_identity"
	Stopped           State = "stopped"
	LeaseLost         State = "lease_lost"
	NotReady          State = "not_ready"
)

type Manager struct {
	mu       sync.Mutex
	state    State
	complete sync.Once
	err      error
}

func New() *Manager             { return &Manager{state: Starting} }
func (m *Manager) State() State { m.mu.Lock(); defer m.mu.Unlock(); return m.state }
func (m *Manager) Transition(next State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	valid := map[State][]State{Starting: {AcquiringIdentity, Draining}, AcquiringIdentity: {Connecting, Draining, LeaseLost}, Connecting: {Ready, Draining, LeaseLost}, Ready: {Reconnecting, Rotating, Draining, LeaseLost}, Reconnecting: {Ready, Draining, LeaseLost}, Rotating: {Ready, Draining, LeaseLost}, LeaseLost: {NotReady}, NotReady: {Draining}, Draining: {ReleasingIdentity}, ReleasingIdentity: {Stopped}}
	for _, s := range valid[m.state] {
		if s == next {
			m.state = next
			return nil
		}
	}
	return errors.New("invalid lifecycle transition")
}

type Hooks struct {
	StopAccepting                                    func()
	Drain, Checkpoint, StopTransport, Release, Flush func(context.Context) error
}

// Complete is idempotent. A failed checkpoint/transport stop never releases ownership.
func (m *Manager) Complete(ctx context.Context, h Hooks) error {
	m.complete.Do(func() {
		if m.err = m.Transition(Draining); m.err != nil {
			return
		}
		h.StopAccepting()
		drainErr := h.Drain(ctx)
		if m.err = h.Checkpoint(ctx); m.err != nil {
			return
		}
		if m.err = h.StopTransport(ctx); m.err != nil {
			return
		}
		m.Transition(ReleasingIdentity)
		if m.err = h.Release(ctx); m.err != nil {
			return
		}
		if m.err = h.Flush(ctx); m.err != nil {
			return
		}
		m.Transition(Stopped)
		m.err = drainErr
	})
	return m.err
}
