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
	valid := map[State][]State{
		Starting: {AcquiringIdentity, Draining, NotReady}, AcquiringIdentity: {Connecting, Draining, LeaseLost, NotReady},
		Connecting: {Ready, Draining, LeaseLost, NotReady}, Ready: {Reconnecting, Rotating, Draining, LeaseLost, NotReady},
		Reconnecting: {Ready, Draining, LeaseLost, NotReady}, Rotating: {Ready, Draining, LeaseLost, NotReady},
		Draining: {ReleasingIdentity, LeaseLost, NotReady}, ReleasingIdentity: {Stopped, LeaseLost, NotReady},
		LeaseLost: {NotReady}, NotReady: {Draining, Stopped},
	}
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

// Complete is idempotent. Transport stops even when checkpoint fails, and diagnostics
// flush on every exit. Failure never permits exclusive ownership release.
func (m *Manager) Complete(ctx context.Context, h Hooks) error {
	m.complete.Do(func() {
		defer func() { m.err = errors.Join(m.err, h.Flush(ctx)) }()
		transitionErr := m.Transition(Draining)
		h.StopAccepting()
		drainErr := h.Drain(ctx)
		checkpointErr := h.Checkpoint(ctx)
		stopErr := h.StopTransport(ctx)
		if transitionErr != nil || checkpointErr != nil || stopErr != nil {
			m.err = errors.Join(transitionErr, drainErr, checkpointErr, stopErr)
			return
		}
		// A bounded forced drain is clean once all sessions and transport are joined.
		if drainErr != nil && !errors.Is(drainErr, context.DeadlineExceeded) {
			m.err = drainErr
			return
		}
		if m.err = m.Transition(ReleasingIdentity); m.err != nil {
			return
		}
		if m.err = h.Release(ctx); m.err != nil {
			return
		}
		m.err = m.Transition(Stopped)
	})
	return m.err
}
