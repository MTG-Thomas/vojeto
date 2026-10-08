// Package workload coordinates a finite child with an exclusively owned overlay.
package workload

import (
	"context"
	"errors"
	"time"
)

// Overlay remains alive while a child exits, then performs its normal ordered
// drain/checkpoint/transport-stop/release. Run must honor context cancellation.
type Overlay interface {
	Run(context.Context, <-chan struct{}) error
	Ready() bool
}

// Run starts work only after readiness. Child failure still permits clean
// network cleanup, but neither child failure nor cleanup failure becomes success.
// A lost overlay cancels and joins the child before returning.
func Run(ctx context.Context, overlay Overlay, child func(context.Context) error, lifetime time.Duration) error {
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return errors.New("invalid workload lifetime")
	}
	bound, cancelBound := context.WithTimeout(ctx, lifetime)
	defer cancelBound()
	networkCtx, cancelNetwork := context.WithCancel(context.Background())
	defer cancelNetwork()
	complete := make(chan struct{})
	networkDone := make(chan error, 1)
	go func() { networkDone <- overlay.Run(networkCtx, complete) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for !overlay.Ready() {
		select {
		case e := <-networkDone:
			return errors.Join(errors.New("workload overlay stopped"), e)
		case <-bound.Done():
			cancelNetwork()
			return errors.Join(errors.New("workload cancelled"), <-networkDone)
		case <-ticker.C:
		}
	}
	// Prefer an already observed stop/cancellation over starting a workload.
	select {
	case e := <-networkDone:
		return errors.Join(errors.New("workload overlay stopped"), e)
	case <-bound.Done():
		cancelNetwork()
		return errors.Join(errors.New("workload cancelled"), <-networkDone)
	default:
	}
	childCtx, cancelChild := context.WithCancel(bound)
	defer cancelChild()
	childDone := make(chan error, 1)
	go func() { childDone <- child(childCtx) }()
	select {
	case e := <-networkDone:
		cancelChild()
		<-childDone
		return errors.Join(errors.New("workload overlay stopped"), e)
	case e := <-childDone:
		// Child is fully joined before network completion is requested.
		close(complete)
		networkError := <-networkDone
		if bound.Err() != nil {
			return errors.Join(errors.New("workload cancelled"), networkError)
		}
		if e != nil {
			return errors.Join(errors.New("workload failed"), networkError)
		}
		return networkError
	}
}
