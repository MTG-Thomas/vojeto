// Package identity separates transport from exclusive identity ownership.
package identity

import (
	"context"
	"errors"
)

// Identity contains secret configuration. It must never be rendered in status or logs.
type Identity struct{ Config []byte }

// Provider must reject stale ownership. Release follows synchronous transport shutdown.
// Renew must checkpoint rotated credentials and accepted configuration before returning
// a changed Identity. An uncertain remote update must return ErrUnsafeRenewal.
type Provider interface {
	Acquire(context.Context) (*Identity, error)
	Renew(context.Context, *Identity) (*Identity, error)
	Checkpoint(context.Context, *Identity) error
	Release(context.Context, *Identity) error
}

// Watcher observes exclusive ownership independently of credential polling.
// revoke must synchronously stop transport; cancellation must join pending work.
// A nil return is permitted only after ctx cancellation.
type Watcher interface {
	Watch(ctx context.Context, revoke func()) error
}

// ErrUnsafeRenewal means remote credential rotation or its checkpoint is uncertain.
// It must quarantine ownership even when an update was cancelled for shutdown.
var ErrUnsafeRenewal = errors.New("identity renewal requires reconciliation")

// Validity optionally exposes conservative ownership validity to health status.
type Validity interface{ Valid() bool }
