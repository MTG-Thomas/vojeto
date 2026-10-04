// Package identity separates transport from exclusive identity ownership.
package identity

import "context"

// Identity contains secret configuration. It must never be rendered in status or logs.
type Identity struct{ Config []byte }

// Provider must reject stale ownership. Release follows synchronous transport shutdown.
// Implementations must checkpoint rotated credentials before applying configuration.
type Provider interface {
	Acquire(context.Context) (*Identity, error)
	Renew(context.Context, *Identity) (*Identity, error)
	Checkpoint(context.Context, *Identity) error
	Release(context.Context, *Identity) error
}
