// Package static loads caller-owned Nebula credentials without an exclusive lease.
package static

import (
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"os"
)

type Provider struct{ Path string }

var _ identity.Provider = Provider{}

func (p Provider) Acquire(ctx context.Context) (*identity.Identity, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	data, e := os.ReadFile(p.Path)
	if e != nil || len(data) == 0 {
		return nil, errors.New("static configuration unavailable")
	}
	return &identity.Identity{Config: data}, nil
}
func (p Provider) Renew(ctx context.Context, current *identity.Identity) (*identity.Identity, error) {
	return current, ctx.Err()
}
func (p Provider) Checkpoint(ctx context.Context, current *identity.Identity) error { return ctx.Err() }
func (p Provider) Release(ctx context.Context, current *identity.Identity) error    { return ctx.Err() }
