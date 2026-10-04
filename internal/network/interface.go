// Package network defines the overlay boundary; consumers never use host dialing as a fallback.
package network

import (
	"context"
	"net"
	"net/netip"
)

type Network interface {
	DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
	Resolve(context.Context, string) ([]netip.Addr, error)
}
