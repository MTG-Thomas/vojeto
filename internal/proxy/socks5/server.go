// Package socks5 implements finite, allowlisted TCP CONNECT only.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Config struct {
	Listen                string
	Allow                 []netip.AddrPort
	MaxConnections        int
	DialTimeout, Lifetime time.Duration
}

func Serve(ctx context.Context, n network.Network, c Config) error {
	a, e := netip.ParseAddrPort(c.Listen)
	if e != nil || !a.Addr().IsLoopback() || len(c.Allow) == 0 || c.MaxConnections < 1 || c.DialTimeout <= 0 || c.Lifetime <= 0 {
		return errors.New("invalid finite SOCKS policy")
	}
	allowed := map[netip.AddrPort]bool{}
	for _, d := range c.Allow {
		if !d.IsValid() || !d.Addr().Is4() || d.Port() == 0 {
			return errors.New("invalid allowlist")
		}
		allowed[d] = true
	}
	ctx, cancel := context.WithTimeout(ctx, c.Lifetime)
	defer cancel()
	ln, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return e
	}
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	slots := make(chan struct{}, c.MaxConnections)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		local, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			local.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer local.Close()
			stop := context.AfterFunc(ctx, func() { local.Close() })
			defer stop()
			local.SetDeadline(time.Now().Add(c.DialTimeout))
			dst, e := request(local)
			if e != nil || !allowed[dst] {
				local.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			dial, cancel := context.WithTimeout(ctx, c.DialTimeout)
			remote, e := n.DialTCP(dial, dst)
			cancel()
			if e != nil {
				local.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer remote.Close()
			if _, e = local.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
				return
			}
			local.SetDeadline(time.Time{})
			forward.Relay(ctx, local, remote)
		}()
	}
}
func request(c net.Conn) (netip.AddrPort, error) {
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return netip.AddrPort{}, e
	}
	if h[0] != 5 || h[1] == 0 {
		return netip.AddrPort{}, errors.New("invalid greeting")
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return netip.AddrPort{}, e
	}
	noauth := false
	for _, m := range methods {
		noauth = noauth || m == 0
	}
	if !noauth {
		c.Write([]byte{5, 255})
		return netip.AddrPort{}, errors.New("unsupported authentication")
	}
	if _, e := c.Write([]byte{5, 0}); e != nil {
		return netip.AddrPort{}, e
	}
	var r [10]byte
	if _, e := io.ReadFull(c, r[:4]); e != nil {
		return netip.AddrPort{}, e
	}
	if r[0] != 5 || r[1] != 1 || r[2] != 0 || r[3] != 1 {
		return netip.AddrPort{}, errors.New("IPv4 TCP CONNECT required")
	}
	if _, e := io.ReadFull(c, r[4:]); e != nil {
		return netip.AddrPort{}, e
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{r[4], r[5], r[6], r[7]}), binary.BigEndian.Uint16(r[8:])), nil
}
