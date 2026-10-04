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

// Server implements runtime admission and bounded drain for a finite SOCKS job.
type Server struct {
	listener      net.Listener
	config        Config
	network       network.Network
	allowed       map[netip.AddrPort]bool
	global, local *forward.Limit
	ctx           context.Context
	cancel        context.CancelFunc
	stop          sync.Once
	sessions      sync.WaitGroup
	done          chan struct{}
	acceptErr     error
}

func policy(c Config) (map[netip.AddrPort]bool, error) {
	a, e := netip.ParseAddrPort(c.Listen)
	if e != nil || !a.Addr().IsLoopback() || len(c.Allow) == 0 || c.MaxConnections < 1 || c.DialTimeout <= 0 || c.Lifetime <= 0 {
		return nil, errors.New("invalid finite SOCKS policy")
	}
	allowed := map[netip.AddrPort]bool{}
	for _, d := range c.Allow {
		if !d.IsValid() || !d.Addr().Is4() || d.Port() == 0 {
			return nil, errors.New("invalid allowlist")
		}
		allowed[d] = true
	}
	return allowed, nil
}
func Validate(c Config) error { _, err := policy(c); return err }
func Open(ctx context.Context, n network.Network, c Config, global *forward.Limit) (*Server, error) {
	return open(ctx, n, c, global, net.Listen)
}
func open(ctx context.Context, n network.Network, c Config, global *forward.Limit, listen func(string, string) (net.Listener, error)) (*Server, error) {
	allowed, err := policy(c)
	if err != nil {
		return nil, err
	}
	if n == nil || global == nil {
		return nil, errors.New("missing SOCKS network or connection limit")
	}
	ln, err := listen("tcp", c.Listen)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.Lifetime)
	s := &Server{listener: ln, config: c, network: n, allowed: allowed, global: global, local: forward.NewLimit(c.MaxConnections), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go s.accept()
	return s, nil
}
func Serve(ctx context.Context, n network.Network, c Config) error {
	return serve(ctx, n, c, net.Listen)
}
func serve(ctx context.Context, n network.Network, c Config, listen func(string, string) (net.Listener, error)) error {
	// Preserve the blocking library API; Open is the runtime-managed alternative.
	if err := Validate(c); err != nil {
		return err
	}
	s, err := open(ctx, n, c, forward.NewLimit(c.MaxConnections), listen)
	if err != nil {
		return err
	}
	<-s.done
	s.cancel()
	s.sessions.Wait()
	return s.acceptErr
}
func (s *Server) Addr() net.Addr { return s.listener.Addr() }
func (s *Server) Active() int    { return s.local.Active() }

// Done closes when admission stops, including finite lifetime expiry.
func (s *Server) Done() <-chan struct{} { return s.done }
func (s *Server) StopAccepting()        { s.stop.Do(func() { s.listener.Close() }) }
func (s *Server) accept() {
	defer close(s.done)
	stop := context.AfterFunc(s.ctx, s.StopAccepting)
	defer stop()
	for {
		local, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.acceptErr = errors.New("SOCKS listener failed")
			}
			return
		}
		releaseGlobal, ok := s.global.Acquire()
		if !ok {
			local.Close()
			continue
		}
		releaseLocal, ok := s.local.Acquire()
		if !ok {
			releaseGlobal()
			local.Close()
			continue
		}
		s.sessions.Add(1)
		go func() {
			defer s.sessions.Done()
			defer releaseGlobal()
			defer releaseLocal()
			defer local.Close()
			stop := context.AfterFunc(s.ctx, func() { local.Close() })
			defer stop()
			local.SetDeadline(time.Now().Add(s.config.DialTimeout))
			dst, e := request(local)
			if e != nil || !s.allowed[dst] {
				local.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			// Handshake and overlay dial have separate bounded phases; retaining
			// the expired handshake deadline would prevent a failure reply.
			local.SetDeadline(time.Time{})
			dial, cancel := context.WithTimeout(s.ctx, s.config.DialTimeout)
			remote, e := s.network.DialTCP(dial, dst)
			cancel()
			local.SetWriteDeadline(time.Now().Add(s.config.DialTimeout))
			if e != nil {
				local.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer remote.Close()
			if _, e = local.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
				return
			}
			local.SetDeadline(time.Time{})
			forward.Relay(s.ctx, local, remote)
		}()
	}
}

// Drain preserves existing sessions until the bound, then cancels and joins all
// handshakes, dials and relays. No ownership release can precede this join.
func (s *Server) Drain(ctx context.Context) error {
	s.StopAccepting()
	<-s.done
	joined := make(chan struct{})
	go func() { s.sessions.Wait(); close(joined) }()
	select {
	case <-joined:
		s.cancel()
		return s.acceptErr
	case <-ctx.Done():
		s.cancel()
		<-joined
		return ctx.Err()
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
