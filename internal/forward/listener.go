// Package forward owns bounded loopback listeners and TCP session cleanup.
package forward

import (
	"context"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type Config struct {
	Name, Listen, Target string
	MaxConnections       int
	DialTimeout          time.Duration
}
type Limit struct{ slots chan struct{} }

func NewLimit(n int) *Limit {
	if n < 1 {
		panic("positive connection limit required")
	}
	return &Limit{make(chan struct{}, n)}
}
func (l *Limit) take() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (l *Limit) release()    { <-l.slots }
func (l *Limit) Active() int { return len(l.slots) }

type Listener struct {
	listener      net.Listener
	config        Config
	network       network.Network
	global, local *Limit
	sessions      sync.WaitGroup
	stop          sync.Once
	done          chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
}

func Open(ctx context.Context, n network.Network, c Config, global *Limit) (*Listener, error) {
	a, e := netip.ParseAddrPort(c.Listen)
	if e != nil || !a.Addr().IsLoopback() {
		return nil, errors.New("explicit loopback listener required")
	}
	h, p, e := net.SplitHostPort(c.Target)
	port, pe := strconv.Atoi(p)
	if e != nil || h == "" || pe != nil || port < 1 || port > 65535 || c.Name == "" || c.MaxConnections < 1 || c.DialTimeout <= 0 || global == nil {
		return nil, errors.New("invalid forward configuration")
	}
	ln, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return nil, e
	}
	use, cancel := context.WithCancel(ctx)
	l := &Listener{listener: ln, config: c, network: n, global: global, local: NewLimit(c.MaxConnections), done: make(chan struct{}), ctx: use, cancel: cancel}
	go l.accept()
	return l, nil
}
func (l *Listener) Addr() net.Addr { return l.listener.Addr() }
func (l *Listener) Active() int    { return l.local.Active() }
func (l *Listener) StopAccepting() { l.stop.Do(func() { l.listener.Close() }) }
func (l *Listener) accept() {
	defer close(l.done)
	stop := context.AfterFunc(l.ctx, l.StopAccepting)
	defer stop()
	for {
		c, e := l.listener.Accept()
		if e != nil {
			return
		}
		if !l.global.take() {
			c.Close()
			continue
		}
		if !l.local.take() {
			l.global.release()
			c.Close()
			continue
		}
		l.sessions.Add(1)
		go func() {
			defer l.sessions.Done()
			defer l.global.release()
			defer l.local.release()
			defer c.Close()
			ctx, cancel := context.WithTimeout(l.ctx, l.config.DialTimeout)
			h, p, _ := net.SplitHostPort(l.config.Target)
			port, _ := strconv.Atoi(p)
			addresses, e := l.network.Resolve(ctx, h)
			var remote net.Conn
			if e == nil {
				for _, a := range addresses {
					remote, e = l.network.DialTCP(ctx, netip.AddrPortFrom(a, uint16(port)))
					if e == nil {
						break
					}
				}
			}
			cancel()
			if remote == nil {
				return
			}
			Relay(l.ctx, c, remote)
		}()
	}
}

// Drain rejects admission, allows existing sessions to finish, then cancels and joins them.
func (l *Listener) Drain(ctx context.Context) error {
	l.StopAccepting()
	<-l.done
	finished := make(chan struct{})
	go func() { l.sessions.Wait(); close(finished) }()
	select {
	case <-finished:
		l.cancel()
		return nil
	case <-ctx.Done():
		l.cancel()
		<-finished
		return ctx.Err()
	}
}

// Relay preserves TCP half-close in both directions. Cancellation closes both endpoints.
func Relay(ctx context.Context, a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	var wg sync.WaitGroup
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, e := io.Copy(dst, src)
		if e != nil {
			a.Close()
			b.Close()
			return
		}
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go copyOne(a, b)
	copyOne(b, a)
	wg.Wait()
}
