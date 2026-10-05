package peer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/network/netstack"
	"go.yaml.in/yaml/v3"
)

// Options are local bind choices. Destination authorization comes only from Grant.
// OnListening reports local startup, not verified peer reachability. Cancel the
// caller context to revoke a running session; cancellation closes active traffic.
type Options struct {
	UDPListen      string
	Listen         string
	MaxConnections int
	DialTimeout    time.Duration
	OnListening    func(net.Addr)
}

func configuration(g Grant, private []byte, listen netip.AddrPort) ([]byte, error) {
	hosts := []string{}
	static := map[string][]string{}
	if g.TargetEndpoint != "" && g.Role != "target" {
		static[address("target").String()] = []string{g.TargetEndpoint}
	}
	relays := []string{}
	if g.LighthouseEndpoint != "" && g.Role != "lighthouse" {
		hosts = []string{address("lighthouse").String()}
		static[address("lighthouse").String()] = []string{g.LighthouseEndpoint}
		relays = hosts
	}
	inbound, outbound := []map[string]any{}, []map[string]any{}
	rule := func(role string) map[string]any {
		return map[string]any{"port": servicePort, "proto": "tcp", "host": g.ID + "/" + role}
	}
	if g.Role == "target" {
		inbound = append(inbound, rule("operator"))
	}
	if g.Role == "operator" {
		outbound = append(outbound, rule("target"))
	}
	cfg := map[string]any{
		"pki":             map[string]any{"ca": g.CA, "cert": g.Certificate, "key": string(private)},
		"listen":          map[string]any{"host": listen.Addr().String(), "port": listen.Port()},
		"lighthouse":      map[string]any{"am_lighthouse": g.Role == "lighthouse", "hosts": hosts},
		"static_host_map": static,
		"punchy":          map[string]any{"punch": true, "respond": true},
		"relay":           map[string]any{"am_relay": g.Role == "lighthouse", "use_relays": g.Role != "lighthouse", "relays": relays},
		"firewall":        map[string]any{"inbound": inbound, "outbound": outbound},
	}
	b, e := yaml.Marshal(cfg)
	if e != nil {
		return nil, ErrRejected
	}
	return b, nil
}

// Run executes one immutable session. It never renews a grant or retries after
// expiry. Lighthouse is an optional third infrastructure role in this same
// trust domain; it exposes no application listeners or host routing.
func Run(parent context.Context, g Grant, private []byte, role string, o Options) error {
	if e := Validate(g, private, role); e != nil {
		return e
	}
	udp, e := netip.ParseAddrPort(o.UDPListen)
	if e != nil || !udp.Addr().Is4() || role == "lighthouse" && udp.Port() == 0 {
		return ErrRejected
	}
	if role != "lighthouse" && (o.MaxConnections < 1 || o.MaxConnections > 128 || o.DialTimeout <= 0 || o.DialTimeout > 30*time.Second) {
		return ErrRejected
	}
	if role == "operator" {
		a, e := netip.ParseAddrPort(o.Listen)
		if e != nil || !a.Addr().IsLoopback() {
			return ErrRejected
		}
	}
	ctx, cancel := context.WithDeadline(parent, g.Expires)
	defer cancel()
	if ctx.Err() != nil {
		return ErrRejected
	}
	config, e := configuration(g, private, udp)
	if e != nil {
		return e
	}
	defer clear(config)
	n, e := netstack.Open(config)
	if e != nil {
		return ErrRejected
	}
	defer n.Close()
	if ctx.Err() != nil {
		return ErrRejected
	}
	switch role {
	case "operator":
		l, e := forward.Open(ctx, n, forward.Config{Name: g.ID, Listen: o.Listen, Target: netip.AddrPortFrom(address("target"), servicePort).String(), MaxConnections: o.MaxConnections, DialTimeout: o.DialTimeout}, forward.NewLimit(o.MaxConnections))
		if e != nil {
			return ErrRejected
		}
		if o.OnListening != nil {
			o.OnListening(l.Addr())
		}
		<-ctx.Done()
		// Expiry/revocation cancels relays immediately; drain joins their cleanup.
		drain, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if e = l.Drain(drain); e != nil && !errors.Is(e, context.DeadlineExceeded) {
			return ErrRejected
		}
	case "target":
		ln, e := n.ListenTCP(netip.AddrPortFrom(address("target"), servicePort))
		if e != nil {
			return ErrRejected
		}
		done := serveGateway(ctx, ln, g.Target, o.MaxConnections, o.DialTimeout)
		if o.OnListening != nil {
			o.OnListening(ln.Addr())
		}
		<-ctx.Done()
		<-done
	case "lighthouse":
		if udp.Port() == 0 {
			return ErrRejected
		}
		if o.OnListening != nil {
			o.OnListening(net.UDPAddrFromAddrPort(udp))
		}
		<-ctx.Done()
	default:
		return ErrRejected
	}
	return nil
}

// serveGateway has exactly one signed numeric destination. An operator cannot
// send a destination request, obtain a shell, or turn this into an open proxy.
func serveGateway(ctx context.Context, ln net.Listener, destination string, maximum int, timeout time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ln.Close()
		stop := context.AfterFunc(ctx, func() { ln.Close() })
		defer stop()
		slots := make(chan struct{}, maximum)
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				c.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				defer c.Close()
				dial, cancel := context.WithTimeout(ctx, timeout)
				remote, e := (&net.Dialer{}).DialContext(dial, "tcp4", destination)
				cancel()
				if e != nil {
					return
				}
				forward.Relay(ctx, c, remote)
			}()
		}
	}()
	return done
}
