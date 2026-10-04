// Packet plumbing adapted from slackhq/nebula/service (MIT; NEBULA_LICENSE).
package netstack

import (
	"bytes"
	"context"
	"errors"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/routing"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"sync"
)

type subnetRoute struct {
	prefix netip.Prefix
	via    routing.Gateways
}
type routedDevice struct {
	*overlay.UserDevice
	routes []subnetRoute
}

func newRoutedDevice(c *config.C, networks []netip.Prefix) (*routedDevice, error) {
	raw, err := overlay.NewUserDevice(networks)
	if err != nil {
		return nil, err
	}
	d := &routedDevice{UserDevice: raw.(*overlay.UserDevice)}
	fail := func() (*routedDevice, error) {
		d.Close()
		return nil, errors.New("unsupported private route configuration")
	}
	if v := c.Get("tun.unsafe_routes"); v != nil {
		entries, ok := v.([]any)
		if !ok {
			return fail()
		}
		for _, entry := range entries {
			m, ok := entry.(map[string]any)
			if !ok {
				return fail()
			}
			cidr, ok := m["route"].(string)
			if !ok {
				return fail()
			}
			via, ok := m["via"].(string)
			if !ok {
				return fail()
			}
			p, e := netip.ParsePrefix(cidr)
			if e != nil || !p.Addr().Is4() {
				return fail()
			}
			gateway, e := netip.ParseAddr(via)
			if e != nil || !gateway.Is4() {
				return fail()
			}
			contained := false
			for _, n := range networks {
				if n.Contains(gateway) {
					contained = true
				}
				if n.Contains(p.Addr()) {
					return fail()
				}
			}
			if !contained {
				return fail()
			}
			for _, r := range d.routes {
				if r.prefix == p.Masked() {
					return fail()
				}
			}
			gs := routing.Gateways{routing.NewGateway(gateway, 1)}
			routing.CalculateBucketsForGateways(gs)
			d.routes = append(d.routes, subnetRoute{p.Masked(), gs})
		}
	}
	return d, nil
}
func (d *routedDevice) RoutesFor(ip netip.Addr) routing.Gateways {
	for _, n := range d.Networks() {
		if n.Contains(ip) {
			g := routing.Gateways{routing.NewGateway(ip, 1)}
			routing.CalculateBucketsForGateways(g)
			return g
		}
	}
	best := -1
	var result routing.Gateways
	for _, r := range d.routes {
		if r.prefix.Contains(ip) && r.prefix.Bits() > best {
			best = r.prefix.Bits()
			result = r.via
		}
	}
	return result
}

// Network is an outbound IPv4 Nebula/gVisor userspace stack.
type Network struct {
	control *nebula.Control
	ipstack *stack.Stack
	reader  *io.PipeReader
	writer  *io.PipeWriter
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool
	config  *config.C
}

func newOutboundNetwork(control *nebula.Control, d *routedDevice) (*Network, error) {
	var address netip.Addr
	for _, p := range d.Networks() {
		if p.Addr().Is4() {
			address = p.Addr()
			break
		}
	}
	if !address.IsValid() {
		return nil, errors.New("IPv4 identity required")
	}
	s := &Network{control: control, ipstack: stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})}
	// Match Nebula service behavior: gVisor disables SACK by default.
	// Selective acknowledgements let parallel TCP streams recover packet loss
	// without waiting for one retransmission timeout per missing segment.
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		s.ipstack.Close()
		return nil, errors.New("netstack TCP recovery configuration failed")
	}
	link := channel.New(512, 1280, "")
	if e := s.ipstack.CreateNIC(1, link); e != nil {
		s.ipstack.Close()
		return nil, errors.New("netstack NIC failed")
	}
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFrom("\x00\x00\x00\x00"))
	s.ipstack.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})
	if e := s.ipstack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(address.As4()).WithPrefix()}, stack.AddressProperties{}); e != nil {
		s.ipstack.Close()
		return nil, errors.New("netstack address failed")
	}
	if e := control.Start(); e != nil {
		s.ipstack.Close()
		return nil, errors.New("overlay start failed")
	}
	ctx, cancel := context.WithCancel(control.Context())
	s.cancel = cancel
	s.reader, s.writer = d.Pipe()
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, header.IPv4MaximumHeaderSize+header.IPv4MaximumPayloadSize)
		for {
			n, e := s.reader.Read(buf)
			if e != nil {
				return
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(buf[:n]))})
			link.InjectInbound(ipv4.ProtocolNumber, packet)
			packet.DecRef()
		}
	}()
	go func() {
		defer s.wg.Done()
		for {
			packet := link.ReadContext(ctx)
			if packet == nil {
				return
			}
			v := packet.ToView()
			_, e := v.WriteTo(s.writer)
			v.Release()
			packet.DecRef()
			if e != nil {
				return
			}
		}
	}()
	return s, nil
}
func (s *Network) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("only TCP supported")
	}
	a, e := netip.ParseAddrPort(address)
	if e != nil || !a.Addr().Is4() || a.Port() == 0 {
		return nil, errors.New("numeric IPv4 destination required")
	}
	return gonet.DialContextTCP(ctx, s.ipstack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(a.Addr().As4()), Port: a.Port()}, ipv4.ProtocolNumber)
}
func (s *Network) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.cancel()
	s.reader.Close()
	s.writer.Close()
	s.control.Stop()
	s.ipstack.Close()
	s.wg.Wait()
	return nil
}

func start(data []byte) (*Network, error) {
	return startReloadable(data, nil)
}

func startReloadable(data []byte, loaded **config.C) (*Network, error) {
	var cfg config.C
	if err := cfg.LoadString(string(data)); err != nil {
		return nil, errors.New("invalid Nebula configuration")
	}
	if loaded != nil {
		*loaded = &cfg
	}
	// A config or upstream error can contain key material. Do not log it.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var device *routedDevice
	ctrl, err := nebula.Main(&cfg, false, "vojeto", logger, func(c *config.C, _ *slog.Logger, networks []netip.Prefix, _ int) (overlay.Device, error) {
		var e error
		device, e = newRoutedDevice(c, networks)
		return device, e
	})
	if err != nil {
		return nil, errors.New("Nebula initialization failed")
	}
	svc, err := newOutboundNetwork(ctrl, device)
	if err != nil {
		ctrl.Stop()
		return nil, errors.New("userspace service initialization failed")
	}
	svc.config = &cfg
	return svc, nil
}

// Open starts the rootless IPv4 overlay. Configuration is secret and errors are sanitized.
func Open(data []byte) (*Network, error) { return start(data) }
func (s *Network) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return s.DialContext(ctx, "tcp", dst.String())
}

// Resolve accepts numeric addresses only until an explicit overlay resolver is configured.
func (s *Network) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	a, e := netip.ParseAddr(name)
	if e != nil || !a.Is4() {
		return nil, errors.New("overlay resolver required for hostname")
	}
	return []netip.Addr{a}, nil
}
func reloadManagedConfig(current *config.C, data []byte, logger *slog.Logger) error {
	var next config.C
	if next.LoadString(string(data)) != nil {
		return errors.New("invalid configuration update")
	}
	if !reflect.DeepEqual(current.Get("tun.unsafe_routes"), next.Get("tun.unsafe_routes")) {
		return errors.New("route change requires review")
	}
	if _, err := nebula.NewPKIFromConfig(logger, &next); err != nil {
		return errors.New("invalid identity update")
	}
	return current.ReloadConfigString(string(data))
}

// Reload applies checkpointed identity configuration. Routes remain immutable.
func (s *Network) Reload(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("overlay stopped")
	}
	return reloadManagedConfig(s.config, data, slog.New(slog.NewTextHandler(io.Discard, nil)))
}
