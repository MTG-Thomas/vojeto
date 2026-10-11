package netstack

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// packetFaultProxy is a test-only UDP relay. It never decrypts overlay traffic.
// One held datagram bounds both memory and reorder delay; closing the socket
// interrupts the read and joins the worker before returning.
type packetFaultProxy struct {
	socket        *net.UDPConn
	target        *net.UDPAddr
	done          chan struct{}
	stop          sync.Once
	dropped       atomic.Uint64
	reordered     atomic.Uint64
	toPeerBytes   atomic.Uint64
	toClientBytes atomic.Uint64
}

func newPacketFaultProxy(target *net.UDPAddr, dropEvery, reorderEvery uint64, hold time.Duration) (*packetFaultProxy, error) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	p := &packetFaultProxy{socket: socket, target: target, done: make(chan struct{})}
	go p.run(dropEvery, reorderEvery, hold)
	return p, nil
}
func (p *packetFaultProxy) Close()          { p.stop.Do(func() { p.socket.Close(); <-p.done }) }
func (p *packetFaultProxy) address() string { return p.socket.LocalAddr().String() }
func (p *packetFaultProxy) run(dropEvery, reorderEvery uint64, hold time.Duration) {
	defer close(p.done)
	buffer := make([]byte, 65535)
	var client, heldTarget *net.UDPAddr
	var held []byte
	var deadline time.Time
	var sequence uint64
	send := func(data []byte, dst *net.UDPAddr) {
		if n, err := p.socket.WriteToUDP(data, dst); err == nil {
			if dst.AddrPort() == p.target.AddrPort() {
				p.toPeerBytes.Add(uint64(n))
			} else {
				p.toClientBytes.Add(uint64(n))
			}
		}
	}
	flush := func() {
		if held != nil {
			send(held, heldTarget)
			held = nil
			deadline = time.Time{}
		}
	}
	for {
		p.socket.SetReadDeadline(deadline)
		n, from, err := p.socket.ReadFromUDP(buffer)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				flush()
				continue
			}
			return
		}
		// Check the fixed deadline even under continuous traffic in the other
		// direction. Updating it per packet could indefinitely strand the held one.
		if held != nil && !time.Now().Before(deadline) {
			flush()
		}
		dst := p.target
		if from.Port == p.target.Port && from.IP.Equal(p.target.IP) {
			if client == nil {
				continue
			}
			dst = client
		} else {
			client = from
		}
		sequence++
		if dropEvery != 0 && sequence%dropEvery == 0 {
			p.dropped.Add(1)
			continue
		}
		if held != nil && heldTarget.AddrPort() == dst.AddrPort() {
			send(buffer[:n], dst)
			flush()
			p.reordered.Add(1)
			continue
		}
		if held == nil && reorderEvery != 0 && sequence%reorderEvery == 0 {
			held = append([]byte(nil), buffer[:n]...)
			heldTarget = dst
			deadline = time.Now().Add(hold)
			continue
		}
		send(buffer[:n], dst)
	}
}

func TestPacketFaultProxy(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	p, err := newPacketFaultProxy(peer.LocalAddr().(*net.UDPAddr), 3, 2, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	client, err := net.Dial("udp", p.address())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	receive := func(c net.Conn, want string) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 16)
		n, err := c.Read(b)
		if err != nil || !bytes.Equal(b[:n], []byte(want)) {
			t.Fatalf("datagram = %q, want %q, error %v", b[:n], want, err)
		}
	}
	client.Write([]byte("A"))
	receive(peer, "A")
	client.Write([]byte("B"))
	client.Write([]byte("C"))
	client.Write([]byte("D"))
	receive(peer, "D")
	receive(peer, "B")
	peer.WriteToUDP([]byte("reply"), p.socket.LocalAddr().(*net.UDPAddr))
	receive(client, "reply")
	if p.dropped.Load() != 1 || p.reordered.Load() != 1 {
		t.Fatalf("fault counts: drop %d reorder %d", p.dropped.Load(), p.reordered.Load())
	}
	// Packet 6 is dropped, 7 forwarded, 8 held until its fixed timeout.
	client.Write([]byte("E"))
	client.Write([]byte("F"))
	receive(peer, "F")
	client.Write([]byte("G"))
	receive(peer, "G")
	p.Close()
	p.Close()
	select {
	case <-p.done:
	default:
		t.Fatal("relay worker survived Close")
	}
}
