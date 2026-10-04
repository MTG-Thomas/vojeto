package netstack

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Lose a full segment, then advertise a smaller nonzero window. Recovery must
// transmit within that window rather than wait indefinitely for a larger one.
func TestRetransmissionFitsSmallNonzeroWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	create := func(ip [4]byte) (*stack.Stack, *channel.Endpoint) {
		s, err := newTCPStack()
		if err != nil {
			t.Fatal(err)
		}
		link := channel.New(512, 1280, "")
		if err := s.CreateNIC(1, link); err != nil {
			s.Close()
			t.Fatal(err)
		}
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(ip).WithPrefix()}, stack.AddressProperties{}); err != nil {
			s.Close()
			t.Fatal(err)
		}
		subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFrom("\x00\x00\x00\x00"))
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})
		return s, link
	}
	client, cl := create([4]byte{192, 0, 2, 2})
	defer client.Close()
	server, sl := create([4]byte{192, 0, 2, 1})
	defer server.Close()
	lost := make(chan struct{})
	var dropped atomic.Bool
	var originalSize, smallPackets atomic.Int64
	var pumps sync.WaitGroup
	pump := func(from, to *channel.Endpoint, fromServer bool) {
		defer pumps.Done()
		scale := 0
		for {
			p := from.ReadContext(ctx)
			if p == nil {
				return
			}
			v := p.ToView()
			data := bytes.Clone(v.AsSlice())
			v.Release()
			p.DecRef()
			ip := header.IPv4(data)
			off := int(ip.HeaderLength())
			th := header.TCP(data[off:])
			payload := len(data) - off - int(th.DataOffset())
			if fromServer {
				if th.Flags()&header.TCPFlagSyn != 0 {
					scale = header.ParseSynOptions(th.Options(), true).WS
					if scale < 0 {
						scale = 0
					}
				}
				if th.Flags()&header.TCPFlagSyn == 0 && dropped.Load() {
					th.SetWindowSize(uint16(1152 >> scale))
					th.SetChecksum(0)
					pseudo := header.PseudoHeaderChecksum(tcp.ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(data)-off))
					th.SetChecksum(^checksum.Checksum(data[off:], pseudo))
				}
			} else if payload > 0 {
				if dropped.CompareAndSwap(false, true) {
					originalSize.Store(int64(payload))
					close(lost)
					continue
				}
				if payload <= 1152 {
					smallPackets.Add(1)
				}
			}
			incoming := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			to.InjectInbound(ipv4.ProtocolNumber, incoming)
			incoming.DecRef()
		}
	}
	pumps.Add(2)
	go pump(cl, sl, false)
	go pump(sl, cl, true)
	ln, err := gonet.ListenTCP(server, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 19001}, ipv4.ProtocolNumber)
	if err != nil {
		cancel()
		pumps.Wait()
		t.Fatal(err)
	}
	echoed := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			echoed <- err
			return
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		select {
		case <-lost:
		case <-ctx.Done():
			echoed <- ctx.Err()
			return
		}
		if _, err = io.WriteString(c, "!"); err != nil {
			echoed <- err
			return
		}
		data := make([]byte, 1200)
		if _, err = io.ReadFull(c, data); err == nil {
			_, err = c.Write(data)
		}
		echoed <- err
	}()
	defer func() { cancel(); ln.Close(); pumps.Wait() }()
	c, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 19001}, ipv4.ProtocolNumber)
	if err != nil {
		cancel()
		ln.Close()
		<-echoed
		t.Fatal(err)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("w"), 1200)
	if _, err = c.Write(payload); err != nil {
		cancel()
		<-echoed
		t.Fatal(err)
	}
	got := make([]byte, 1201)
	_, err = io.ReadFull(c, got)
	if err != nil {
		cancel()
	}
	remoteErr := <-echoed
	if err != nil || remoteErr != nil {
		t.Fatalf("small-window recovery failed: client=%v remote=%v original=%d smallPackets=%d timeouts=%d", err, remoteErr, originalSize.Load(), smallPackets.Load(), client.Stats().TCP.Timeouts.Value())
	}
	if got[0] != '!' || !bytes.Equal(got[1:], payload) {
		t.Fatal("corrupted bytes")
	}
	if originalSize.Load() <= 1152 || smallPackets.Load() == 0 || client.Stats().TCP.Retransmits.Value() == 0 {
		t.Fatal("small-window retransmission was not exercised")
	}
}
