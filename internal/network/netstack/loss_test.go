package netstack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Faults occur in both directions after TCP negotiation. Every test uses the
// production stack configuration and keeps connections open during the reply,
// so a FIN cannot hide a lost final response. No kernel fault injection is used.
func TestTCPRecoversPacketLoss(t *testing.T) {
	for _, mode := range []string{"periodic", "burst", "tail", "reorder"} {
		t.Run(mode, func(t *testing.T) { testTCPFault(t, mode) })
	}
}
func testTCPFault(t *testing.T, mode string) {
	const payloadBytes = 1050000
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	create := func(ip [4]byte) (*stack.Stack, *channel.Endpoint) {
		s, e := newTCPStack()
		if e != nil {
			t.Fatal(e)
		}
		link := channel.New(512, 1280, "")
		if e := s.CreateNIC(1, link); e != nil {
			s.Close()
			t.Fatal(e)
		}
		if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(ip).WithPrefix()}, stack.AddressProperties{}); e != nil {
			s.Close()
			t.Fatal(e)
		}
		subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFrom("\x00\x00\x00\x00"))
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})
		return s, link
	}
	client, cl := create([4]byte{192, 0, 2, 2})
	defer client.Close()
	server, sl := create([4]byte{192, 0, 2, 1})
	defer server.Close()
	var pumps sync.WaitGroup
	var drops, reorders atomic.Int64
	inject := func(to *channel.Endpoint, data []byte) {
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		to.InjectInbound(ipv4.ProtocolNumber, p)
		p.DecRef()
	}
	pump := func(from, to *channel.Endpoint) {
		defer pumps.Done()
		bases := map[string]uint32{}
		dropped := map[string]bool{}
		count := 0
		var held []byte
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
			flow := fmt.Sprint(th.SourcePort(), "/", th.DestinationPort())
			if th.Flags()&header.TCPFlagSyn != 0 {
				bases[flow] = th.SequenceNumber() + 1
			}
			drop := false
			if payload > 0 {
				count++
				switch mode {
				case "periodic":
					drop = count%101 == 0
				case "burst":
					drop = count >= 100 && count <= 120
				case "tail":
					if uint32(th.SequenceNumber()-bases[flow])+uint32(payload) >= payloadBytes-2400 {
						key := flow + "/" + fmt.Sprint(th.SequenceNumber())
						if !dropped[key] {
							dropped[key] = true
							drop = true
						}
					}
				case "reorder":
					if count == 100 {
						held = data
						continue
					}
				}
			}
			if drop {
				drops.Add(1)
				continue
			}
			inject(to, data)
			if held != nil && payload > 0 {
				inject(to, held)
				held = nil
				reorders.Add(1)
			}
		}
	}
	pumps.Add(2)
	go pump(cl, sl)
	go pump(sl, cl)
	ln, e := gonet.ListenTCP(server, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 19001}, ipv4.ProtocolNumber)
	if e != nil {
		cancel()
		pumps.Wait()
		t.Fatal(e)
	}
	var echo sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			echo.Add(1)
			go func(c net.Conn) {
				defer echo.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				io.Copy(c, c)
			}(c)
		}
	}()
	defer func() { cancel(); ln.Close(); <-accepted; echo.Wait(); pumps.Wait() }()
	var wg sync.WaitGroup
	failures := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 19001}, ipv4.ProtocolNumber)
			if e != nil {
				failures <- e
				return
			}
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			payload := bytes.Repeat([]byte("loss-regression"), 70000)
			write := make(chan error, 1)
			go func() { _, e := c.Write(payload); write <- e }()
			got := make([]byte, len(payload))
			n, e := io.ReadFull(c, got)
			if e != nil {
				c.Close()
			}
			werr := <-write
			if e != nil {
				failures <- fmt.Errorf("received %d/%d bytes: %w", n, len(payload), e)
			} else if werr != nil {
				failures <- werr
			} else if !bytes.Equal(got, payload) {
				failures <- io.ErrUnexpectedEOF
			}
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Error(e)
	}
	stats := client.Stats().TCP
	peer := server.Stats().TCP
	t.Logf("drops=%d reorders=%d retransmits=%d timeouts=%d SACK recoveries=%d", drops.Load(), reorders.Load(), stats.Retransmits.Value()+peer.Retransmits.Value(), stats.Timeouts.Value()+peer.Timeouts.Value(), stats.SACKRecovery.Value()+peer.SACKRecovery.Value())
	if mode == "reorder" {
		if reorders.Load() != 2 {
			t.Fatal("reorder fault was not exercised")
		}
	} else if drops.Load() == 0 || stats.Retransmits.Value()+peer.Retransmits.Value() == 0 {
		t.Fatal("loss recovery was not exercised")
	}
}
