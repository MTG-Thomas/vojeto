package netstack

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var debugMu sync.Mutex
var debugStates = map[string]stack.TCPEndpointState{}

func attachTCPProbe(s *stack.Stack) {
	s.AddTCPProbe(func(p *stack.TCPEndpointState) {
		debugMu.Lock()
		debugStates[fmt.Sprint(p.ID.LocalPort, "/", p.ID.RemotePort)] = *p
		debugMu.Unlock()
	})
}
func debugTCPStack(s *stack.Stack) string {
	var out strings.Builder
	st := s.Stats().TCP
	fmt.Fprintf(&out, "[DEBUG-tcp-loss] stack established=%d retransmits=%d timeouts=%d sacks=%d tails=%d invalid=%d resets=%d\n", st.CurrentEstablished.Value(), st.Retransmits.Value(), st.Timeouts.Value(), st.SACKRecovery.Value(), st.TLPRecovery.Value(), st.InvalidSegmentsReceived.Value(), st.ResetsSent.Value())
	for _, raw := range s.RegisteredEndpoints() {
		ep, ok := raw.(tcpip.Endpoint)
		if !ok {
			continue
		}
		var info tcpip.TCPInfoOption
		if ep.GetSockOpt(&info) != nil {
			continue
		}
		send, _ := ep.GetSockOptInt(tcpip.SendQueueSizeOption)
		receive, _ := ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
		local, _ := ep.GetLocalAddress()
		remote, _ := ep.GetRemoteAddress()
		debugMu.Lock()
		p := debugStates[fmt.Sprint(local.Port, "/", remote.Port)]
		debugMu.Unlock()
		if send <= 0 && receive == 0 && info.RTO < time.Second && p.SndBufState.SndBufUsed <= 0 && p.Receiver.PendingBufUsed == 0 && p.Sender.SndNxt == p.Sender.SndUna {
			continue
		}
		fmt.Fprintf(&out, "[DEBUG-tcp-loss] probe port=%d->%d unacked=%d sentNext=%d ackedNext=%d sendUsed=%d receiveUsed=%d receiveNext=%d pending=%d wnd=%d outstanding=%d rackReord=%t\n", local.Port, remote.Port, uint32(p.Sender.SndNxt-p.Sender.SndUna), uint32(p.Sender.SndNxt), uint32(p.Sender.SndUna), p.SndBufState.SndBufUsed, p.RcvBufState.RcvBufUsed, uint32(p.Receiver.RcvNxt), p.Receiver.PendingBufUsed, p.Sender.SndWnd, p.Sender.Outstanding, p.Sender.RACKState.Reord)

		fmt.Fprintf(&out, "[DEBUG-tcp-loss] port=%d->%d send=%d receive=%d rto=%s state=%d cc=%d cwnd=%d rtt=%s\n", local.Port, remote.Port, send, receive, info.RTO, info.State, info.CcState, info.SndCwnd, info.RTT)
	}
	return out.String()
}

func debugSignals(n *Network) {
	attachTCPProbe(n.ipstack)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case <-n.control.Context().Done():
				return
			case <-signals:
				fmt.Fprint(os.Stderr, debugTCPStack(n.ipstack))
			}
		}
	}()
}
