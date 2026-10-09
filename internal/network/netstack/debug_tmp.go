package netstack

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"strings"
	"sync"
	"time"
)

var debugMu sync.Mutex

// tcpProbeState holds only the probe fields debugTCPStack reports. The full
// stack.TCPEndpointState embeds sync.NoCopy, so copying it into the map trips
// go vet's copylocks check; these primitives carry the same signal without it.
type tcpProbeState struct {
	sndBufUsed  int
	rcvBufUsed  int
	pendingUsed int
	rcvNxt      uint32
	sndNxt      uint32
	sndUna      uint32
	sndWnd      uint32
	outstanding int
	rackReord   bool
}

var debugStates = map[string]tcpProbeState{}

func captureProbe(p *stack.TCPEndpointState) tcpProbeState {
	return tcpProbeState{
		sndBufUsed:  p.SndBufState.SndBufUsed,
		rcvBufUsed:  p.RcvBufState.RcvBufUsed,
		pendingUsed: p.Receiver.PendingBufUsed,
		rcvNxt:      uint32(p.Receiver.RcvNxt),
		sndNxt:      uint32(p.Sender.SndNxt),
		sndUna:      uint32(p.Sender.SndUna),
		sndWnd:      uint32(p.Sender.SndWnd),
		outstanding: p.Sender.Outstanding,
		rackReord:   p.Sender.RACKState.Reord,
	}
}

func attachTCPProbe(s *stack.Stack) {
	s.AddTCPProbe(func(p *stack.TCPEndpointState) {
		debugMu.Lock()
		debugStates[fmt.Sprint(p.ID.LocalPort, "/", p.ID.RemotePort)] = captureProbe(p)
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
		if send <= 0 && receive == 0 && info.RTO < time.Second && p.sndBufUsed <= 0 && p.pendingUsed == 0 && p.sndNxt == p.sndUna {
			continue
		}
		fmt.Fprintf(&out, "[DEBUG-tcp-loss] probe port=%d->%d unacked=%d sentNext=%d ackedNext=%d sendUsed=%d receiveUsed=%d receiveNext=%d pending=%d wnd=%d outstanding=%d rackReord=%t\n", local.Port, remote.Port, p.sndNxt-p.sndUna, p.sndNxt, p.sndUna, p.sndBufUsed, p.rcvBufUsed, p.rcvNxt, p.pendingUsed, p.sndWnd, p.outstanding, p.rackReord)

		fmt.Fprintf(&out, "[DEBUG-tcp-loss] port=%d->%d send=%d receive=%d rto=%s state=%d cc=%d cwnd=%d rtt=%s\n", local.Port, remote.Port, send, receive, info.RTO, info.State, info.CcState, info.SndCwnd, info.RTT)
	}
	return out.String()
}
