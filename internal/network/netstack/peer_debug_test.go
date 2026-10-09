package netstack

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
)

// The measurement peer runs inside nebula's service.Service, which builds its
// own gvisor stack in the unexported field Service.ipstack. Go cannot add a
// method to a type owned by another package, and neither nebula.Control,
// overlay.Device, nor gonet.TCPConn expose stack or sockopt introspection, so
// per-endpoint TCP state is unreachable for the peer.
//
// peerDebugTCP reports what this process does own instead: connection progress
// through the nebula listener, plus the kernel's TCP counters. The kernel
// counters still carry signal because the client and the peer share a network
// namespace, so the client's outer TCP connections are counted there.
//
// Output lines keep the [DEBUG-tcp-loss] prefix that TestResourceProfile scans
// for in the captured stderr logs.
var (
	peerAccepted atomic.Int64
	peerClosed   atomic.Int64
	peerBytesIn  atomic.Int64
	peerBytesOut atomic.Int64
)

type peerCountingConn struct {
	net.Conn
}

func (c *peerCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	peerBytesIn.Add(int64(n))
	return n, err
}

func (c *peerCountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	peerBytesOut.Add(int64(n))
	return n, err
}

func trackPeerConn(c net.Conn) net.Conn {
	peerAccepted.Add(1)
	return &peerCountingConn{Conn: c}
}

func peerConnDone() { peerClosed.Add(1) }

func peerDebugTCP() string {
	var out strings.Builder
	fmt.Fprintf(&out, "[DEBUG-tcp-loss] peer accepted=%d closed=%d active=%d bytesIn=%d bytesOut=%d\n",
		peerAccepted.Load(), peerClosed.Load(),
		peerAccepted.Load()-peerClosed.Load(),
		peerBytesIn.Load(), peerBytesOut.Load())
	tcp, tcpErr := procPairs("/proc/net/snmp", "Tcp")
	ext, extErr := procPairs("/proc/net/netstat", "TcpExt")
	if tcpErr != nil && extErr != nil {
		return out.String()
	}
	fmt.Fprintf(&out, "[DEBUG-tcp-loss] kernel retransSegs=%s outSegs=%s inSegs=%s inErrs=%s lostRetransmit=%s timeouts=%s fastRetrans=%s slowStartRetrans=%s\n",
		counter(tcp, "RetransSegs"), counter(tcp, "OutSegs"), counter(tcp, "InSegs"), counter(tcp, "InErrs"),
		counter(ext, "TCPLostRetransmit"), counter(ext, "TCPTimeouts"), counter(ext, "TCPFastRetrans"), counter(ext, "TCPSlowStartRetrans"))
	return out.String()
}

// counter returns the value for key, or "-" when the kernel build omits it.
func counter(values map[string]string, key string) string {
	if v, ok := values[key]; ok && v != "" {
		return v
	}
	return "-"
}

// procPairs parses the key/value map for one section of a /proc file. Both
// /proc/net/snmp and /proc/net/netstat are a header line followed by a value
// line that share the same "Section:" prefix, so the header supplies the keys
// and the next matching line supplies the values.
func procPairs(path, section string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	var keys []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != section+":" {
			continue
		}
		row := fields[1:]
		if keys == nil {
			keys = row
			continue
		}
		for i, key := range keys {
			if i < len(row) {
				values[key] = row[i]
			}
		}
		return values, nil
	}
	return values, nil
}
