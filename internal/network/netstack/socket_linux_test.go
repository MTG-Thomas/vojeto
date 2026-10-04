//go:build linux

package netstack

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/udp"
)

func TestRootlessSocketBufferConfiguration(t *testing.T) {
	conn, err := udp.NewListener(slog.New(slog.NewTextHandler(io.Discard, nil)), netip.MustParseAddr("127.0.0.1"), 0, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	socket := conn.(*udp.StdConn)
	if err = socket.SetRecvBuffer(16 << 10); err != nil {
		t.Fatalf("receive buffer configuration requires privilege: %v", err)
	}
	if err = socket.SetSendBuffer(16 << 10); err != nil {
		t.Fatalf("send buffer configuration requires privilege: %v", err)
	}
	receive, err := socket.GetRecvBuffer()
	if err != nil || receive <= 0 {
		t.Fatal("receive buffer", receive, err)
	}
	send, err := socket.GetSendBuffer()
	if err != nil || send <= 0 {
		t.Fatal("send buffer", send, err)
	}
	t.Logf("effective socket buffers: receive=%d send=%d", receive, send)
}
