// Package health verifies configured dependencies through the overlay only.
package health

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/network"
)

type Probe struct {
	RootCAs    *x509.CertPool `json:"-"`
	Target     string         `json:"target"`
	Protocol   string         `json:"protocol"` // tcp, tls, or postgres-tls
	ServerName string         `json:"server_name,omitempty"`
}

func (p Probe) Validate() error {
	h, port, err := net.SplitHostPort(p.Target)
	n, pe := strconv.Atoi(port)
	if err != nil || h == "" || pe != nil || n < 1 || n > 65535 {
		return errors.New("invalid probe target")
	}
	switch p.Protocol {
	case "tcp":
		if p.ServerName != "" {
			return errors.New("TCP probe cannot verify TLS")
		}
	case "tls", "postgres-tls":
		if p.ServerName == "" {
			return errors.New("TLS probe requires original server name")
		}
	default:
		return errors.New("unsupported probe protocol")
	}
	return nil
}

// Check authenticates TLS without terminating application TLS or exposing its
// credentials. The caller must provide a bounded context.
func (p Probe) Check(ctx context.Context, n network.Network) error {
	if err := p.Validate(); err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(p.Target)
	number, _ := strconv.Atoi(port)
	addresses, err := n.Resolve(ctx, host)
	if err != nil {
		return errors.New("probe resolution failed")
	}
	for _, addr := range addresses {
		conn, err := n.DialTCP(ctx, netip.AddrPortFrom(addr, uint16(number)))
		if err != nil {
			continue
		}
		err = p.checkConn(ctx, conn)
		conn.Close()
		if err == nil {
			return nil
		}
	}
	return errors.New("dependency probe failed")
}
func (p Probe) checkConn(ctx context.Context, conn net.Conn) error {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		return errors.New("probe deadline required")
	}
	if p.Protocol == "tcp" {
		return ctx.Err()
	}
	if p.Protocol == "postgres-tls" {
		var request [8]byte
		binary.BigEndian.PutUint32(request[:4], 8)
		binary.BigEndian.PutUint32(request[4:], 80877103)
		if _, err := io.Copy(conn, bytes.NewReader(request[:])); err != nil {
			return err
		}
		var response [1]byte
		if _, err := io.ReadFull(conn, response[:]); err != nil || response[0] != 'S' {
			return errors.New("PostgreSQL TLS required")
		}
	}
	secured := tls.Client(conn, &tls.Config{ServerName: p.ServerName, RootCAs: p.RootCAs, MinVersion: tls.VersionTLS12})
	return secured.HandshakeContext(ctx)
}

// CheckAll gives each probe a finite budget. No destination details or errors are
// returned through public status; a failure keeps readiness false.
func CheckAll(ctx context.Context, n network.Network, probes []Probe, timeout time.Duration) bool {
	for _, p := range probes {
		bounded, cancel := context.WithTimeout(ctx, timeout)
		err := p.Check(bounded, n)
		cancel()
		if err != nil {
			return false
		}
	}
	return ctx.Err() == nil
}
