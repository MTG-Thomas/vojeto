//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MTG-Thomas/vojeto/launcher"
)

type config struct {
	PeerBinary        string `json:"peerBinary"`
	RunDir            string `json:"runDir"`
	Listen            string `json:"listen"`
	PublicIP          string `json:"publicIP"`
	BindIP            string `json:"bindIP"`
	FirstPort         uint16 `json:"firstPort"`
	LastPort          uint16 `json:"lastPort"`
	MaxSessions       int    `json:"maxSessions"`
	StateDir          string `json:"stateDir"`
	Certificate       string `json:"certificate"`
	Key               string `json:"key"`
	ClientCA          string `json:"clientCA"`
	BrokerFingerprint string `json:"brokerFingerprint"`
}

func run() error {
	if len(os.Args) != 2 {
		return launcher.ErrInvalid
	}
	f, e := os.Open(os.Args[1])
	if e != nil {
		return launcher.ErrInvalid
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(data) > 16384 {
		return launcher.ErrInvalid
	}
	defer clear(data)
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var c config
	if d.Decode(&c) != nil {
		return launcher.ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return launcher.ErrInvalid
	}
	listen, e := netip.ParseAddrPort(c.Listen)
	if e != nil || listen.Port() < 1024 {
		return launcher.ErrInvalid
	}
	certificate, e := tls.LoadX509KeyPair(c.Certificate, c.Key)
	if e != nil {
		return launcher.ErrInvalid
	}
	pem, e := os.ReadFile(c.ClientCA)
	if e != nil {
		return launcher.ErrInvalid
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(pem) {
		return launcher.ErrInvalid
	}
	tlsConfig, e := launcher.TLS(certificate, ca, c.BrokerFingerprint)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	publicIP, e := netip.ParseAddr(c.PublicIP)
	if e != nil {
		return launcher.ErrInvalid
	}
	bindIP, e := netip.ParseAddr(c.BindIP)
	if e != nil {
		return launcher.ErrInvalid
	}
	m, e := launcher.Open(ctx, launcher.Config{PeerBinary: c.PeerBinary, RunDir: c.RunDir, PublicIP: publicIP, BindIP: bindIP, FirstPort: c.FirstPort, LastPort: c.LastPort, MaxSessions: c.MaxSessions, StateDir: c.StateDir})
	if e != nil {
		return e
	}
	defer m.Close()
	ln, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return launcher.ErrUnavailable
	}
	defer ln.Close()
	server := &http.Server{Handler: launcher.Handler(m), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(ln, tlsConfig)) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case e := <-done:
		return e
	}
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "launcher failed; inspect configuration privately")
		os.Exit(1)
	}
}
