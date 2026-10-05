// vojeto-peer exposes finite operator, target and optional lighthouse roles.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MTG-Thomas/vojeto/peer"
)

func read(path string, dst any) error {
	f, e := os.Open(path)
	if e != nil {
		return peer.ErrRejected
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if e != nil || len(b) > 64<<10 {
		return peer.ErrRejected
	}
	defer clear(b)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return peer.ErrRejected
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return peer.ErrRejected
	}
	return nil
}
func write(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return peer.ErrRejected
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return peer.ErrRejected
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		os.Remove(path)
		return peer.ErrRejected
	}
	return nil
}
func run(args []string) error {
	if len(args) < 1 {
		return errors.New("expected keygen, issue, operator, target or lighthouse")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	switch args[0] {
	case "keygen":
		dir := fs.String("out", "", "new private directory for public.json and private.json")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *dir == "" {
			return peer.ErrRejected
		}
		pub, priv, e := peer.Keygen()
		if e != nil {
			return e
		}
		defer clear(priv)
		if mkdirPrivate(*dir) != nil {
			return peer.ErrRejected
		}
		success := false
		defer func() {
			if !success {
				os.RemoveAll(*dir)
			}
		}()
		if e = write(filepath.Join(*dir, "private.json"), priv); e != nil {
			return e
		}
		if e = write(filepath.Join(*dir, "public.json"), pub); e != nil {
			return e
		}
		success = true
	case "issue":
		op := fs.String("operator-key", "", "operator public.json")
		target := fs.String("target-key", "", "target public.json")
		lh := fs.String("lighthouse-key", "", "optional lighthouse public.json")
		destination := fs.String("destination", "", "approved numeric IPv4 TCP host:port")
		endpoint := fs.String("target-endpoint", "", "reachable target UDP IP:port")
		lhEndpoint := fs.String("lighthouse-endpoint", "", "optional reachable lighthouse UDP IP:port")
		ttl := fs.Duration("ttl", 5*time.Minute, "session lifetime, at most 30m")
		dir := fs.String("out", "", "new directory for public signed grants")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *dir == "" {
			return peer.ErrRejected
		}
		r := peer.Request{Target: *destination, TargetEndpoint: *endpoint, LighthouseEndpoint: *lhEndpoint, Lifetime: *ttl}
		if read(*op, &r.OperatorKey) != nil || read(*target, &r.TargetKey) != nil {
			return peer.ErrRejected
		}
		if *lh != "" && read(*lh, &r.LighthouseKey) != nil {
			return peer.ErrRejected
		}
		grants, e := peer.Issue(r)
		if e != nil {
			return e
		}
		if mkdirPrivate(*dir) != nil {
			return peer.ErrRejected
		}
		success := false
		defer func() {
			if !success {
				os.RemoveAll(*dir)
			}
		}()
		for role, g := range grants {
			if write(filepath.Join(*dir, role+".json"), g) != nil {
				return peer.ErrRejected
			}
		}
		success = true
	case "operator", "target", "lighthouse":
		grant := fs.String("grant", "", "signed role grant from authenticated issuer")
		key := fs.String("key", "", "locally generated private.json")
		listen := fs.String("listen", "127.0.0.1:0", "operator loopback TCP address")
		udp := fs.String("udp-listen", "0.0.0.0:0", "local UDP bind; target/lighthouse need a known reachable port")
		maximum := fs.Int("max-connections", 16, "connection ceiling, 1..128")
		dial := fs.Duration("dial-timeout", 5*time.Second, "bounded target dial")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
			return peer.ErrRejected
		}
		var g peer.Grant
		var private []byte
		if read(*grant, &g) != nil || read(*key, &private) != nil {
			return peer.ErrRejected
		}
		defer clear(private)
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return peer.Run(ctx, g, private, args[0], peer.Options{UDPListen: *udp, Listen: *listen, MaxConnections: *maximum, DialTimeout: *dial, OnListening: func(a net.Addr) {
			_ = json.NewEncoder(os.Stdout).Encode(struct {
				Event   string `json:"event"`
				Address string `json:"address"`
			}{"listening", a.String()})
		}})
	default:
		return peer.ErrRejected
	}
	return nil
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "vojeto-peer rejected request; inspect inputs privately")
		os.Exit(1)
	}
}
