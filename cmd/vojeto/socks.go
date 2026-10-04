package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/forward"
	"github.com/MTG-Thomas/vojeto/internal/proxy/socks5"
)

type socksSettings struct {
	Listen         string   `json:"listen"`
	Allow          []string `json:"allow"`
	MaxConnections int      `json:"maxConnections"`
	DialTimeout    string   `json:"dialTimeout"`
	Lifetime       string   `json:"lifetime"`
}

func loadSessions(forwardsPath, socksPath string) ([]forward.Config, *socks5.Config, error) {
	if (forwardsPath == "") == (socksPath == "") {
		return nil, nil, errors.New("configure exactly one of forwards or finite SOCKS")
	}
	if forwardsPath != "" {
		data, err := os.ReadFile(forwardsPath)
		var entries []forward.Config
		if err != nil || json.Unmarshal(data, &entries) != nil || len(entries) == 0 {
			return nil, nil, errors.New("invalid forwards")
		}
		return entries, nil, nil
	}
	reject := func() ([]forward.Config, *socks5.Config, error) {
		return nil, nil, errors.New("invalid finite SOCKS configuration")
	}
	file, err := os.Open(socksPath)
	if err != nil {
		return reject()
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return reject()
	}
	var settings socksSettings
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&settings) != nil || decoder.Decode(new(any)) != io.EOF || len(settings.Allow) > 1024 {
		return reject()
	}
	dial, err := time.ParseDuration(settings.DialTimeout)
	if err != nil {
		return reject()
	}
	lifetime, err := time.ParseDuration(settings.Lifetime)
	if err != nil {
		return reject()
	}
	config := &socks5.Config{Listen: settings.Listen, MaxConnections: settings.MaxConnections, DialTimeout: dial, Lifetime: lifetime}
	for _, raw := range settings.Allow {
		dst, err := netip.ParseAddrPort(raw)
		if err != nil {
			return reject()
		}
		config.Allow = append(config.Allow, dst)
	}
	if socks5.Validate(*config) != nil {
		return reject()
	}
	return nil, config, nil
}

func openSocksSession(ctx context.Context, n network.Network, config socks5.Config, limit *forward.Limit, complete func()) (*socks5.Server, error) {
	server, err := socks5.Open(ctx, n, config, limit)
	if err != nil {
		return nil, err
	}
	go func() { <-server.Done(); complete() }()
	return server, nil
}
