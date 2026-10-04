package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"

	"github.com/MTG-Thomas/vojeto/internal/health"
	"github.com/MTG-Thomas/vojeto/internal/network"
	"github.com/MTG-Thomas/vojeto/internal/runtime"
)

type readinessSettings struct {
	Hosts        map[string][]string `json:"hosts"`
	Overlay      []health.Probe      `json:"overlay"`
	Dependencies []health.Probe      `json:"dependencies"`
}

func loadReadiness(path string) (*readinessSettings, *network.Resolver, error) {
	if path == "" {
		return nil, nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("readiness configuration unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return nil, nil, errors.New("readiness configuration exceeds bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var settings readinessSettings
	if decoder.Decode(&settings) != nil || decoder.Decode(new(any)) != io.EOF || len(settings.Overlay) == 0 || len(settings.Overlay)+len(settings.Dependencies) > 32 {
		return nil, nil, errors.New("invalid readiness configuration")
	}
	for _, probes := range [][]health.Probe{settings.Overlay, settings.Dependencies} {
		for _, p := range probes {
			if p.Validate() != nil {
				return nil, nil, errors.New("invalid readiness probe")
			}
		}
	}
	resolver, err := network.NewResolver(settings.Hosts)
	if err != nil {
		return nil, nil, err
	}
	return &settings, resolver, nil
}

type resolvedTransport struct {
	runtime.Transport
	resolver *network.Resolver
}

func (n *resolvedTransport) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	return n.resolver.Resolve(ctx, name)
}
