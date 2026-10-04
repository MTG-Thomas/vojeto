package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/identity"
	"github.com/MTG-Thomas/vojeto/internal/providers/agent"
	"github.com/MTG-Thomas/vojeto/internal/providers/azure"
	"github.com/MTG-Thomas/vojeto/internal/providers/defined"
	"github.com/MTG-Thomas/vojeto/internal/providers/static"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
)

type providerConfig struct {
	Type            string   `json:"type"`
	AgentSocket     string   `json:"agentSocket,omitempty"`
	Hostname        string   `json:"hostname,omitempty"`
	StorageBaseURL  string   `json:"storageBaseURL"`
	Owner           string   `json:"owner"`
	Claimant        string   `json:"claimant"`
	ClaimantEnv     string   `json:"claimantEnv,omitempty"`
	HostIDs         []string `json:"hostIDs"`
	NetworkID       string   `json:"networkID"`
	DefinedAPI      string   `json:"definedAPI"`
	PollOutageGrace string   `json:"pollOutageGrace,omitempty"`
}

func selectProvider(staticPath, providerPath string) (identity.Provider, error) {
	if (staticPath == "") == (providerPath == "") {
		return nil, errors.New("configure exactly one identity provider")
	}
	if staticPath != "" {
		return static.Provider{Path: staticPath}, nil
	}
	file, e := os.Open(providerPath)
	if e != nil {
		return nil, errors.New("identity provider configuration unavailable")
	}
	defer file.Close()
	data, e := io.ReadAll(io.LimitReader(file, 65537))
	if e != nil || len(data) > 65536 {
		return nil, errors.New("identity provider configuration rejected")
	}
	var cfg providerConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || (cfg.Type != "defined-azure-pool" && cfg.Type != "defined-external-agent") {
		return nil, errors.New("identity provider configuration rejected")
	}
	if cfg.ClaimantEnv != "" {
		if cfg.Claimant != "" || !regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`).MatchString(cfg.ClaimantEnv) {
			return nil, errors.New("claimant environment rejected")
		}
		cfg.Claimant = os.Getenv(cfg.ClaimantEnv)
	}
	if cfg.DefinedAPI == "" {
		cfg.DefinedAPI = "https://api.defined.net"
	}
	api, e := url.Parse(cfg.DefinedAPI)
	if e != nil || api.Scheme != "https" || api.Hostname() == "" || api.User != nil || api.RawQuery != "" || api.Fragment != "" || api.Path != "" && api.Path != "/" {
		return nil, errors.New("Defined endpoint rejected")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	dn, e := defined.NewClient(api.String(), &http.Client{Timeout: 30 * time.Second})
	if e != nil {
		return nil, e
	}
	var grace time.Duration
	if cfg.PollOutageGrace != "" {
		grace, e = time.ParseDuration(cfg.PollOutageGrace)
		if e != nil {
			return nil, errors.New("poll outage grace rejected")
		}
	}
	if cfg.Type == "defined-external-agent" {
		if cfg.StorageBaseURL != "" || cfg.Owner != "" || cfg.Claimant != "" || cfg.ClaimantEnv != "" || len(cfg.HostIDs) != 0 || cfg.Hostname == "" || len(cfg.Hostname) > 253 {
			return nil, errors.New("external identity settings rejected")
		}
		store, err := agent.New(cfg.AgentSocket)
		if err != nil {
			return nil, err
		}
		return defined.NewEnrollmentProvider(store, store, dn, cfg.NetworkID, cfg.Hostname, defined.ProviderOptions{PollOutageGrace: grace})
	}
	if cfg.AgentSocket != "" || cfg.Hostname != "" {
		return nil, errors.New("pool identity settings rejected")
	}
	pool, e := azure.NewPool(client, func(ctx context.Context) (string, error) { return azure.StorageToken(ctx, client) }, cfg.Owner, cfg.HostIDs, cfg.StorageBaseURL)
	if e != nil {
		return nil, e
	}
	store, e := azure.NewStore(pool, cfg.Claimant)
	if e != nil {
		return nil, e
	}
	return defined.NewProviderWithOptions(store, dn, cfg.NetworkID, defined.ProviderOptions{PollOutageGrace: grace})
}
