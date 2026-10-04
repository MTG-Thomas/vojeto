package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/DefinedNet/dnapi"
	"github.com/MTG-Thomas/vojeto/internal/identity"
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
	Type           string   `json:"type"`
	StorageBaseURL string   `json:"storageBaseURL"`
	Owner          string   `json:"owner"`
	Claimant       string   `json:"claimant"`
	ClaimantEnv    string   `json:"claimantEnv,omitempty"`
	HostIDs        []string `json:"hostIDs"`
	NetworkID      string   `json:"networkID"`
	DefinedAPI     string   `json:"definedAPI"`
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
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || cfg.Type != "defined-azure-pool" {
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
	pool, e := azure.NewPool(client, func(ctx context.Context) (string, error) { return azure.StorageToken(ctx, client) }, cfg.Owner, cfg.HostIDs, cfg.StorageBaseURL)
	if e != nil {
		return nil, e
	}
	store, e := azure.NewStore(pool, cfg.Claimant)
	if e != nil {
		return nil, e
	}
	return defined.NewProvider(store, dnapi.NewClient("vojeto/initial", api.String()), cfg.NetworkID)
}
