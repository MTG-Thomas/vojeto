package azure

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/MTG-Thomas/vojeto/internal/providers/defined"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const maximumIdentityStateBytes = 1024 * 1024
const identityLeaseDuration = 60 * time.Second
const identityLeaseMargin = 15 * time.Second

var errIdentitySlotBusy = errors.New("identity slot is leased")
var errIdentityPoolFull = errors.New("identity pool has no available slots")
var errIdentityQuarantined = errors.New("identity requires shutdown reconciliation")

// No network-wide Defined API token reaches this client. The operator enrolls
// a bounded pool of hosts in advance, then replicas lease their own SDK state.
type identityPool struct {
	client *http.Client
	token  func(context.Context) (string, error)
	app    string
	hosts  []string
	base   string
}

func newIdentityPool(client *http.Client, token func(context.Context) (string, error), app string, hosts []string, base string) (*identityPool, error) {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`).MatchString(app) || len(hosts) < 1 || len(hosts) > 1024 {
		return nil, errors.New("undeclared identity pool")
	}
	if client == nil || token == nil {
		return nil, errors.New("storage client and token required")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || u.Path == "" || strings.Contains(u.Path, "..") {
		return nil, errors.New("invalid storage base")
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &copyClient
	seen := map[string]bool{}
	for _, host := range hosts {
		if !regexp.MustCompile(`^host-[A-Z0-9]+$`).MatchString(host) || seen[host] {
			return nil, errors.New("invalid or duplicate identity pool host")
		}
		seen[host] = true
	}
	return &identityPool{client: client, token: token, app: app, hosts: append([]string(nil), hosts...), base: strings.TrimRight(base, "/")}, nil
}

func (p *identityPool) endpoint(slot int) string {
	return p.base + "/" + p.hosts[slot-1] + ".json"
}

func (p *identityPool) request(ctx context.Context, method string, slot int, query string, headers map[string]string, body []byte) (*http.Response, error) {
	if slot < 1 || slot > len(p.hosts) {
		return nil, errors.New("undeclared identity slot")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	token, err := p.token(ctx)
	if err != nil {
		return nil, errors.New("identity storage authentication failed")
	}
	request, err := http.NewRequestWithContext(ctx, method, p.endpoint(slot)+query, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("identity storage request failed")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	request.Header.Set("x-ms-version", "2023-11-03")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return nil, errors.New("identity storage transport failed")
	}
	// Read a bounded body before the request deadline is cancelled. Neither body
	// nor provider errors are logged; they can contain keys/configuration.
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maximumIdentityStateBytes+1))
	response.Body.Close()
	if readErr != nil || len(data) > maximumIdentityStateBytes {
		return nil, errors.New("identity storage response rejected")
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	return response, nil
}

type identityLease struct {
	pool       *identityPool
	slot       int
	id         string
	replica    string
	mu         sync.Mutex
	validUntil time.Time
}

func (p *identityPool) acquire(ctx context.Context, slot int) (*identityLease, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("identity lease nonce failed")
	}
	nonce[6] = (nonce[6] & 15) | 64
	nonce[8] = (nonce[8] & 63) | 128
	h := hex.EncodeToString(nonce[:])
	id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	started := time.Now()
	response, err := p.request(ctx, http.MethodPut, slot, "?comp=lease", map[string]string{
		"x-ms-lease-action": "acquire", "x-ms-proposed-lease-id": id, "x-ms-lease-duration": "60"}, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == 409 && response.Header.Get("x-ms-error-code") == "LeaseAlreadyPresent" {
		return nil, errIdentitySlotBusy
	}
	if response.StatusCode != 201 || response.Header.Get("x-ms-lease-id") != id {
		return nil, errors.New("identity lease acquisition rejected")
	}
	return &identityLease{pool: p, slot: slot, id: id, validUntil: started.Add(identityLeaseDuration - identityLeaseMargin)}, nil
}

func (l *identityLease) remaining() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Until(l.validUntil)
}

func (l *identityLease) renew(ctx context.Context) error {
	// Azure can renew an expired lease. This client deliberately cannot resume
	// after its conservative deadline: a stale observation never reauthorizes use.
	if l.remaining() <= 0 {
		return errors.New("identity lease deadline passed")
	}
	started := time.Now()
	response, err := l.pool.request(ctx, http.MethodPut, l.slot, "?comp=lease", map[string]string{
		"x-ms-lease-action": "renew", "x-ms-lease-id": l.id}, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("x-ms-lease-id") != l.id {
		return errors.New("identity lease renewal rejected")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !time.Now().Before(l.validUntil) {
		return errors.New("identity lease renewal arrived too late")
	}
	l.validUntil = started.Add(identityLeaseDuration - identityLeaseMargin)
	return nil
}

func (l *identityLease) read(ctx context.Context) ([]byte, error) {
	if l.remaining() <= 0 {
		return nil, errors.New("identity lease deadline passed")
	}
	response, err := l.pool.request(ctx, http.MethodGet, l.slot, "", map[string]string{"x-ms-lease-id": l.id}, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("x-ms-meta-owner") != l.pool.app || l.remaining() <= 0 {
		return nil, errors.New("identity state read rejected")
	}
	// Lease expiry does not prove the prior Nebula process exited. A crashed,
	// paused or uncertain owner leaves an active tombstone, which another
	// replica must never clear merely because Azure granted it a lease.
	if response.Header.Get("x-ms-meta-state") != "available" {
		return nil, errIdentityQuarantined
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.New("identity state read failed")
	}
	state, _, err := defined.DecodeState(data)
	if err != nil {
		return nil, err
	}
	if state.HostID != l.pool.hosts[l.slot-1] {
		return nil, errors.New("identity state does not match leased host")
	}
	return data, nil
}

func (l *identityLease) write(ctx context.Context, data []byte) error {
	state, _, err := defined.DecodeState(data)
	if err != nil {
		return err
	}
	if state.HostID != l.pool.hosts[l.slot-1] {
		return errors.New("identity checkpoint does not match leased host")
	}
	if l.remaining() <= 0 {
		return errors.New("identity lease deadline passed")
	}
	response, err := l.pool.request(ctx, http.MethodPut, l.slot, "", map[string]string{
		"x-ms-lease-id": l.id, "x-ms-blob-type": "BlockBlob", "Content-Type": "application/json", "x-ms-meta-owner": l.pool.app,
		"x-ms-meta-state": "active", "x-ms-meta-replica": l.replica}, data)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 201 || l.remaining() <= 0 {
		return errors.New("identity state checkpoint rejected")
	}
	return nil
}

func (l *identityLease) mark(ctx context.Context, state string) error {
	if (state != "active" && state != "available") || l.remaining() <= 0 {
		return errors.New("identity ownership transition rejected")
	}
	response, err := l.pool.request(ctx, http.MethodPut, l.slot, "?comp=metadata", map[string]string{
		"x-ms-lease-id": l.id, "x-ms-meta-owner": l.pool.app, "x-ms-meta-state": state, "x-ms-meta-replica": l.replica}, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || l.remaining() <= 0 {
		return errors.New("identity ownership transition unconfirmed")
	}
	return nil
}

func (p *identityPool) takeAvailable(ctx context.Context, replica string) (*identityLease, []byte, error) {
	busy := false
	if !stringsReplicaOf(p.app, replica) {
		return nil, nil, errors.New("foreign identity pool claimant")
	}
	for slot := 1; slot <= len(p.hosts); slot++ {
		lease, err := p.acquire(ctx, slot)
		if errors.Is(err, errIdentitySlotBusy) {
			busy = true
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		data, err := lease.read(ctx)
		if err != nil {
			// This is only our freshly obtained Blob lease; releasing it does not
			// unblock/re-enroll/delete a Defined host or clear its active marker.
			if lease.release(ctx) != nil {
				return nil, nil, errors.New("unused identity lease release unconfirmed")
			}
			if errors.Is(err, errIdentityQuarantined) {
				continue
			}
			return nil, nil, err
		}
		lease.replica = replica
		if err := lease.mark(ctx, "active"); err != nil {
			lease.release(ctx)
			return nil, nil, err
		}
		return lease, data, nil
	}
	if !busy {
		return nil, nil, errIdentityQuarantined
	}
	return nil, nil, errIdentityPoolFull
}

func (l *identityLease) release(ctx context.Context) error {
	response, err := l.pool.request(ctx, http.MethodPut, l.slot, "?comp=lease", map[string]string{
		"x-ms-lease-action": "release", "x-ms-lease-id": l.id}, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	l.mu.Lock()
	l.validUntil = time.Time{}
	l.mu.Unlock()
	if response.StatusCode != 200 {
		return errors.New("identity lease release rejected")
	}
	return nil
}

// Watchdog is independent of HTTP renewal. A stalled request cannot keep an
// expired host identity running. stopTransport must synchronously close Nebula.
func (l *identityLease) maintain(ctx context.Context, stopTransport func()) error {
	ticks := time.NewTicker(time.Second)
	defer ticks.Stop()
	renewals := time.NewTicker(10 * time.Second)
	defer renewals.Stop()
	results := make(chan error, 1)
	pending := false
	renewCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticks.C:
			if l.remaining() <= 0 {
				stopTransport()
				return errors.New("identity lease ownership expired")
			}
		case <-renewals.C:
			if !pending {
				pending = true
				go func() { results <- l.renew(renewCtx) }()
			}
		case err := <-results:
			pending = false
			if err != nil {
				stopTransport()
				return errors.New("identity lease ownership unconfirmed")
			}
		}
	}
}

func storageIdentityToken(ctx context.Context, client *http.Client) (string, error) {
	endpoint, err := url.Parse(os.Getenv("IDENTITY_ENDPOINT"))
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Fragment != "" ||
		(endpoint.Hostname() != "localhost" && endpoint.Hostname() != "127.0.0.1") {
		return "", errors.New("invalid storage identity endpoint")
	}
	query := endpoint.Query()
	query.Set("api-version", "2019-08-01")
	query.Set("resource", "https://storage.azure.com/")
	query.Set("client_id", os.Getenv("AZURE_CLIENT_ID"))
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", errors.New("storage identity request failed")
	}
	request.Header.Set("X-IDENTITY-HEADER", os.Getenv("IDENTITY_HEADER"))
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("storage identity transport failed")
	}
	defer response.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 32768)).Decode(&result) != nil || result.AccessToken == "" {
		return "", errors.New("storage identity response rejected")
	}
	return result.AccessToken, nil
}

func stringsReplicaOf(app, replica string) bool {
	return regexp.MustCompile("^" + regexp.QuoteMeta(app) + `--[a-z0-9-]+$`).MatchString(replica)
}

// NewPool configures an explicit private state location; it never provisions identities.
func NewPool(client *http.Client, token func(context.Context) (string, error), owner string, hosts []string, base string) (*identityPool, error) {
	return newIdentityPool(client, token, owner, hosts, base)
}
func (p *identityPool) Acquire(ctx context.Context, claimant string) (*identityLease, []byte, error) {
	return p.takeAvailable(ctx, claimant)
}
func (l *identityLease) Checkpoint(ctx context.Context, data []byte) error { return l.write(ctx, data) }
func (l *identityLease) Maintain(ctx context.Context, stop func()) error {
	return l.maintain(ctx, stop)
}

// ReleaseClean must only be called after checkpoint and synchronous transport shutdown.
func (l *identityLease) ReleaseClean(ctx context.Context) error {
	if e := l.mark(ctx, "available"); e != nil {
		return e
	}
	return l.release(ctx)
}
