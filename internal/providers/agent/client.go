// Package agent bridges the enrollment provider to a caller-owned local identity
// agent. The agent owns durable fencing, allocation policy and reconciliation.
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MTG-Thomas/vojeto/internal/providers/defined"
)

var errRejected = errors.New("identity agent request rejected")

const maxBody = 4 << 20

// Client is single-use. Any uncertain request or expired ownership permanently
// revokes this instance. Tokens, grants and checkpoints never enter diagnostics.
type Client struct {
	http      *http.Client
	tokenMu   sync.Mutex
	token     string
	attempted atomic.Bool
	revoked   atomic.Bool
	released  atomic.Bool
	deadline  atomic.Pointer[time.Time]
	ttl       atomic.Int64
	watching  atomic.Bool
}
type request struct {
	Attempt   string `json:"attempt,omitempty"`
	Token     string `json:"token,omitempty"`
	HostID    string `json:"hostID,omitempty"`
	NetworkID string `json:"networkID,omitempty"`
	State     []byte `json:"state,omitempty"`
}
type reply struct {
	OK                bool   `json:"ok"`
	Token             string `json:"token"`
	LeaseMilliseconds int64  `json:"leaseMilliseconds,omitempty"`
	State             []byte `json:"state,omitempty"`
	Grant             *grant `json:"grant,omitempty"`
}
type grant struct {
	Code          string   `json:"code"`
	HostID        string   `json:"hostID"`
	NetworkID     string   `json:"networkID"`
	Addresses     []string `json:"addresses,omitempty"`
	AddressRanges []string `json:"addressRanges,omitempty"`
	RoutePolicy   string   `json:"routePolicy"`
}

// New requires an absolute socket in a private directory, both owned by the
// current UID. Each connection also verifies peer UID. No TCP fallback exists.
func New(socket string) (*Client, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return nil, errRejected
	}
	if err := checkPath(socket); err != nil {
		return nil, errRejected
	}
	transport := &http.Transport{DisableKeepAlives: true, Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if checkPath(socket) != nil {
			return nil, errRejected
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, errRejected
		}
		if checkPeer(conn) != nil {
			conn.Close()
			return nil, errRejected
		}
		return conn, nil
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func checkPath(socket string) error {
	dir, err := os.Lstat(filepath.Dir(socket))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 || !owned(dir) {
		return errRejected
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 || !owned(info) {
		return errRejected
	}
	return nil
}
func (c *Client) call(ctx context.Context, operation string, req request) (reply, error) {
	reject := func() (reply, error) { return reply{}, errRejected }
	data, err := json.Marshal(req)
	if err != nil || len(data) > maxBody {
		return reject()
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://identity-agent/v1/identity/"+operation, bytes.NewReader(data))
	if err != nil {
		return reject()
	}
	// Mutations must never be automatically replayed after an uncertain response.
	r.GetBody = nil
	r.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(r)
	if err != nil {
		if ctx.Err() != nil {
			return reply{}, ctx.Err()
		}
		return reject()
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return reject()
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		if ctx.Err() != nil {
			return reply{}, ctx.Err()
		}
		return reject()
	}
	if len(body) > maxBody {
		return reject()
	}
	var result reply
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&result) != nil || dec.Decode(new(any)) != io.EOF || !result.OK || result.Token == "" || len(result.Token) > 4096 || (req.Token != "" && result.Token != req.Token) {
		return reject()
	}
	if ctx.Err() != nil {
		return reply{}, ctx.Err()
	}
	return result, nil
}
func (c *Client) lease(start time.Time, milliseconds int64) error {
	if milliseconds < 100 || milliseconds > 60000 {
		c.revoked.Store(true)
		return errRejected
	}
	duration := time.Duration(milliseconds) * time.Millisecond
	end := start.Add(duration)
	if !time.Now().Before(end) {
		c.revoked.Store(true)
		return errRejected
	}
	c.ttl.Store(int64(duration))
	c.deadline.Store(&end)
	return nil
}
func (c *Client) Acquire(ctx context.Context) ([]byte, error) {
	if !c.attempted.CompareAndSwap(false, true) {
		return nil, errRejected
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errRejected
	}
	started := time.Now()
	res, err := c.call(ctx, "acquire", request{Attempt: hex.EncodeToString(nonce[:])})
	if err != nil {
		c.revoked.Store(true)
		return nil, err
	}
	if c.lease(started, res.LeaseMilliseconds) != nil {
		return nil, errRejected
	}
	c.tokenMu.Lock()
	c.token = res.Token
	c.tokenMu.Unlock()
	return res.State, nil
}
func (c *Client) Valid() bool {
	deadline := c.deadline.Load()
	return !c.revoked.Load() && !c.released.Load() && deadline != nil && time.Now().Before(*deadline)
}
func (c *Client) ownedRequest() (request, error) {
	if !c.Valid() {
		c.revoked.Store(true)
		return request{}, errRejected
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return request{Token: c.token}, nil
}
func (c *Client) mutation(ctx context.Context, operation string, edit func(*request)) error {
	req, err := c.ownedRequest()
	if err != nil {
		return err
	}
	if edit != nil {
		edit(&req)
	}
	_, err = c.call(ctx, operation, req)
	if err != nil || !c.Valid() {
		c.revoked.Store(true)
		return errRejected
	}
	return nil
}
func (c *Client) BeginEnrollment(ctx context.Context) error { return c.mutation(ctx, "begin", nil) }
func (c *Client) BindEnrollment(ctx context.Context, host, network string) error {
	return c.mutation(ctx, "bind", func(r *request) { r.HostID = host; r.NetworkID = network })
}
func (c *Client) Checkpoint(ctx context.Context, state []byte) error {
	return c.mutation(ctx, "checkpoint", func(r *request) { r.State = state })
}
func (c *Client) Release(ctx context.Context) error {
	if err := c.mutation(ctx, "release", nil); err != nil {
		return err
	}
	c.released.Store(true)
	return nil
}
func (c *Client) AcquireGrant(ctx context.Context) (*defined.EnrollmentGrant, error) {
	req, err := c.ownedRequest()
	if err != nil {
		return nil, err
	}
	res, err := c.call(ctx, "grant", req)
	if err != nil || !c.Valid() || res.Grant == nil {
		c.revoked.Store(true)
		return nil, errRejected
	}
	g := res.Grant
	result := &defined.EnrollmentGrant{Code: g.Code, HostID: g.HostID, NetworkID: g.NetworkID, Addresses: g.Addresses, RoutePolicy: []byte(g.RoutePolicy)}
	for _, raw := range g.AddressRanges {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			c.revoked.Store(true)
			return nil, errRejected
		}
		result.AddressRanges = append(result.AddressRanges, p)
	}
	return result, nil
}

// Watch renews only the ownership lease, independently of Defined polling. The
// timeout is bounded by the last confirmed lease; stale/uncertain replies revoke.
func (c *Client) Watch(ctx context.Context, lost func()) error {
	if !c.watching.CompareAndSwap(false, true) {
		return errRejected
	}
	defer c.watching.Store(false)
	fail := func() error { c.revoked.Store(true); lost(); return errRejected }
	for {
		if c.released.Load() {
			return nil
		}
		if !c.Valid() {
			return fail()
		}
		pause := time.Duration(c.ttl.Load()) / 3
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if c.released.Load() {
			return nil
		}
		req, err := c.ownedRequest()
		if err != nil {
			return fail()
		}
		limit := c.deadline.Load()
		requestCtx, cancel := context.WithDeadline(ctx, *limit)
		started := time.Now()
		res, err := c.call(requestCtx, "renew", req)
		cancel()
		if ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled)) {
			return nil
		}
		if c.released.Load() {
			return nil
		}
		// A response cannot revive an ownership interval that already expired.
		if err != nil || !c.Valid() || c.lease(started, res.LeaseMilliseconds) != nil {
			return fail()
		}
	}
}

var _ defined.EnrollmentStore = (*Client)(nil)
var _ defined.GrantSource = (*Client)(nil)
