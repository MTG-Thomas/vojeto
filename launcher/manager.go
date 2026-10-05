//go:build linux

// Package launcher hosts finite peer lighthouses for a trusted session broker.
// Endpoint authorization belongs to that broker. No endpoint private key enters
// this API; the launcher generates and retains only its own lighthouse key.
package launcher

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/MTG-Thomas/vojeto/peer"
	"golang.org/x/sys/unix"
)

var (
	ErrInvalid     = errors.New("invalid session request")
	ErrConflict    = errors.New("request identity already used")
	ErrGone        = errors.New("session is no longer active")
	ErrCapacity    = errors.New("session capacity reached")
	ErrUnavailable = errors.New("session could not start")
)

// StartRequest is immutable and uses an absolute deadline, so retry cannot
// extend a lease. ID is a broker-generated 128-bit lowercase hexadecimal nonce.
type StartRequest struct {
	ID          string    `json:"id"`
	OperatorKey []byte    `json:"operatorKey"`
	TargetKey   []byte    `json:"targetKey"`
	Destination string    `json:"destination"`
	Expires     time.Time `json:"expires"`
}
type Session struct {
	ID       string     `json:"id"`
	Operator peer.Grant `json:"operator"`
	Target   peer.Grant `json:"target"`
}
type Config struct {
	PeerBinary          string
	RunDir              string
	PublicIP            netip.Addr
	BindIP              netip.Addr
	FirstPort, LastPort uint16
	MaxSessions         int
	StateDir            string
}
type tombstone struct {
	Hash    string    `json:"hash"`
	Expires time.Time `json:"expires"`
}
type running struct {
	hash    string
	session Session
	port    uint16
	cancel  context.CancelFunc
	done    chan struct{}
}
type Manager struct {
	mu       sync.Mutex
	config   Config
	ctx      context.Context
	cancel   context.CancelFunc
	lock     *os.File
	sessions map[string]*running
	records  map[string]tombstone
	closed   bool
	failed   bool
}

// Open takes an exclusive process lock and recovers only tombstones. Restart
// never resurrects peers or reissues an old request's certificates.
func Open(parent context.Context, c Config) (*Manager, error) {
	if !c.PublicIP.Is4() || c.PublicIP.IsUnspecified() || c.PublicIP.IsMulticast() || !c.BindIP.Is4() || c.FirstPort < 1024 || c.LastPort < c.FirstPort || int(c.LastPort)-int(c.FirstPort) > 127 || c.MaxSessions < 1 || c.MaxSessions > int(c.LastPort)-int(c.FirstPort)+1 || !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.RunDir) || !filepath.IsAbs(c.PeerBinary) {
		return nil, ErrInvalid
	}
	runtime, e := os.Lstat(c.RunDir)
	if e != nil || !runtime.IsDir() || runtime.Mode().Perm() != 0700 {
		return nil, ErrInvalid
	}
	binary, e := os.Lstat(c.PeerBinary)
	if e != nil || !binary.Mode().IsRegular() || binary.Mode().Perm()&0111 == 0 || binary.Mode().Perm()&0022 != 0 {
		return nil, ErrInvalid
	}
	st, e := os.Lstat(c.StateDir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, ErrInvalid
	}
	lock, e := os.OpenFile(filepath.Join(c.StateDir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, ErrUnavailable
	}
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		lock.Close()
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{config: c, ctx: ctx, cancel: cancel, lock: lock, sessions: map[string]*running{}, records: map[string]tombstone{}}
	fail := func() (*Manager, error) { cancel(); lock.Close(); return nil, ErrUnavailable }
	files, e := os.ReadDir(c.StateDir)
	if e != nil || len(files) > 1025 {
		return fail()
	}
	for _, f := range files {
		if f.Name() == ".lock" {
			continue
		}
		id := f.Name()
		if filepath.Ext(id) != ".json" || !validID(id[:len(id)-5]) || !f.Type().IsRegular() {
			return fail()
		}
		data, e := os.ReadFile(filepath.Join(c.StateDir, id))
		if e != nil || len(data) > 1024 {
			return fail()
		}
		var r tombstone
		if json.Unmarshal(data, &r) != nil || len(r.Hash) != 64 || r.Expires.IsZero() {
			return fail()
		}
		if r.Expires.After(time.Now()) {
			m.records[id[:len(id)-5]] = r
		} else if os.Remove(filepath.Join(c.StateDir, id)) != nil {
			return fail()
		}
	}
	abandoned, e := os.ReadDir(c.RunDir)
	if e != nil {
		return fail()
	}
	for _, f := range abandoned {
		if !validID(f.Name()) || !f.IsDir() {
			return fail()
		}
		if os.RemoveAll(filepath.Join(c.RunDir, f.Name())) != nil {
			return fail()
		}
	}
	return m, nil
}
func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && s == hex.EncodeToString(b)
}
func fingerprint(r StartRequest) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (m *Manager) Start(r StartRequest) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.failed || m.ctx.Err() != nil {
		return Session{}, ErrUnavailable
	}
	if !validID(r.ID) || len(r.OperatorKey) != 32 || len(r.TargetKey) != 32 || r.Expires.Sub(time.Now()) < time.Second || r.Expires.Sub(time.Now()) > peer.MaxLifetime {
		return Session{}, ErrInvalid
	}
	hash := fingerprint(r)
	if old, ok := m.records[r.ID]; ok {
		if old.Hash != hash {
			return Session{}, ErrConflict
		}
		if current, ok := m.sessions[r.ID]; ok {
			return current.session, nil
		}
		return Session{}, ErrGone
	}
	now := time.Now()
	for id, old := range m.records {
		if !old.Expires.After(now) {
			if os.Remove(filepath.Join(m.config.StateDir, id+".json")) != nil {
				return Session{}, ErrUnavailable
			}
			delete(m.records, id)
		}
	}
	if len(m.sessions) >= m.config.MaxSessions || len(m.records) >= 1024 {
		return Session{}, ErrCapacity
	}
	used := map[uint16]bool{}
	for _, s := range m.sessions {
		used[s.port] = true
	}
	port := m.config.FirstPort
	for used[port] {
		port++
	}
	pub, private, e := peer.Keygen()
	if e != nil {
		return Session{}, ErrUnavailable
	}
	grants, e := peer.Issue(peer.Request{OperatorKey: r.OperatorKey, TargetKey: r.TargetKey, LighthouseKey: pub, Target: r.Destination, LighthouseEndpoint: netip.AddrPortFrom(m.config.PublicIP, port).String(), Lifetime: time.Until(r.Expires)})
	if e != nil {
		clear(private)
		return Session{}, ErrInvalid
	}
	record := tombstone{Hash: hash, Expires: r.Expires}
	if e = m.remember(r.ID, record); e != nil {
		clear(private)
		return Session{}, e
	}
	ctx, cancel := context.WithCancel(m.ctx)
	s := &running{hash: hash, session: Session{ID: r.ID, Operator: grants["operator"], Target: grants["target"]}, port: port, cancel: cancel, done: make(chan struct{})}
	m.sessions[r.ID] = s
	ready := make(chan struct{}, 1)
	exit := make(chan error, 1)

	roleDir := filepath.Join(m.config.RunDir, r.ID)
	if os.Mkdir(roleDir, 0700) != nil {
		delete(m.sessions, r.ID)
		cancel()
		clear(private)
		return Session{}, ErrUnavailable
	}
	write := func(name string, value any) error {
		data, e := json.Marshal(value)
		if e != nil {
			return e
		}
		defer clear(data)
		return os.WriteFile(filepath.Join(roleDir, name), data, 0600)
	}
	if write("lighthouse.json", grants["lighthouse"]) != nil || write("private.json", private) != nil {
		delete(m.sessions, r.ID)
		cancel()
		clear(private)
		if os.RemoveAll(roleDir) != nil {
			m.failed = true
		}
		return Session{}, ErrUnavailable
	}
	clear(private)
	child := exec.CommandContext(ctx, m.config.PeerBinary, "lighthouse", "--grant", filepath.Join(roleDir, "lighthouse.json"), "--key", filepath.Join(roleDir, "private.json"), "--udp-listen", netip.AddrPortFrom(m.config.BindIP, port).String())
	child.Cancel = func() error { return child.Process.Signal(syscall.SIGTERM) }
	child.WaitDelay = 2 * time.Second
	child.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	output, e := child.StdoutPipe()
	if e != nil {
		delete(m.sessions, r.ID)
		cancel()
		if os.RemoveAll(roleDir) != nil {
			m.failed = true
		}
		return Session{}, ErrUnavailable
	}
	// No caller-controlled arguments, environment overrides or shell. Child stderr
	// is discarded because initialization failures may include private material.
	if e = child.Start(); e != nil {
		delete(m.sessions, r.ID)
		cancel()
		if os.RemoveAll(roleDir) != nil {
			m.failed = true
		}
		return Session{}, ErrUnavailable
	}
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 1024), 4096)
		if scanner.Scan() {
			var event struct {
				Event   string `json:"event"`
				Address string `json:"address"`
			}
			if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Event == "listening" {
				ready <- struct{}{}
			}
		}
		// Drain the bounded output stream before Wait; no child output is logged.
		for scanner.Scan() {
		}
	}()
	go func() {
		<-outputDone
		err := child.Wait()
		exit <- err
		cleanupErr := os.RemoveAll(roleDir)
		m.mu.Lock()
		if cleanupErr != nil {
			m.failed = true
		}
		delete(m.sessions, r.ID)
		m.mu.Unlock()
		close(s.done)
	}()
	select {
	case <-ready:
		return s.session, nil
	case <-exit:
		cancel()
		return Session{}, ErrUnavailable
	case <-time.After(3 * time.Second):
		cancel()
		return Session{}, ErrUnavailable
	}
}
func (m *Manager) Get(id string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		return s.session, nil
	}
	return Session{}, ErrGone
}

// remember must be called while holding the manager mutex.
func (m *Manager) remember(id string, record tombstone) error {
	if len(m.records) >= 1024 {
		return ErrCapacity
	}
	data, _ := json.Marshal(record)
	f, e := os.OpenFile(filepath.Join(m.config.StateDir, id+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrUnavailable
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		m.failed = true
		return ErrUnavailable
	}
	dir, e := os.Open(m.config.StateDir)
	if e != nil {
		m.failed = true
		return ErrUnavailable
	}
	e = dir.Sync()
	dir.Close()
	if e != nil {
		m.failed = true
		return ErrUnavailable
	}
	m.records[id] = record
	return nil
}

// Stop is idempotent and waits for the transport to close before returning.
func (m *Manager) Stop(id string) error {
	if !validID(id) {
		return ErrInvalid
	}
	m.mu.Lock()
	if m.closed || m.failed {
		m.mu.Unlock()
		return ErrUnavailable
	}
	if _, exists := m.records[id]; !exists {
		// Revoke-before-create is a durable barrier, not a successful no-op. It
		// closes the race between an in-flight create RPC and cancellation.
		if e := m.remember(id, tombstone{Hash: hex.EncodeToString(make([]byte, 32)), Expires: time.Now().UTC().Add(peer.MaxLifetime)}); e != nil {
			m.mu.Unlock()
			return e
		}
	}
	s, ok := m.sessions[id]
	if ok {
		s.cancel()
	}
	m.mu.Unlock()
	if !ok {
		m.mu.Lock()
		failed := m.failed
		m.mu.Unlock()
		if failed {
			return ErrUnavailable
		}
		return nil
	}
	select {
	case <-s.done:
		m.mu.Lock()
		failed := m.failed
		m.mu.Unlock()
		if failed {
			return ErrUnavailable
		}
		return nil
	case <-time.After(5 * time.Second):
		return ErrUnavailable
	}
}
func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	wait := []chan struct{}{}
	for _, s := range m.sessions {
		wait = append(wait, s.done)
	}
	m.mu.Unlock()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for _, done := range wait {
		select {
		case <-done:
		case <-deadline.C:
			return ErrUnavailable
		}
	}
	lockErr := m.lock.Close()
	m.mu.Lock()
	failed := m.failed
	m.mu.Unlock()
	if failed {
		return ErrUnavailable
	}
	return lockErr
}
