package defined

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
)

const certificateSafetyMargin = 15 * time.Second

// confirmFreshness counts request time against the budget and validates every
// inline certificate and its issuer. It never extends a previously expired owner.
func (p *Provider) confirmFreshness(started time.Time) error {
	if p.options.PollOutageGrace == 0 {
		return nil
	}
	deadline := started.Add(p.options.PollOutageGrace)
	var cfg config.C
	if cfg.LoadString(string(p.state.Config)) != nil {
		return errors.New("identity certificate bounds rejected")
	}
	pki, err := nebula.NewPKIFromConfig(slog.New(slog.NewTextHandler(io.Discard, nil)), &cfg)
	if err != nil {
		return errors.New("identity certificate bounds rejected")
	}
	data := []byte(cfg.GetString("pki.cert", ""))
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		leaf, rest, e := cert.UnmarshalCertificateFromPEM(data)
		if e != nil || leaf.IsCA() {
			return errors.New("identity certificate bounds rejected")
		}
		if _, e = pki.GetCAPool().VerifyCertificate(p.now(), leaf); e != nil {
			return errors.New("identity certificate validity rejected")
		}
		issuer, e := pki.GetCAPool().GetCAForCert(leaf)
		if e != nil {
			return errors.New("identity certificate issuer rejected")
		}
		for _, bound := range []time.Time{leaf.NotAfter(), issuer.Certificate.NotAfter()} {
			bound = bound.Add(-certificateSafetyMargin)
			if bound.Before(deadline) {
				deadline = bound
			}
		}
		data = rest
		count++
	}
	if count == 0 || !p.now().Before(deadline) || p.revoked.Load() || !p.store.Valid() {
		return errors.New("identity freshness bound exhausted")
	}
	p.deadline.Store(&deadline)
	select {
	case p.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}

// Watch enforces freshness independently of the provider lock and a stalled
// read-only poll. Both monitors are cancelled and joined before it returns.
func (p *Provider) Watch(ctx context.Context, revoke func()) error {
	var once sync.Once
	stop := func() { once.Do(func() { p.revoked.Store(true); revoke() }) }
	if p.options.PollOutageGrace == 0 {
		return p.store.Watch(ctx, stop)
	}
	watching, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- p.store.Watch(watching, stop) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		var expired <-chan time.Time
		if deadline := p.deadline.Load(); deadline != nil {
			remaining := deadline.Sub(p.now())
			if remaining <= 0 {
				stop()
				return errors.New("identity freshness bound exhausted")
			}
			timer.Reset(remaining)
			expired = timer.C
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			joined = true
			if ctx.Err() != nil {
				return nil
			}
			stop()
			if err == nil {
				return errors.New("identity ownership monitor ended unexpectedly")
			}
			return err
		case <-p.deadlineChanged:
		case <-expired:
			// Recheck the atomically refreshed bound before revoking an owner.
			if !p.Valid() {
				stop()
				return errors.New("identity freshness or ownership lost")
			}
		}
	}
}

// ValidatePollSchedule prevents normal polling from exhausting the opt-in bound.
func (p *Provider) ValidatePollSchedule(interval, timeout time.Duration) error {
	grace := p.options.PollOutageGrace
	if grace > 0 && (interval <= 0 || timeout <= 0 || timeout >= grace || interval >= grace-timeout) {
		return errors.New("poll outage grace must exceed poll interval plus request timeout")
	}
	return nil
}
