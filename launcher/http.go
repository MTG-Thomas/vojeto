//go:build linux

package launcher

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// TLS requires a verified client chain AND an explicitly pinned broker leaf.
// Use a dedicated client CA. Pinning prevents another CA-issued client from
// gaining the launcher's privileged issuance capability.
func TLS(server tls.Certificate, ca *x509.CertPool, brokerFingerprint string) (*tls.Config, error) {
	pin, e := hex.DecodeString(brokerFingerprint)
	if e != nil || len(pin) != 32 || ca == nil || len(server.Certificate) == 0 {
		return nil, ErrInvalid
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientCAs: ca, ClientAuth: tls.RequireAndVerifyClientCert, VerifyConnection: func(c tls.ConnectionState) error {
		if len(c.VerifiedChains) == 0 || len(c.PeerCertificates) == 0 {
			return ErrInvalid
		}
		h := sha256.Sum256(c.PeerCertificates[0].Raw)
		if hex.EncodeToString(h[:]) != hex.EncodeToString(pin) {
			return ErrInvalid
		}
		return nil
	}}, nil
}
func Handler(m *Manager) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(value)
	}
	reject := func(w http.ResponseWriter, e error) {
		code := http.StatusBadRequest
		switch {
		case errors.Is(e, ErrConflict):
			code = 409
		case errors.Is(e, ErrGone):
			code = 410
		case errors.Is(e, ErrCapacity):
			code = 429
		case errors.Is(e, ErrUnavailable):
			code = 503
		}
		http.Error(w, "session request rejected", code)
	}
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		d.DisallowUnknownFields()
		var request StartRequest
		if d.Decode(&request) != nil {
			reject(w, ErrInvalid)
			return
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			reject(w, ErrInvalid)
			return
		}
		result, e := m.Start(request)
		if e != nil {
			reject(w, e)
			return
		}
		reply(w, result)
	})
	mux.HandleFunc("GET /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, e := m.Get(r.PathValue("id"))
		if e != nil {
			reject(w, e)
			return
		}
		reply(w, result)
	})
	mux.HandleFunc("DELETE /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if e := m.Stop(r.PathValue("id")); e != nil {
			reject(w, e)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "authenticated broker required", http.StatusUnauthorized)
			return
		}
		for _, chain := range r.TLS.VerifiedChains {
			for _, certificate := range chain {
				if time.Now().After(certificate.NotAfter) || time.Now().Before(certificate.NotBefore) {
					http.Error(w, "authenticated broker required", http.StatusUnauthorized)
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
