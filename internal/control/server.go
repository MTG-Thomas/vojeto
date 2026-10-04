// Package control provides a permission-restricted local completion and health API.
package control

import (
	"encoding/json"
	"net/http"
)

type Status struct {
	State             string `json:"state"`
	IdentityValid     bool   `json:"identity_valid"`
	OverlayReady      bool   `json:"overlay_ready"`
	DependenciesReady bool   `json:"dependencies_ready"`
}

func Handler(status func() Status, complete func()) http.Handler {
	mux := healthMux(status)
	mux.HandleFunc("POST /v1/lifecycle/complete", func(w http.ResponseWriter, r *http.Request) { complete(); w.WriteHeader(202) })
	return mux
}

// HealthHandler deliberately excludes lifecycle mutations, even on public binds.
func HealthHandler(status func() Status) http.Handler { return healthMux(status) }
func healthMux(status func() Status) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		s := status()
		if s.State != "ready" || !s.IdentityValid || !s.OverlayReady || !s.DependenciesReady {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status())
	})
	return mux
}
