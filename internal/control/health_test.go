package control

import (
	"net/http/httptest"
	"testing"
)

func TestPublicHealthCannotComplete(t *testing.T) {
	h := HealthHandler(func() Status {
		return Status{State: "ready", IdentityValid: true, OverlayReady: true, DependenciesReady: true}
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/lifecycle/complete", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
