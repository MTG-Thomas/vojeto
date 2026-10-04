package control

import (
	"net/http/httptest"
	"testing"
)

func TestSeparateHealthAndCompletion(t *testing.T) {
	completed := false
	h := Handler(func() Status { return Status{State: "lease_lost"} }, func() { completed = true })
	for _, v := range []struct {
		method, path string
		code         int
	}{{"GET", "/live", 200}, {"GET", "/ready", 503}, {"GET", "/v1/lifecycle/complete", 405}, {"POST", "/v1/lifecycle/complete", 202}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(v.method, v.path, nil))
		if w.Code != v.code {
			t.Fatal(v, w.Code)
		}
	}
	if !completed {
		t.Fatal("completion missing")
	}
}
