package control

import (
	"encoding/json"
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

func TestStatusExposesOnlyHealthAndAggregateCounters(t *testing.T) {
	active := 2
	h := HealthHandler(func() Status {
		return Status{State: "ready", IdentityValid: true, OverlayReady: true, DependenciesReady: true, ActiveConnections: &active}
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatal("invalid status JSON")
	}
	allowed := map[string]bool{"state": true, "identity_valid": true, "overlay_ready": true, "dependencies_ready": true, "active_connections": true, "process": true}
	for key := range body {
		if !allowed[key] {
			t.Fatal("unapproved status field", key)
		}
	}
	if string(body["active_connections"]) != "2" {
		t.Fatal("connection count missing")
	}
	var counters map[string]json.RawMessage
	if json.Unmarshal(body["process"], &counters) != nil {
		t.Fatal("process counters missing")
	}
	for key := range counters {
		if key != "goroutines" && key != "open_fds" {
			t.Fatal("unapproved process field", key)
		}
	}
	var goroutines int
	if json.Unmarshal(counters["goroutines"], &goroutines) != nil || goroutines < 1 {
		t.Fatal("invalid goroutine count")
	}
}
