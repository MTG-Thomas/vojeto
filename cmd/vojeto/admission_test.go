package main

import (
	"testing"
	"time"
)

func TestPortableSignalGrace(t *testing.T) {
	for _, grace := range []time.Duration{0, time.Second, 5 * time.Minute, 12 * time.Minute, time.Hour} {
		if err := validateAdmission(128, grace); err != nil {
			t.Fatalf("explicit finite grace %s rejected: %v", grace, err)
		}
	}
	if err := validateAdmission(128, -time.Second); err == nil {
		t.Fatal("negative grace accepted")
	}
	if err := validateAdmission(0, time.Hour); err == nil {
		t.Fatal("unbounded connections accepted")
	}
}
