package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestFailureCodesExposeOnlyClosedSourceOwnedConstants(t *testing.T) {
	err := errors.Join(errors.New("identity acquisition failed"), errors.New("pooled route change requires review"), errors.New("private-secret-value"))
	if got := safeFailureCodes(err); got != "identity-acquisition,route-change" || strings.Contains(got, "private-secret") {
		t.Fatal("bounded failure classification differs")
	}
	if safeFailureCodes(fmt.Errorf("secret wrapper: %w", errors.New("Nebula initialization failed"))) != "nebula-initialization" {
		t.Fatal("safe wrapped stage unavailable")
	}
	if safeFailureCodes(errors.New("pooled route change requires review: secret")) != "unclassified" {
		t.Fatal("non-exact external error escaped")
	}
	for i := 0; i < 100; i++ {
		err = fmt.Errorf("private nested details: %w", err)
	}
	if safeFailureCodes(err) != "unclassified" {
		t.Fatal("unbounded traversal")
	}
}
