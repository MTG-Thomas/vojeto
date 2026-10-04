package main

import (
	"errors"
	"time"
)

func validateAdmission(maximum int, signalGrace time.Duration) error {
	if maximum < 1 {
		return errors.New("invalid connection limit")
	}
	if signalGrace < 0 {
		return errors.New("invalid signal grace")
	}
	return nil
}
