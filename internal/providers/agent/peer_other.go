//go:build !linux

package agent

import (
	"net"
	"os"
)

// Fail closed until another platform has a tested peer-credential implementation.
func owned(os.FileInfo) bool   { return false }
func checkPeer(net.Conn) error { return errRejected }
