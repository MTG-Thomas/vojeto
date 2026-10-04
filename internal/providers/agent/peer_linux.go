//go:build linux

package agent

import (
	"net"
	"os"
	"syscall"
)

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
func checkPeer(conn net.Conn) error {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return errRejected
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return errRejected
	}
	accepted := false
	err = raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		accepted = e == nil && int(cred.Uid) == os.Geteuid()
	})
	if err != nil || !accepted {
		return errRejected
	}
	return nil
}
