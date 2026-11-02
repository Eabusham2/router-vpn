//go:build linux

package installcap

import (
	"errors"
	"syscall"
	"unsafe"
)

// Linux exercises the same receiver and real file-description lifetimes in
// isolated executable tests. Darwin uses its own public peer ABI below.
func checkPeer(fd, expected int) error {
	var info syscall.Stat_t
	kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil || kind != syscall.SOCK_STREAM || syscall.Fstat(fd, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFSOCK || info.Uid != 0 {
		return errors.New("installer channel is not its anonymous root-created stream")
	}
	peer, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || peer.Uid != 0 || int(peer.Pid) != expected {
		return errors.New("installer channel has another original kernel peer")
	}
	for _, call := range []uintptr{syscall.SYS_GETSOCKNAME, syscall.SYS_GETPEERNAME} {
		var address syscall.RawSockaddrUnix
		size := uint32(unsafe.Sizeof(address))
		_, _, errno := syscall.Syscall(call, uintptr(fd), uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Pointer(&size)))
		if errno != 0 || size != 2 || address.Family != syscall.AF_UNIX {
			return errors.New("installer channel is named or disconnected")
		}
	}
	return nil
}
