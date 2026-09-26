//go:build windows

package startwhitening

import "syscall"

func setUDPBuffers(fd uintptr) error {
	if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, UDPSocketBufferBytes); err != nil {
		return err
	}
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, UDPSocketBufferBytes)
}
