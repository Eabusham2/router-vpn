//go:build darwin

package main

import (
	"context"
	"errors"
	"syscall"
)

func bindDesktopImportedMTUKernel(ctx context.Context, network string, handle uintptr, live desktopNodeMTURecord) error {
	if ctx == nil || live.Index < 1 || live.Index > 0x7fffffff {
		return errors.New("Darwin imported MTU socket has no captured interface")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	wantKind, ipv6 := syscall.SOCK_STREAM, false
	switch network {
	case "tcp4":
	case "tcp6":
		ipv6 = true
	case "udp4":
		wantKind = syscall.SOCK_DGRAM
	case "udp6":
		wantKind, ipv6 = syscall.SOCK_DGRAM, true
	default:
		return errors.New("Darwin imported MTU socket changed its captured transport")
	}
	fd := int(handle)
	kind, kindErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	address, addressErr := syscall.Getsockname(fd)
	_, is4 := address.(*syscall.SockaddrInet4)
	_, is6 := address.(*syscall.SockaddrInet6)
	if kindErr != nil || addressErr != nil || kind != wantKind || ipv6 && !is6 || !ipv6 && !is4 {
		return errors.Join(kindErr, addressErr, errors.New("Darwin imported MTU socket changed its actual type or address family"))
	}
	level, option := syscall.IPPROTO_IP, 25 // XNU IP_BOUND_IF.
	if ipv6 {
		level, option = syscall.IPPROTO_IPV6, 125 // XNU IPV6_BOUND_IF.
	}
	if err := syscall.SetsockoptInt(fd, level, option, live.Index); err != nil {
		return err
	}
	index, err := syscall.GetsockoptInt(fd, level, option)
	if err != nil || index != live.Index {
		return errors.Join(err, errors.New("Darwin imported MTU socket did not retain its exact kernel interface"))
	}
	return ctx.Err()
}
