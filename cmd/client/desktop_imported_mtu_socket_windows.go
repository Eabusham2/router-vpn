//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"
)

func bindDesktopImportedMTUKernel(ctx context.Context, network string, handle uintptr, live desktopNodeMTURecord) error {
	if ctx == nil || live.Index < 1 || live.Index > 0x7fffffff {
		return errors.New("Windows imported MTU socket has no captured interface")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	wantKind, wantProtocol, ipv6 := int32(syscall.SOCK_STREAM), int32(syscall.IPPROTO_TCP), false
	switch network {
	case "tcp4":
	case "tcp6":
		ipv6 = true
	case "udp4":
		wantKind, wantProtocol = syscall.SOCK_DGRAM, syscall.IPPROTO_UDP
	case "udp6":
		wantKind, wantProtocol, ipv6 = syscall.SOCK_DGRAM, syscall.IPPROTO_UDP, true
	default:
		return errors.New("Windows imported MTU socket changed its captured transport")
	}
	fd := syscall.Handle(handle)
	// Dialer.ControlContext runs before bind/connect. SO_PROTOCOL_INFOW reads
	// an unbound socket's real family without requiring getsockname to succeed.
	var info syscall.WSAProtocolInfo
	size := int32(unsafe.Sizeof(info))
	err := syscall.Getsockopt(fd, syscall.SOL_SOCKET, 0x2005, (*byte)(unsafe.Pointer(&info)), &size)
	wantFamily := int32(syscall.AF_INET)
	if ipv6 {
		wantFamily = syscall.AF_INET6
	}
	if err != nil || size != int32(unsafe.Sizeof(info)) || info.SocketType != wantKind || info.Protocol != wantProtocol || info.AddressFamily != wantFamily {
		return errors.Join(err, errors.New("Windows imported MTU socket changed its actual type, protocol or address family"))
	}
	level, option, value := syscall.IPPROTO_IPV6, 31, live.Index // IPV6_UNICAST_IF: host order.
	if !ipv6 {
		level = syscall.IPPROTO_IP
		// IP_UNICAST_IF accepts network byte order but reads back host order,
		// matching the retained Windows physical-socket policy implementation.
		var index [4]byte
		binary.BigEndian.PutUint32(index[:], uint32(live.Index))
		value = int(binary.LittleEndian.Uint32(index[:]))
	}
	if err := syscall.SetsockoptInt(fd, level, option, value); err != nil {
		return err
	}
	index, err := syscall.GetsockoptInt(fd, level, option)
	if err != nil || index != live.Index {
		return errors.Join(err, errors.New("Windows imported MTU socket did not retain its exact kernel interface"))
	}
	return ctx.Err()
}
