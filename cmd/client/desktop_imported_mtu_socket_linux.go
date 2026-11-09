//go:build linux

package main

import (
	"context"
	"errors"
	"syscall"
)

// The caller brackets this operation with the exact active native lease and
// interface readback. The descriptor stays retained by RawConn.Control.
func bindDesktopImportedMTUKernel(ctx context.Context, network string, handle uintptr, live desktopNodeMTURecord) error {
	if ctx == nil || live.Index < 1 || live.Index > 0x7fffffff || validateMTULiveInterface(live.Interface) != nil {
		return errors.New("Linux imported MTU socket has no captured interface")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	wantKind, wantFamily := syscall.SOCK_STREAM, syscall.AF_INET
	switch network {
	case "tcp4":
	case "tcp6":
		wantFamily = syscall.AF_INET6
	case "udp4":
		wantKind = syscall.SOCK_DGRAM
	case "udp6":
		wantKind, wantFamily = syscall.SOCK_DGRAM, syscall.AF_INET6
	default:
		return errors.New("Linux imported MTU socket changed its captured transport")
	}
	fd := int(handle)
	kind, kindErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	family, familyErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if kindErr != nil || familyErr != nil || kind != wantKind || family != wantFamily {
		return errors.Join(kindErr, familyErr, errors.New("Linux imported MTU socket changed its actual type or address family"))
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, linuxNodeProofBindToIfIndex, live.Index); err != nil {
		return err
	}
	index, indexErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, linuxNodeProofBindToIfIndex)
	name, nameErr := desktopLinuxNodeProofBoundName(fd)
	if indexErr != nil || nameErr != nil || index != live.Index || name != live.Interface {
		return errors.Join(indexErr, nameErr, errors.New("Linux imported MTU socket did not retain its exact kernel interface"))
	}
	return ctx.Err()
}
