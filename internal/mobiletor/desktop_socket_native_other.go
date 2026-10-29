//go:build !windows

package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

func desktopSocketImportNativeTCP(context.Context, string, netip.AddrPort, DesktopSocketNative, func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
	return nil, errors.New("this platform requires a transferred Unix socket descriptor")
}

func desktopSocketImportNativePacket(context.Context, string, DesktopSocketNative, netip.Addr, func(string, string, syscall.RawConn) error) (net.PacketConn, error) {
	return nil, errors.New("this platform requires a transferred Unix socket descriptor")
}
