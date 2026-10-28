//go:build !linux && !darwin

package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
)

func desktopSocketImportTCP(context.Context, string, netip.AddrPort, *os.File, func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
	return nil, errors.New("this platform does not accept a Unix socket creator")
}

func desktopSocketImportPacket(context.Context, string, *os.File, netip.Addr, func(string, string, syscall.RawConn) error) (net.PacketConn, error) {
	return nil, errors.New("this platform does not accept a Unix socket creator")
}
