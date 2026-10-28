//go:build !linux && !darwin && !windows

package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

type desktopSocketKeeper struct{}

func (*desktopSocketKeeper) Close() error { return nil }
func desktopSocketExclusive(syscall.RawConn) error {
	return errors.New("this platform has no captured physical socket adapter")
}
func desktopSocketBindTCP(syscall.RawConn, netip.Addr) (*desktopSocketKeeper, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, errors.New("this platform has no captured physical socket adapter")
}
func desktopSocketRetain(syscall.RawConn) (*desktopSocketKeeper, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, errors.New("this platform has no captured physical socket adapter")
}

func desktopSocketDialTCP(context.Context, string, netip.AddrPort, func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
	return nil, errors.New("this platform has no captured physical socket adapter")
}
