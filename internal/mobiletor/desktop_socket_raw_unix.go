//go:build linux || darwin

package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
)

type desktopSocketKeeper struct {
	file *os.File
	once sync.Once
	err  error
}

func (k *desktopSocketKeeper) Close() error {
	k.once.Do(func() { k.err = k.file.Close() })
	return k.err
}

func desktopSocketNoReuse(fd int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 0); err != nil {
		return err
	}
	portOption := 15 // Linux SO_REUSEPORT; not exported by frozen syscall on amd64.
	if runtime.GOOS == "darwin" {
		portOption = 0x200
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, portOption, 0); err != nil && !errors.Is(err, syscall.ENOPROTOOPT) {
		return err
	}
	value, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR)
	if err != nil || value != 0 {
		return errors.New("desktop physical socket permits address reuse")
	}
	value, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, portOption)
	if errors.Is(err, syscall.ENOPROTOOPT) {
		return nil
	}
	if err != nil || value != 0 {
		return errors.New("desktop physical socket permits port reuse")
	}
	return nil
}

func desktopSocketExclusive(raw syscall.RawConn) error {
	var result error
	err := raw.Control(func(fd uintptr) { result = desktopSocketNoReuse(int(fd)) })
	return errors.Join(err, result)
}

func desktopSocketLocal(fd int) (netip.AddrPort, error) {
	address, err := syscall.Getsockname(fd)
	if err != nil {
		return netip.AddrPort{}, err
	}
	switch address := address.(type) {
	case *syscall.SockaddrInet4:
		if address.Port == 0 {
			break
		}
		return netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port)), nil
	case *syscall.SockaddrInet6:
		if address.Port == 0 || address.ZoneId != 0 {
			break
		}
		return netip.AddrPortFrom(netip.AddrFrom16(address.Addr), uint16(address.Port)), nil
	}
	return netip.AddrPort{}, errors.New("desktop physical socket has no exact bound address")
}

func desktopSocketDuplicate(fd int) (*desktopSocketKeeper, error) {
	duplicate, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(duplicate)
	return &desktopSocketKeeper{file: os.NewFile(uintptr(duplicate), "routervpn-owned-physical-socket")}, nil
}

func desktopSocketBindTCP(raw syscall.RawConn, address netip.Addr) (*desktopSocketKeeper, netip.AddrPort, error) {
	var keeper *desktopSocketKeeper
	var local netip.AddrPort
	var result error
	err := raw.Control(func(rawFD uintptr) {
		fd := int(rawFD)
		if result = desktopSocketNoReuse(fd); result != nil {
			return
		}
		var target syscall.Sockaddr
		if address.Is4() {
			target = &syscall.SockaddrInet4{Addr: address.As4()}
		} else {
			target = &syscall.SockaddrInet6{Addr: address.As16()}
		}
		if result = syscall.Bind(fd, target); result != nil {
			return
		}
		local, result = desktopSocketLocal(fd)
		if result != nil {
			return
		}
		keeper, result = desktopSocketDuplicate(fd)
	})
	return keeper, local, errors.Join(err, result)
}

func desktopSocketRetain(raw syscall.RawConn) (*desktopSocketKeeper, netip.AddrPort, error) {
	var keeper *desktopSocketKeeper
	var local netip.AddrPort
	var result error
	err := raw.Control(func(rawFD uintptr) {
		local, result = desktopSocketLocal(int(rawFD))
		if result != nil {
			return
		}
		keeper, result = desktopSocketDuplicate(int(rawFD))
	})
	return keeper, local, errors.Join(err, result)
}

func desktopSocketDialTCP(ctx context.Context, network string, remote netip.AddrPort, control func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
	dialer := net.Dialer{ControlContext: control}
	return dialer.DialContext(ctx, network, remote.String())
}
