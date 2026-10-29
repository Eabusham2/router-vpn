package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

// Imported UDP uses the same bounded nonblocking Winsock ownership as TCP.
// A new destination is still authorized by desktopSocketPacket before WriteTo.
type desktopWindowsPacket struct{ *desktopWindowsSocket }

func (p *desktopWindowsPacket) SyscallConn() (syscall.RawConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.closed {
		return nil, net.ErrClosed
	}
	return desktopWindowsRaw{p.desktopWindowsSocket}, nil
}
func (p *desktopWindowsPacket) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(p.local) }

func (p *desktopWindowsPacket) ReadFrom(data []byte) (int, net.Addr, error) {
	if err := p.begin(); err != nil {
		return 0, nil, err
	}
	defer p.io.Done()
	p.read.Lock()
	defer p.read.Unlock()
	for {
		if _, err := p.state(context.Background(), false); err != nil {
			return 0, nil, err
		}
		var scratch byte
		buffer := syscall.WSABuf{Len: uint32(min(len(data), 65535)), Buf: &scratch}
		if len(data) != 0 {
			buffer.Buf = &data[0]
		}
		var received, flags uint32
		var address syscall.RawSockaddrAny
		size := int32(unsafe.Sizeof(address))
		err := syscall.WSARecvFrom(p.handle, &buffer, 1, &received, &flags, &address, &size, nil, nil)
		if errors.Is(err, desktopSocketWouldBlock) {
			if err = p.wait(context.Background(), false); err != nil {
				return 0, nil, err
			}
			continue
		}
		if err != nil {
			return 0, nil, err
		}
		if received > buffer.Len || flags != 0 {
			return 0, nil, errors.New("Windows physical UDP receive was truncated or changed its flags")
		}
		peer, err := address.Sockaddr()
		if err != nil {
			return 0, nil, err
		}
		var remote netip.AddrPort
		switch peer := peer.(type) {
		case *syscall.SockaddrInet4:
			if size != int32(unsafe.Sizeof(syscall.RawSockaddrInet4{})) {
				return 0, nil, errors.New("Windows physical UDP address length changed")
			}
			remote = netip.AddrPortFrom(netip.AddrFrom4(peer.Addr), uint16(peer.Port))
		case *syscall.SockaddrInet6:
			if size != int32(unsafe.Sizeof(syscall.RawSockaddrInet6{})) || peer.ZoneId != 0 {
				return 0, nil, errors.New("Windows physical UDP address length or scope changed")
			}
			remote = netip.AddrPortFrom(netip.AddrFrom16(peer.Addr), uint16(peer.Port))
		default:
			return 0, nil, errors.New("Windows physical UDP source family changed")
		}
		if !remote.IsValid() || remote.Port() == 0 || remote.Addr().Is4() != p.local.Addr().Is4() || remote.Addr().Is4In6() {
			return 0, nil, errors.New("Windows physical UDP source address changed")
		}
		return int(received), net.UDPAddrFromAddrPort(remote), nil
	}
}

func (p *desktopWindowsPacket) WriteTo(data []byte, address net.Addr) (int, error) {
	peer, ok := address.(*net.UDPAddr)
	if !ok || peer == nil {
		return 0, errors.New("Windows physical UDP requires a numeric destination")
	}
	remote := peer.AddrPort()
	if !remote.IsValid() || remote.Port() == 0 || remote.Addr().Zone() != "" || remote.Addr().Is4In6() || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Is4() != p.local.Addr().Is4() || len(data) > 65535 {
		return 0, errors.New("Windows physical UDP destination family or datagram length changed")
	}
	if err := p.begin(); err != nil {
		return 0, err
	}
	defer p.io.Done()
	p.write.Lock()
	defer p.write.Unlock()
	var target syscall.RawSockaddrAny
	var size int32
	port := remote.Port()<<8 | remote.Port()>>8
	if remote.Addr().Is4() {
		value := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&target))
		*value = syscall.RawSockaddrInet4{Family: syscall.AF_INET, Port: port, Addr: remote.Addr().As4()}
		size = int32(unsafe.Sizeof(*value))
	} else {
		value := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&target))
		*value = syscall.RawSockaddrInet6{Family: syscall.AF_INET6, Port: port, Addr: remote.Addr().As16()}
		size = int32(unsafe.Sizeof(*value))
	}
	for {
		if _, err := p.state(context.Background(), true); err != nil {
			return 0, err
		}
		var scratch byte
		buffer := syscall.WSABuf{Len: uint32(len(data)), Buf: &scratch}
		if len(data) != 0 {
			buffer.Buf = &data[0]
		}
		var sent uint32
		err := syscall.WSASendTo(p.handle, &buffer, 1, &sent, 0, &target, size, nil, nil)
		if errors.Is(err, desktopSocketWouldBlock) && sent == 0 {
			if err = p.wait(context.Background(), true); err != nil {
				return 0, err
			}
			continue
		}
		if sent > buffer.Len {
			return 0, errors.New("Windows physical UDP send length changed")
		}
		if err != nil {
			return int(sent), err
		}
		if sent != buffer.Len {
			return int(sent), io.ErrShortWrite
		}
		return int(sent), nil
	}
}
