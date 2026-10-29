package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"
)

// An imported Winsock socket is not an os.File: CloseHandle is not its close
// primitive. Control and Close serialize against the exact retained handle.
type desktopWindowsNativeSocket struct {
	mu     sync.Mutex
	handle syscall.Handle
	closed bool
}

type desktopWindowsNativeRaw struct{ socket *desktopWindowsNativeSocket }

func desktopWindowsNativeOwn(handle syscall.Handle) DesktopSocketNative {
	return &desktopWindowsNativeSocket{handle: handle}
}

func desktopWindowsNativeDuplicate(raw syscall.RawConn) (DesktopSocketNative, error) {
	if raw == nil {
		return nil, errors.New("Windows socket duplicate requires its captured raw owner")
	}
	var owned DesktopSocketNative
	var result error
	err := raw.Control(func(handle uintptr) {
		var keeper *desktopSocketKeeper
		keeper, result = desktopSocketDuplicate(syscall.Handle(handle))
		if keeper != nil {
			// Ownership is consumed here; keeper has no finalizer or second close.
			owned = desktopWindowsNativeOwn(keeper.handle)
		}
	})
	return owned, errors.Join(err, result)
}

func (s *desktopWindowsNativeSocket) SyscallConn() (syscall.RawConn, error) {
	if s == nil {
		return nil, net.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.handle == syscall.InvalidHandle {
		return nil, net.ErrClosed
	}
	return desktopWindowsNativeRaw{s}, nil
}

func (s *desktopWindowsNativeSocket) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := syscall.Closesocket(s.handle); err != nil {
		return err
	}
	s.closed = true
	return nil
}

func (r desktopWindowsNativeRaw) Control(f func(uintptr)) error {
	if r.socket == nil || f == nil {
		return net.ErrClosed
	}
	r.socket.mu.Lock()
	defer r.socket.mu.Unlock()
	if r.socket.closed || r.socket.handle == syscall.InvalidHandle {
		return net.ErrClosed
	}
	f(uintptr(r.socket.handle))
	return nil
}
func (desktopWindowsNativeRaw) Read(func(uintptr) bool) error {
	return errors.New("Windows source sockets permit captured control only")
}
func (desktopWindowsNativeRaw) Write(func(uintptr) bool) error {
	return errors.New("Windows source sockets permit captured control only")
}

// SO_PROTOCOL_INFOW verifies the real family, type and protocol before bind.
// Windows getsockname returns WSAEINVAL for an unbound socket, unlike Unix.
// No socket is imported if it already owns a local tuple, listener or peer.
func desktopSocketNativeRaw(source DesktopSocketNative, network string, address netip.Addr) (syscall.RawConn, string, error) {
	if source == nil || (network != "tcp" && network != "udp") || !address.IsValid() {
		return nil, "", errors.New("Windows socket creator supplied no exact source")
	}
	raw, err := source.SyscallConn()
	if err != nil || raw == nil {
		return nil, "", errors.Join(err, net.ErrClosed)
	}
	actual := network + "6"
	family, kind, protocol := syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP
	if address.Is4() {
		family, actual = syscall.AF_INET, network+"4"
	}
	if network == "udp" {
		kind, protocol = syscall.SOCK_DGRAM, syscall.IPPROTO_UDP
	}
	var result error
	err = raw.Control(func(handle uintptr) {
		fd := syscall.Handle(handle)
		var info syscall.WSAProtocolInfo
		size := int32(unsafe.Sizeof(info))
		const protocolInfoW = 0x2005
		if result = syscall.Getsockopt(fd, syscall.SOL_SOCKET, protocolInfoW, (*byte)(unsafe.Pointer(&info)), &size); result != nil {
			return
		}
		if size != int32(unsafe.Sizeof(info)) || info.AddressFamily != int32(family) || info.SocketType != int32(kind) || info.Protocol != int32(protocol) {
			result = errors.New("Windows socket creator changed the kernel family or protocol")
			return
		}
		// SO_ACCEPTCONN is defined only for connection-oriented sockets on
		// Windows. The independent protocol readback above has already proved
		// SOCK_DGRAM/IPPROTO_UDP for a packet source; it cannot be a TCP listener.
		// An unknown TCP listener state still fails rather than ignoring errors.
		if network == "tcp" {
			listening, readErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, 0x0002 /* SO_ACCEPTCONN */)
			if readErr != nil || listening != 0 {
				result = errors.Join(readErr, errors.New("Windows socket creator supplied a listener or unproved listening state"))
				return
			}
		}
		if _, readErr := syscall.Getsockname(fd); !errors.Is(readErr, syscall.Errno(10022) /* WSAEINVAL */) {
			result = errors.New("Windows socket creator already bound a tuple")
			return
		}
		if _, readErr := syscall.Getpeername(fd); !errors.Is(readErr, desktopSocketNotConnected) && !errors.Is(readErr, syscall.Errno(10022) /* WSAEINVAL */) {
			result = errors.New("Windows socket creator connected before permission acknowledgment")
			return
		}
		if family == syscall.AF_INET6 {
			if result = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); result != nil {
				return
			}
			only, readErr := syscall.GetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
			if readErr != nil || only != 1 {
				result = errors.Join(readErr, errors.New("Windows source socket lost its exact IPv6 family"))
				return
			}
		}
		if network == "udp" {
			// Match the native Go packet socket's behavior: an ICMP error from
			// one failed ICE/STUN peer must not terminate this shared UDP socket.
			// This changes error delivery only; every destination still requires
			// its separately acknowledged physical permit before any datagram.
			var disabled, returned uint32
			if result = syscall.WSAIoctl(fd, syscall.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&disabled)), uint32(unsafe.Sizeof(disabled)), nil, 0, &returned, nil, 0); result != nil {
				return
			}
		}
		if result = syscall.SetHandleInformation(fd, syscall.HANDLE_FLAG_INHERIT, 0); result != nil {
			return
		}
	})
	if err != nil || result != nil {
		return nil, "", errors.Join(err, result)
	}
	return raw, actual, nil
}

func desktopSocketImportNativeTCP(ctx context.Context, network string, remote netip.AddrPort, source DesktopSocketNative, control func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
	return desktopSocketImportNativeTCPWithConnect(ctx, network, remote, source, control, desktopSocketConnectOwnedTCP)
}

// A captured source may own the bind-to-connected ALE transition. Its hooks
// receive the actual imported I/O object before any connect operation, never a
// caller-supplied endpoint number or a descriptor recovered after completion.
type desktopWindowsNativeTCPSource interface {
	beginNativeTCP(context.Context, *desktopWindowsSocket) error
	finishNativeTCP(context.Context, *desktopWindowsSocket, error) error
}

// The connector seam holds the real entered operation in cancellation tests.
// Production always supplies the shipping Winsock connect implementation above.
func desktopSocketImportNativeTCPWithConnect(ctx context.Context, network string, remote netip.AddrPort, source DesktopSocketNative, control func(context.Context, string, string, syscall.RawConn) error, connect func(context.Context, *desktopWindowsSocket) error) (net.Conn, error) {
	raw, actual, err := desktopSocketNativeRaw(source, "tcp", remote.Addr())
	if err != nil {
		return nil, err
	}
	if ctx == nil || ctx.Err() != nil || control == nil || connect == nil || (network != "tcp" && network != actual) {
		return nil, net.ErrClosed
	}
	// The exact source handle is used for Bind and acknowledged Grant. Its
	// retained original and every duplicate refer to the same ALE endpoint.
	if err := control(ctx, actual, remote.String(), raw); err != nil {
		return nil, err
	}
	var keeper *desktopSocketKeeper
	var result error
	err = raw.Control(func(handle uintptr) { keeper, result = desktopSocketDuplicate(syscall.Handle(handle)) })
	if keeper == nil {
		return nil, errors.Join(err, result)
	}
	c := &desktopWindowsSocket{handle: keeper.handle, remote: remote}
	if err != nil || result != nil {
		return c, errors.Join(err, result)
	}
	if err := desktopSocketNonblocking(c.handle); err != nil {
		return c, err
	}
	// An entered import keeps the I/O descriptor alive through registration,
	// connection and final proof. Close joins it without holding the short raw
	// control mutex, so the policy can renew and inspect a pending connection.
	if err := c.begin(); err != nil {
		return c, err
	}
	defer c.io.Done()
	observer, observed := source.(desktopWindowsNativeTCPSource)
	if observed {
		if err := observer.beginNativeTCP(ctx, c); err != nil {
			return c, err
		}
	}
	connectErr := connect(ctx, c)
	if observed {
		connectErr = errors.Join(connectErr, observer.finishNativeTCP(ctx, c, connectErr))
	}
	if connectErr != nil {
		return c, connectErr
	}
	return c, nil
}

func desktopSocketImportNativePacket(ctx context.Context, network string, source DesktopSocketNative, local netip.Addr, control func(string, string, syscall.RawConn) error) (net.PacketConn, error) {
	raw, actual, err := desktopSocketNativeRaw(source, "udp", local)
	if err != nil {
		return nil, err
	}
	if ctx == nil || ctx.Err() != nil || control == nil || (network != "udp" && network != actual) {
		return nil, net.ErrClosed
	}
	if err := control(actual, netip.AddrPortFrom(local, 0).String(), raw); err != nil {
		return nil, err
	}
	var keeper *desktopSocketKeeper
	var bound netip.AddrPort
	var result error
	err = raw.Control(func(handle uintptr) {
		fd := syscall.Handle(handle)
		var target syscall.Sockaddr = &syscall.SockaddrInet6{Addr: local.As16()}
		if local.Is4() {
			target = &syscall.SockaddrInet4{Addr: local.As4()}
		}
		if result = syscall.Bind(fd, target); result != nil {
			return
		}
		bound, result = desktopSocketLocal(fd)
		if result != nil {
			return
		}
		keeper, result = desktopSocketDuplicate(fd)
	})
	if keeper == nil {
		return nil, errors.Join(err, result)
	}
	c := &desktopWindowsPacket{desktopWindowsSocket: &desktopWindowsSocket{handle: keeper.handle, local: bound}}
	if err != nil || result != nil || ctx.Err() != nil {
		return c, errors.Join(err, result, ctx.Err())
	}
	if err := desktopSocketNonblocking(c.handle); err != nil {
		return c, err
	}
	return c, nil
}
