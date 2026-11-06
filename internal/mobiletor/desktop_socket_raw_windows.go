package mobiletor

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var desktopSocketWinsock = syscall.NewLazyDLL("ws2_32.dll")
var desktopSocketDuplicateProc = desktopSocketWinsock.NewProc("WSADuplicateSocketW")
var desktopSocketCreateProc = desktopSocketWinsock.NewProc("WSASocketW")
var desktopSocketErrorProc = desktopSocketWinsock.NewProc("WSAGetLastError")

type desktopSocketKeeper struct {
	handle syscall.Handle
	once   sync.Once
	err    error
}

func (k *desktopSocketKeeper) Close() error {
	k.once.Do(func() { k.err = syscall.Closesocket(k.handle) })
	return k.err
}

func desktopSocketWinsockError() error {
	value, _, _ := desktopSocketErrorProc.Call()
	if value == 0 {
		return errors.New("desktop physical Winsock operation failed")
	}
	return syscall.Errno(value)
}

func desktopSocketNoReuse(fd syscall.Handle) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 0); err != nil {
		return err
	}
	const exclusiveAddressUse = -5 // SO_EXCLUSIVEADDRUSE, before bind.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, exclusiveAddressUse, 1); err != nil {
		return err
	}
	value, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, exclusiveAddressUse)
	if err != nil || value == 0 {
		return errors.New("desktop physical socket has no exclusive Windows bind")
	}
	return nil
}

func desktopSocketExclusive(raw syscall.RawConn) error {
	var result error
	err := raw.Control(func(fd uintptr) { result = desktopSocketNoReuse(syscall.Handle(fd)) })
	return errors.Join(err, result)
}

func desktopSocketLocal(fd syscall.Handle) (netip.AddrPort, error) {
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

// Read the actual provider tuple at each ownership boundary. This does not
// bind, connect, close, or substitute a descriptor.
func desktopWindowsSocketProtocolInfo(fd syscall.Handle) (syscall.WSAProtocolInfo, error) {
	var info syscall.WSAProtocolInfo
	size := int32(unsafe.Sizeof(info))
	const protocolInfoW = 0x2005 // SO_PROTOCOL_INFOW
	if err := syscall.Getsockopt(fd, syscall.SOL_SOCKET, protocolInfoW, (*byte)(unsafe.Pointer(&info)), &size); err != nil {
		return info, err
	}
	if size != int32(unsafe.Sizeof(info)) {
		return info, fmt.Errorf("Windows socket protocol information size changed (bytes %d/%d)", size, unsafe.Sizeof(info))
	}
	return info, nil
}

func desktopWindowsSocketProtocol(fd syscall.Handle, family, kind, protocol int) error {
	info, err := desktopWindowsSocketProtocolInfo(fd)
	if err != nil {
		return err
	}
	if info.AddressFamily != int32(family) || info.SocketType != int32(kind) || info.Protocol != int32(protocol) {
		// SO_TYPE is an additional diagnostic only. It can never replace a
		// failed SO_PROTOCOL_INFOW check or admit a different provider tuple.
		actualKind, typeErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, 0x1008 /* SO_TYPE */)
		return errors.Join(fmt.Errorf("Windows socket creator changed the kernel family or protocol (family %d/%d, type %d/%d, protocol %d/%d; SO_TYPE %d)",
			info.AddressFamily, family, info.SocketType, kind, info.Protocol, protocol, actualKind), typeErr)
	}
	return nil
}

func desktopSocketDuplicate(fd syscall.Handle) (*desktopSocketKeeper, error) {
	// WSAGetLastError is thread-local. Capture it on the same OS thread as
	// the failing native call, before any other Winsock operation can run.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	source, err := desktopWindowsSocketProtocolInfo(fd)
	if err != nil {
		return nil, fmt.Errorf("Windows duplicate source protocol readback: %w", err)
	}
	var info syscall.WSAProtocolInfo
	result, _, _ := desktopSocketDuplicateProc.Call(uintptr(fd), uintptr(syscall.Getpid()), uintptr(unsafe.Pointer(&info)))
	if result != 0 {
		return nil, desktopSocketWinsockError()
	}
	// The retained handle never performs I/O or acquires a second IOCP owner.
	// It exists solely to reserve the exact socket until policy deletion joins.
	const flags = 0x01 | 0x80 // OVERLAPPED | NO_HANDLE_INHERIT
	duplicate, _, _ := desktopSocketCreateProc.Call(^uintptr(0), ^uintptr(0), ^uintptr(0), uintptr(unsafe.Pointer(&info)), 0, flags)
	if duplicate == ^uintptr(0) {
		return nil, desktopSocketWinsockError()
	}
	keeper := &desktopSocketKeeper{handle: syscall.Handle(duplicate)}
	// Consume the one-use duplication data before checking its fields so a
	// failure still has an owned descriptor to retire. Never silently close
	// or discard an acquired handle while its caller retains the original.
	if info.AddressFamily != source.AddressFamily || info.SocketType != source.SocketType || info.Protocol != source.Protocol {
		return keeper, fmt.Errorf("Windows duplicate transfer metadata changed its source protocol (family %d/%d, type %d/%d, protocol %d/%d)",
			info.AddressFamily, source.AddressFamily, info.SocketType, source.SocketType, info.Protocol, source.Protocol)
	}
	if err := desktopWindowsSocketProtocol(keeper.handle, int(source.AddressFamily), int(source.SocketType), int(source.Protocol)); err != nil {
		return keeper, fmt.Errorf("Windows duplicated descriptor protocol readback: %w", err)
	}
	return keeper, nil
}

func desktopSocketBindTCP(raw syscall.RawConn, address netip.Addr) (*desktopSocketKeeper, netip.AddrPort, error) {
	var keeper *desktopSocketKeeper
	var local netip.AddrPort
	var result error
	err := raw.Control(func(rawFD uintptr) {
		fd := syscall.Handle(rawFD)
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
		local, result = desktopSocketLocal(syscall.Handle(rawFD))
		if result != nil {
			return
		}
		keeper, result = desktopSocketDuplicate(syscall.Handle(rawFD))
	})
	return keeper, local, errors.Join(err, result)
}
