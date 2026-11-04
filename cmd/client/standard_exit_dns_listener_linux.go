//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var errLegacyDNSListenerNotFound = errors.New("original legacy child has no captured DNS proof listener")

type legacyDNSListenerIdentity struct {
	device, inode, cookie uint64
}

type legacyDNSListener struct {
	pidfd    *os.File
	pidInfo  os.FileInfo
	targetFD int
	file     *os.File
	identity legacyDNSListenerIdentity
	endpoint netip.AddrPort
}

func legacyDNSDuplicateChildFD(pidfd *os.File, target int) (*os.File, error) {
	if pidfd == nil || target < 0 || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, errors.New("legacy DNS listener requires its original pidfd and supported native ABI")
	}
	// This duplicates from the creation-time process descriptor. A numeric PID
	// or /proc directory can never authorize the socket transfer.
	raw, err := pidfd.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd uintptr
	var errno syscall.Errno
	if err := raw.Control(func(original uintptr) {
		fd, _, errno = syscall.Syscall(438, original, uintptr(target), 0) // pidfd_getfd, Linux x64/ARM64
	}); err != nil {
		return nil, err
	}
	if errno != 0 {
		return nil, os.NewSyscallError("pidfd_getfd original DNS listener", errno)
	}
	return os.NewFile(fd, "original-legacy-dns-listener"), nil
}

func legacyDNSListenerSnapshot(file *os.File, endpoint netip.AddrPort) (legacyDNSListenerIdentity, error) {
	var result legacyDNSListenerIdentity
	if file == nil || !endpoint.IsValid() || !endpoint.Addr().Is4() || !endpoint.Addr().IsLoopback() {
		return result, errors.New("legacy DNS listener has no original loopback endpoint")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return result, err
	}
	var readErr error
	if err := raw.Control(func(fd uintptr) { result, readErr = legacyDNSListenerSnapshotFD(int(fd), endpoint) }); err != nil {
		return result, err
	}
	return result, readErr
}

func legacyDNSListenerSnapshotFD(fd int, endpoint netip.AddrPort) (legacyDNSListenerIdentity, error) {
	var result legacyDNSListenerIdentity
	address, err := syscall.Getsockname(fd)
	if errors.Is(err, syscall.ENOTSOCK) {
		return result, errLegacyDNSListenerNotFound
	}
	if err != nil {
		return result, err
	}
	ipv4, ok := address.(*syscall.SockaddrInet4)
	if !ok || netip.AddrPortFrom(netip.AddrFrom4(ipv4.Addr), uint16(ipv4.Port)) != endpoint {
		return result, errLegacyDNSListenerNotFound
	}
	for _, check := range []struct{ option, expected int }{
		{syscall.SO_TYPE, syscall.SOCK_STREAM}, {syscall.SO_ACCEPTCONN, 1},
		{38 /* SO_PROTOCOL */, syscall.IPPROTO_TCP}, {39 /* SO_DOMAIN */, syscall.AF_INET}, {15 /* SO_REUSEPORT */, 0},
	} {
		actual, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, check.option)
		if err != nil || actual != check.expected {
			return result, errors.Join(err, errors.New("legacy DNS listener changed native type, state or exclusive ownership"))
		}
	}
	var native syscall.Stat_t
	if err := syscall.Fstat(fd, &native); err != nil || native.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return result, errors.Join(err, errors.New("legacy DNS listener has no original socket inode"))
	}
	var cookie uint64
	size := uint32(unsafe.Sizeof(cookie))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, 57, /* SO_COOKIE */
		uintptr(unsafe.Pointer(&cookie)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 || size != 8 || cookie == 0 {
		return result, errors.Join(errno, errors.New("legacy DNS listener has no captured native socket cookie"))
	}
	return legacyDNSListenerIdentity{uint64(native.Dev), native.Ino, cookie}, nil
}

func captureLegacyDNSListener(ctx context.Context, pidfd *os.File, endpoint netip.AddrPort) (*legacyDNSListener, error) {
	if ctx == nil || ctx.Err() != nil || pidfd == nil {
		return nil, errors.New("legacy DNS listener capture has no live original process")
	}
	info, err := pidfd.Stat()
	if err != nil {
		return nil, err
	}
	retired, err := legacyExitPIDFDState(pidfd)
	if err != nil || retired {
		return nil, errors.Join(err, errors.New("legacy DNS listener process is no longer live"))
	}
	// A bounded descriptor scan uses only the original pidfd. It neither
	// reacquires process authority by PID nor assumes /proc shares our PID
	// namespace. A listener beyond this inventory bound is never adopted.
	var owned *legacyDNSListener
	for number := 0; number < 4096; number++ {
		if ctx.Err() != nil {
			if owned != nil {
				_ = owned.Close()
			}
			return nil, ctx.Err()
		}
		file, err := legacyDNSDuplicateChildFD(pidfd, number)
		if errors.Is(err, syscall.EBADF) {
			continue
		} // An unrelated descriptor closed during enumeration.
		if err != nil {
			if owned != nil {
				_ = owned.Close()
			}
			return nil, err
		}
		identity, err := legacyDNSListenerSnapshot(file, endpoint)
		if errors.Is(err, errLegacyDNSListenerNotFound) {
			if err := file.Close(); err != nil {
				if owned != nil {
					_ = owned.Close()
				}
				return nil, err
			}
			continue
		}
		if err != nil || owned != nil {
			_ = file.Close()
			if owned != nil {
				_ = owned.Close()
			}
			return nil, errors.Join(err, errors.New("legacy DNS listener identity is invalid or repeated"))
		}
		owned = &legacyDNSListener{pidfd: pidfd, pidInfo: info, targetFD: number, file: file, identity: identity, endpoint: endpoint}
	}
	if owned == nil {
		return nil, errLegacyDNSListenerNotFound
	}
	if err := owned.Current(); err != nil {
		_ = owned.Close()
		return nil, err
	}
	return owned, nil
}

func (l *legacyDNSListener) Current() error {
	if l == nil || l.file == nil || l.pidfd == nil {
		return errors.New("legacy DNS listener capture is closed")
	}
	info, err := l.pidfd.Stat()
	if err != nil || !os.SameFile(info, l.pidInfo) {
		return errors.New("legacy DNS listener lost original process descriptor")
	}
	current, err := legacyDNSListenerSnapshot(l.file, l.endpoint)
	if err != nil || current != l.identity {
		return errors.Join(err, errors.New("retained DNS listener socket changed"))
	}
	member, err := legacyDNSDuplicateChildFD(l.pidfd, l.targetFD)
	if err != nil {
		return err
	}
	actual, readErr := legacyDNSListenerSnapshot(member, l.endpoint)
	closeErr := member.Close()
	if readErr != nil || closeErr != nil || actual != l.identity {
		return errors.Join(readErr, closeErr, errors.New("original process no longer owns its captured DNS listener"))
	}
	return nil
}

func (l *legacyDNSListener) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	if err == nil {
		l.file = nil
	}
	return err
}
