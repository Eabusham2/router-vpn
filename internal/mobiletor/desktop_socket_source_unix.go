//go:build linux || darwin

package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// A transferred descriptor is imported using net.FileConn/FilePacketConn.
// Those APIs duplicate the actual kernel socket; they do not create a socket
// with the receiver's credentials. Bind/Grant must still verify its creator.
func desktopSocketSourceRaw(file *os.File, network string, address netip.Addr) (syscall.RawConn, string, error) {
	if file == nil || (network != "tcp" && network != "udp") || !address.IsValid() {
		return nil, "", errors.New("desktop socket creator supplied no socket")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, "", err
	}
	actualNetwork := network + "6"
	if address.Is4() {
		actualNetwork = network + "4"
	}
	var result error
	err = raw.Control(func(handle uintptr) {
		fd := int(handle)
		var stat syscall.Stat_t
		if result = syscall.Fstat(fd, &stat); result != nil {
			return
		}
		if stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
			result = errors.New("desktop socket creator returned a non-socket descriptor")
			return
		}
		typeValue, readErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
		wantType := syscall.SOCK_STREAM
		if network == "udp" {
			wantType = syscall.SOCK_DGRAM
		}
		if readErr != nil || typeValue != wantType {
			result = errors.New("desktop socket creator changed the kernel protocol")
			return
		}
		listening, readErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
		if readErr != nil || listening != 0 {
			result = errors.New("desktop socket creator returned a listening socket")
			return
		}
		local, readErr := syscall.Getsockname(fd)
		unbound := false
		if address.Is4() {
			value, ok := local.(*syscall.SockaddrInet4)
			unbound = ok && value.Port == 0 && value.Addr == [4]byte{}
		} else {
			value, ok := local.(*syscall.SockaddrInet6)
			unbound = ok && value.Port == 0 && value.ZoneId == 0 && value.Addr == [16]byte{}
		}
		if readErr != nil || !unbound {
			result = errors.New("desktop socket creator changed its family or already bound a tuple")
			return
		}
		if _, readErr := syscall.Getpeername(fd); !errors.Is(readErr, syscall.ENOTCONN) {
			result = errors.New("desktop socket creator connected before permit acknowledgment")
			return
		}
		// The received descriptor must not escape into any later native child.
		syscall.CloseOnExec(fd)
	})
	if err != nil || result != nil {
		return nil, "", errors.Join(err, result)
	}
	return raw, actualNetwork, nil
}

type desktopImportedTCP struct {
	*net.TCPConn
	remote netip.AddrPort
}

func (c *desktopImportedTCP) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.remote) }

func desktopSocketImportTCP(ctx context.Context, network string, remote netip.AddrPort, file *os.File, control func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
	raw, actualNetwork, err := desktopSocketSourceRaw(file, "tcp", remote.Addr())
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || (network != "tcp" && network != actualNetwork) {
		return nil, net.ErrClosed
	}
	// The same control callback as the ordinary creator binds the actual FD,
	// retains its duplicate and installs/read-backs the exact full permit.
	if err := control(ctx, actualNetwork, remote.String(), raw); err != nil {
		return nil, err
	}
	connection, err := net.FileConn(file)
	if err != nil {
		return connection, err
	}
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		return connection, errors.New("desktop socket import changed TCP into another kernel protocol")
	}
	owned := &desktopImportedTCP{TCPConn: tcp, remote: remote}
	if err := desktopSocketConnectImported(ctx, tcp, remote); err != nil {
		return owned, err
	}
	return owned, nil
}

func desktopSocketConnectImported(ctx context.Context, connection *net.TCPConn, remote netip.AddrPort) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if until, ok := ctx.Deadline(); ok {
		if err := connection.SetWriteDeadline(until); err != nil {
			return err
		}
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = connection.SetWriteDeadline(time.Now())
		close(interrupted)
	})
	interruptJoined := false
	defer func() {
		if !interruptJoined && !stop() {
			<-interrupted
		}
	}()
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var target syscall.Sockaddr
	if remote.Addr().Is4() {
		target = &syscall.SockaddrInet4{Addr: remote.Addr().As4(), Port: int(remote.Port())}
	} else {
		target = &syscall.SockaddrInet6{Addr: remote.Addr().As16(), Port: int(remote.Port())}
	}
	started := false
	var result error
	err = raw.Write(func(handle uintptr) bool {
		if result = ctx.Err(); result != nil {
			return true
		}
		fd := int(handle)
		if !started {
			started = true
			result = syscall.Connect(fd, target)
			if errors.Is(result, syscall.EINPROGRESS) || errors.Is(result, syscall.EALREADY) || errors.Is(result, syscall.EINTR) {
				result = nil
				return false
			}
			if result != nil && !errors.Is(result, syscall.EISCONN) {
				return true
			}
			result = nil
		}
		value, readErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if readErr != nil {
			result = readErr
			return true
		}
		if value == int(syscall.EINPROGRESS) || value == int(syscall.EALREADY) || value == int(syscall.EINTR) {
			return false
		}
		if value != 0 && value != int(syscall.EISCONN) {
			result = syscall.Errno(value)
			return true
		}
		peer, readErr := syscall.Getpeername(fd)
		if errors.Is(readErr, syscall.ENOTCONN) {
			// Go's poller may wake before the kernel has completed connect.
			// Wait again using the same FD and its captured cancellation bound.
			return false
		}
		if readErr != nil {
			result = readErr
			return true
		}
		matches := false
		if remote.Addr().Is4() {
			value, ok := peer.(*syscall.SockaddrInet4)
			matches = ok && value.Addr == remote.Addr().As4() && value.Port == int(remote.Port())
		} else {
			value, ok := peer.(*syscall.SockaddrInet6)
			matches = ok && value.Addr == remote.Addr().As16() && value.Port == int(remote.Port()) && value.ZoneId == 0
		}
		if !matches {
			result = errors.New("desktop imported TCP connected to a different kernel peer")
		}
		return true
	})
	if err != nil || result != nil || ctx.Err() != nil {
		return errors.Join(err, result, ctx.Err())
	}
	// Join the interrupt callback before clearing its deadline. The broker then
	// installs the independently captured lease deadline before returning data.
	if !stop() {
		<-interrupted
		interruptJoined = true
		return errors.Join(ctx.Err(), net.ErrClosed)
	}
	interruptJoined = true
	return connection.SetWriteDeadline(time.Time{})
}

func desktopSocketImportPacket(ctx context.Context, network string, file *os.File, local netip.Addr, control func(string, string, syscall.RawConn) error) (net.PacketConn, error) {
	raw, actualNetwork, err := desktopSocketSourceRaw(file, "udp", local)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || (network != "udp" && network != actualNetwork) {
		return nil, net.ErrClosed
	}
	if err := control(actualNetwork, netip.AddrPortFrom(local, 0).String(), raw); err != nil {
		return nil, err
	}
	var result error
	err = raw.Control(func(handle uintptr) {
		var target syscall.Sockaddr
		if local.Is4() {
			target = &syscall.SockaddrInet4{Addr: local.As4()}
		} else {
			target = &syscall.SockaddrInet6{Addr: local.As16()}
		}
		result = syscall.Bind(int(handle), target)
	})
	if err != nil || result != nil || ctx.Err() != nil {
		return nil, errors.Join(err, result, ctx.Err())
	}
	packet, err := net.FilePacketConn(file)
	if err == nil {
		if _, ok := packet.(*net.UDPConn); !ok {
			err = errors.New("desktop socket import changed UDP into another kernel protocol")
		}
	}
	return packet, err
}
