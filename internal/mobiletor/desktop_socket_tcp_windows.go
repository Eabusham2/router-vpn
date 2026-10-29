package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var desktopSocketPollProc = desktopSocketWinsock.NewProc("WSAPoll")
var desktopSocketNonblockProc = desktopSocketWinsock.NewProc("ioctlsocket")
var desktopSocketStartupOnce sync.Once
var desktopSocketStartupError error

// Winsock2.h values. Error/hangup bits are returned by WSAPoll; they must not
// be passed in events. Poll waits are bounded independently of a control RPC.
const (
	desktopSocketPollRead     int16 = 0x0100
	desktopSocketPollWrite    int16 = 0x0010
	desktopSocketPollError    int16 = 0x0001
	desktopSocketPollHang     int16 = 0x0002
	desktopSocketPollBad      int16 = 0x0004
	desktopSocketWouldBlock         = syscall.Errno(10035)
	desktopSocketInProgress         = syscall.Errno(10036)
	desktopSocketAlready            = syscall.Errno(10037)
	desktopSocketNotConnected       = syscall.Errno(10057)
)

type desktopSocketPollFD struct {
	handle  syscall.Handle
	events  int16
	revents int16
}

// The Windows net.Dialer binds again immediately before ConnectEx. A socket
// whose actual source port was already authorized therefore cannot be handed
// back to it. This narrow connection owns nonblocking Winsock I/O directly;
// there is no temporary unbind, guessed port, unsafe netFD or host dial fallback.
// The separate duplicate still keeps the port until the policy absent readback.
type desktopWindowsSocket struct {
	handle     syscall.Handle
	boundLocal netip.AddrPort // Captured before import; never overwritten by connected readback.
	local      netip.AddrPort
	remote     netip.AddrPort
	mu         sync.Mutex
	closing    bool
	closed     bool
	readUntil  time.Time
	writeUntil time.Time
	read       sync.Mutex
	write      sync.Mutex
	close      sync.Mutex
	io         sync.WaitGroup
}

type desktopWindowsRaw struct{ socket *desktopWindowsSocket }

func desktopSocketCreateTCP(family int) (syscall.Handle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const flags = 0x01 | 0x80 // WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT.
	handle, _, _ := desktopSocketCreateProc.Call(uintptr(family), syscall.SOCK_STREAM, syscall.IPPROTO_TCP, 0, 0, flags)
	if handle == ^uintptr(0) {
		return syscall.InvalidHandle, desktopSocketWinsockError()
	}
	return syscall.Handle(handle), nil
}

func desktopSocketNonblocking(handle syscall.Handle) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var nonblocking uint32 = 1
	const fionbio = 0x8004667e
	result, _, _ := desktopSocketNonblockProc.Call(uintptr(handle), fionbio, uintptr(unsafe.Pointer(&nonblocking)))
	if int32(result) != 0 {
		return desktopSocketWinsockError()
	}
	return nil
}

func desktopSocketPoll(poll *desktopSocketPollFD, milliseconds int64) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, _ := desktopSocketPollProc.Call(uintptr(unsafe.Pointer(poll)), 1, uintptr(milliseconds))
	if int32(result) < 0 {
		return desktopSocketWinsockError()
	}
	return nil
}

func (r desktopWindowsRaw) Control(f func(uintptr)) error {
	r.socket.mu.Lock()
	defer r.socket.mu.Unlock()
	if r.socket.closing || r.socket.closed {
		return net.ErrClosed
	}
	f(uintptr(r.socket.handle))
	return nil
}

func (desktopWindowsRaw) Read(func(uintptr) bool) error {
	return errors.New("desktop physical raw socket only permits captured control")
}
func (desktopWindowsRaw) Write(func(uintptr) bool) error {
	return errors.New("desktop physical raw socket only permits captured control")
}

func desktopSocketDialTCP(ctx context.Context, network string, remote netip.AddrPort, control func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
	if ctx == nil || ctx.Err() != nil || control == nil {
		return nil, net.ErrClosed
	}
	desktopSocketStartupOnce.Do(func() {
		var data syscall.WSAData
		desktopSocketStartupError = syscall.WSAStartup(0x0202, &data)
	})
	if desktopSocketStartupError != nil {
		return nil, desktopSocketStartupError
	}
	family, actualNetwork := syscall.AF_INET6, "tcp6"
	if remote.Addr().Is4() {
		family, actualNetwork = syscall.AF_INET, "tcp4"
	}
	if network != "tcp" && network != actualNetwork {
		return nil, errors.New("desktop physical TCP address family changed")
	}
	handle, err := desktopSocketCreateTCP(family)
	if err != nil {
		return nil, err
	}
	c := &desktopWindowsSocket{handle: handle, remote: remote}
	failed := true
	defer func() {
		if failed {
			// Return a nonnil partial owner below when close fails. The broker
			// retains it and retries only after its exact policy drain.
			_ = c.Close()
		}
	}()
	if err := desktopSocketNonblocking(handle); err != nil {
		return c, err
	}
	if err := control(ctx, actualNetwork, remote.String(), desktopWindowsRaw{c}); err != nil {
		return c, err
	}
	if err := desktopSocketConnectOwnedTCP(ctx, c); err != nil {
		return c, err
	}
	failed = false
	return c, nil
}

// The socket is already exclusively bound and its exact physical permit has
// been acknowledged. Both ordinary and token-created sockets connect through
// this same Winsock path without creating or rebinding another endpoint.
func desktopSocketConnectOwnedTCP(ctx context.Context, c *desktopWindowsSocket) error {
	return desktopSocketConnectOwnedTCPReadback(ctx, c, desktopSocketLocal)
}

// The private readback seam can inject a changed actual local observation in
// native tests. Production always supplies desktopSocketLocal. Expected local
// ownership remains a separate captured value, never the output being checked.
func desktopSocketConnectOwnedTCPReadback(ctx context.Context, c *desktopWindowsSocket, readLocal func(syscall.Handle) (netip.AddrPort, error)) error {
	if ctx == nil || c == nil || readLocal == nil {
		return net.ErrClosed
	}
	remote := c.remote
	expectedLocal := c.boundLocal
	if !expectedLocal.IsValid() {
		// An ordinary socket has no imported capture; this descriptor itself
		// performed Bind and must prove its local tuple before the handshake.
		var err error
		expectedLocal, err = desktopSocketLocal(c.handle)
		if err != nil {
			return fmt.Errorf("Windows TCP bound local tuple: %w", err)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var target syscall.Sockaddr = &syscall.SockaddrInet6{Addr: remote.Addr().As16(), Port: int(remote.Port())}
	if remote.Addr().Is4() {
		target = &syscall.SockaddrInet4{Addr: remote.Addr().As4(), Port: int(remote.Port())}
	}
	err := syscall.Connect(c.handle, target)
	if err != nil && !errors.Is(err, desktopSocketWouldBlock) && !errors.Is(err, desktopSocketInProgress) && !errors.Is(err, desktopSocketAlready) {
		return fmt.Errorf("Winsock Connect: %w", err)
	}
	err = desktopSocketCompleteTCP(ctx, err != nil, remote, func(ctx context.Context) error {
		return c.wait(ctx, true)
	}, func() error {
		const socketError = 0x1007 // SO_ERROR, after actual completion only.
		code, err := syscall.GetsockoptInt(c.handle, syscall.SOL_SOCKET, socketError)
		if err != nil {
			return err
		}
		if code != 0 {
			return syscall.Errno(code)
		}
		return nil
	}, func() (netip.AddrPort, error) {
		peer, peerErr := syscall.Getpeername(c.handle)
		if peerErr != nil {
			return netip.AddrPort{}, peerErr
		}
		var actual netip.AddrPort
		switch peer := peer.(type) {
		case *syscall.SockaddrInet4:
			actual = netip.AddrPortFrom(netip.AddrFrom4(peer.Addr), uint16(peer.Port))
		case *syscall.SockaddrInet6:
			if peer.ZoneId == 0 {
				actual = netip.AddrPortFrom(netip.AddrFrom16(peer.Addr), uint16(peer.Port))
			}
		}
		return actual, nil
	})
	if err != nil {
		return err
	}
	local, err := readLocal(c.handle)
	if err != nil {
		return fmt.Errorf("Windows TCP completed local tuple: %w", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if local != expectedLocal {
		return errors.New("Windows TCP connected local tuple differs from its captured bind")
	}
	c.local = local
	return nil
}

func (c *desktopWindowsSocket) begin() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.closed {
		return net.ErrClosed
	}
	c.io.Add(1)
	return nil
}

func (c *desktopWindowsSocket) state(ctx context.Context, write bool) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	closing, deadline := c.closing || c.closed, c.readUntil
	if write {
		deadline = c.writeUntil
	}
	c.mu.Unlock()
	if closing {
		return 0, net.ErrClosed
	}
	if until, ok := ctx.Deadline(); ok {
		deadline = desktopSocketDeadline(deadline, until)
	}
	wait := 20 * time.Millisecond
	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		if remaining < wait {
			wait = remaining
		}
	}
	return wait, nil
}

func (c *desktopWindowsSocket) wait(ctx context.Context, write bool) error {
	for {
		wait, err := c.state(ctx, write)
		if err != nil {
			return err
		}
		event := desktopSocketPollRead
		if write {
			event = desktopSocketPollWrite
		}
		poll := desktopSocketPollFD{handle: c.handle, events: event}
		// Round down so polling never extends the currently captured deadline.
		if err := desktopSocketPoll(&poll, wait.Milliseconds()); err != nil {
			return err
		}
		if _, err = c.state(ctx, write); err != nil {
			return err
		}
		if poll.revents&desktopSocketPollBad != 0 {
			return net.ErrClosed
		}
		if poll.revents&desktopSocketPollError != 0 {
			const socketError = 0x1007 // SO_ERROR.
			code, err := syscall.GetsockoptInt(c.handle, syscall.SOL_SOCKET, socketError)
			if err != nil {
				return err
			}
			if code != 0 {
				return syscall.Errno(code)
			}
			return errors.New("desktop physical socket reported an unspecified native error")
		}
		if poll.revents&desktopSocketPollHang != 0 && write {
			return net.ErrClosed
		}
		if poll.revents&(event|desktopSocketPollHang) != 0 {
			return nil
		}
	}
}

func (c *desktopWindowsSocket) Read(data []byte) (int, error) {
	if err := c.begin(); err != nil {
		return 0, err
	}
	defer c.io.Done()
	c.read.Lock()
	defer c.read.Unlock()
	if len(data) == 0 {
		return 0, nil
	}
	for {
		if _, err := c.state(context.Background(), false); err != nil {
			return 0, err
		}
		buffer := syscall.WSABuf{Len: uint32(min(len(data), 1<<30)), Buf: &data[0]}
		var received, flags uint32
		err := syscall.WSARecv(c.handle, &buffer, 1, &received, &flags, nil, nil)
		if err == nil {
			if received == 0 {
				return 0, io.EOF
			}
			if received > buffer.Len {
				return 0, errors.New("desktop physical native receive length changed")
			}
			return int(received), nil
		}
		if !errors.Is(err, desktopSocketWouldBlock) {
			return 0, err
		}
		if err = c.wait(context.Background(), false); err != nil {
			return 0, err
		}
	}
}

func (c *desktopWindowsSocket) Write(data []byte) (int, error) {
	if err := c.begin(); err != nil {
		return 0, err
	}
	defer c.io.Done()
	c.write.Lock()
	defer c.write.Unlock()
	written := 0
	for written < len(data) {
		if _, err := c.state(context.Background(), true); err != nil {
			return written, err
		}
		buffer := syscall.WSABuf{Len: uint32(min(len(data)-written, 1<<30)), Buf: &data[written]}
		var sent uint32
		err := syscall.WSASend(c.handle, &buffer, 1, &sent, 0, nil, nil)
		if sent > buffer.Len {
			return written, errors.New("desktop physical native send length changed")
		}
		written += int(sent)
		if err != nil && !errors.Is(err, desktopSocketWouldBlock) {
			return written, err
		}
		if err == nil && sent == 0 {
			return written, io.ErrNoProgress
		}
		if written < len(data) {
			if err = c.wait(context.Background(), true); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (c *desktopWindowsSocket) Close() error {
	c.close.Lock()
	defer c.close.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closing = true
	c.mu.Unlock()
	// No handle is closed while a poll or actual nonblocking I/O can still
	// refer to it. New operations are excluded before this wait begins.
	c.io.Wait()
	if err := syscall.Closesocket(c.handle); err != nil {
		return err
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *desktopWindowsSocket) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(c.local) }
func (c *desktopWindowsSocket) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.remote) }
func (c *desktopWindowsSocket) SetDeadline(value time.Time) error {
	return c.deadline(value, true, true)
}
func (c *desktopWindowsSocket) SetReadDeadline(value time.Time) error {
	return c.deadline(value, true, false)
}
func (c *desktopWindowsSocket) SetWriteDeadline(value time.Time) error {
	return c.deadline(value, false, true)
}
func (c *desktopWindowsSocket) deadline(value time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.closed {
		return net.ErrClosed
	}
	if read {
		c.readUntil = value
	}
	if write {
		c.writeUntil = value
	}
	return nil
}
