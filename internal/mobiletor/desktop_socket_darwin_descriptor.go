//go:build darwin

package mobiletor

import (
	"errors"
	"io"
	"net"
	"syscall"
)

// Darwin has neither SOCK_CLOEXEC nor MSG_CMSG_CLOEXEC. Keep the allocation
// and checked FD_CLOEXEC installation inside Go's fork exclusion. In particular,
// net.UnixConn.ReadMsgUnix's post-receive CloseOnExec does not exclude a fork.
func desktopDarwinDescriptorCloseOnExec(fd int) error {
	_, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, syscall.FD_CLOEXEC)
	if err != 0 {
		return err
	}
	return nil
}

func desktopDarwinSocketCloseOnExec(family, kind int) (int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := syscall.Socket(family, kind, 0)
	if err != nil {
		return -1, err
	}
	if err := desktopDarwinDescriptorCloseOnExec(fd); err != nil {
		return -1, errors.Join(err, syscall.Close(fd))
	}
	return fd, nil
}

func desktopDarwinSocketPairCloseOnExec() ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return pair, err
	}
	for _, fd := range pair {
		if err := desktopDarwinDescriptorCloseOnExec(fd); err != nil {
			return [2]int{-1, -1}, errors.Join(err, syscall.Close(pair[0]), syscall.Close(pair[1]))
		}
	}
	return pair, nil
}

type desktopDarwinCloexecFrame struct{ *net.UnixConn }

func (r desktopDarwinCloexecFrame) readMsgCloseOnExec(body, control []byte) (int, int, int, *net.UnixAddr, error) {
	return desktopDarwinReadMsgCloseOnExec(r.UnixConn, body, control)
}

func desktopDarwinReadMsgCloseOnExec(channel *net.UnixConn, body, control []byte) (n, oob, flags int, peer *net.UnixAddr, failure error) {
	raw, err := channel.SyscallConn()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	return desktopDarwinReadMsgRawCloseOnExec(raw, body, control)
}

func desktopDarwinReadMsgRawCloseOnExec(raw syscall.RawConn, body, control []byte) (n, oob, flags int, peer *net.UnixAddr, failure error) {
	err := raw.Read(func(fd uintptr) bool {
		// MSG_DONTWAIT makes even a changed descriptor nonblocking while the
		// fork lock is held. RawConn owns readiness/deadline/close waiting after
		// this callback releases the lock; no idle control stream stalls exec.
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()
		var address syscall.Sockaddr
		for {
			n, oob, flags, address, failure = syscall.Recvmsg(int(fd), body, control, syscall.MSG_DONTWAIT)
			if failure != syscall.EINTR {
				break
			}
		}
		// XNU returns the supplied MSG_DONTWAIT in msg_flags. Remove only
		// that input bit; truncation and every other output flag remain fatal
		// to the bounded frame parser.
		flags &^= syscall.MSG_DONTWAIT
		if failure == syscall.EAGAIN || failure == syscall.EWOULDBLOCK {
			n, oob, flags, failure = 0, 0, 0, nil
			return false
		}
		messages, parseErr := syscall.ParseSocketControlMessage(control[:oob])
		var received []int
		for _, message := range messages {
			if message.Header.Level != syscall.SOL_SOCKET || message.Header.Type != syscall.SCM_RIGHTS {
				continue
			}
			rights, rightsErr := syscall.ParseUnixRights(&message)
			parseErr = errors.Join(parseErr, rightsErr)
			for _, receivedFD := range rights {
				received = append(received, receivedFD)
				parseErr = errors.Join(parseErr, desktopDarwinDescriptorCloseOnExec(receivedFD))
			}
		}
		if failure != nil || parseErr != nil {
			for _, receivedFD := range received {
				parseErr = errors.Join(parseErr, syscall.Close(receivedFD))
			}
			oob = 0
			failure = errors.Join(failure, parseErr)
		}
		if unix, ok := address.(*syscall.SockaddrUnix); ok && unix.Name != "" {
			peer = &net.UnixAddr{Name: unix.Name, Net: "unix"}
		}
		if n == 0 && failure == nil {
			failure = io.EOF
		}
		return true
	})
	return n, oob, flags, peer, errors.Join(err, failure)
}
