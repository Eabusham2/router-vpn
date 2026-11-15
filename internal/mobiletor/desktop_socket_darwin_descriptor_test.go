//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Observe the real poll callback without supplying native bytes, descriptors,
// readiness, errors or success. Both barriers are reached by the actual reader.
type desktopDarwinDescriptorReadObserver struct {
	syscall.RawConn
	entered, idle   chan struct{}
	started, waited sync.Once
}

func (r *desktopDarwinDescriptorReadObserver) Read(read func(uintptr) bool) error {
	return r.RawConn.Read(func(fd uintptr) bool {
		r.started.Do(func() { close(r.entered) })
		done := read(fd)
		if !done {
			r.waited.Do(func() { close(r.idle) })
		}
		return done
	})
}

func TestDesktopDarwinGuardianKernelDescriptorOwnership(t *testing.T) {
	if inherited := os.Getenv("ROUTERVPN_DARWIN_DESCRIPTOR_CHILD"); inherited != "" {
		parts := strings.Split(inherited, ":")
		if len(parts) != 2 {
			t.Fatal("descriptor child lost its captured kernel identity")
		}
		fd, err := strconv.Atoi(parts[0])
		original, parseErr := strconv.ParseUint(parts[1], 10, 64)
		if err != nil || parseErr != nil || fd < 3 || original == 0 {
			t.Fatal("descriptor child received an invalid original identity")
		}
		var stat syscall.Stat_t
		err = syscall.Fstat(fd, &stat)
		if errors.Is(err, syscall.EBADF) {
			return
		}
		if err != nil {
			t.Fatal("descriptor child could not inspect its actual descriptor", err)
		}
		if stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
			return // The runtime may reuse the number for a different object.
		}
		identity, err := desktopDarwinReadSocket(fd)
		if err != nil || identity.socket == original {
			t.Fatal("original physical descriptor survived unrelated exec", err)
		}
		return
	}
	check := func(t *testing.T, fd int) {
		t.Helper()
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
			t.Fatal("original descriptor is not close-on-exec", errno)
		}
		identity, err := desktopDarwinReadSocket(fd)
		if err != nil || identity.socket == 0 {
			t.Fatal("descriptor check lost actual kernel socket identity", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDesktopDarwinGuardianKernelDescriptorOwnership$", "-test.timeout=4s")
		child.Env = append(os.Environ(), fmt.Sprintf("ROUTERVPN_DARWIN_DESCRIPTOR_CHILD=%d:%d", fd, identity.socket))
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("original descriptor crossed unrelated exec: %v\n%s", err, output)
		}
	}
	t.Run("socket-and-duplicate", func(t *testing.T) {
		fd, err := desktopDarwinSocketCloseOnExec(syscall.AF_INET, syscall.SOCK_DGRAM)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(fd)
		check(t, fd)
		kept, err := desktopSocketDuplicate(fd)
		if err != nil {
			t.Fatal(err)
		}
		defer kept.Close()
		check(t, int(kept.file.Fd()))
	})
	for _, test := range []string{"received-rights", "idle-fork", "receive-excludes-fork", "closed-receive", "deadline-receive"} {
		t.Run(test, func(t *testing.T) {
			receiver, senderFile, err := desktopDarwinSocketPair()
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			defer senderFile.Close()
			// This is an actual AF_UNIX control descriptor, so inspect its flags
			// directly; the IP socket libproc inspector deliberately rejects it.
			flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, senderFile.Fd(), syscall.F_GETFD, 0)
			if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
				t.Fatal("original socketpair descriptor is not close-on-exec", errno)
			}
			senderConnection, err := net.FileConn(senderFile)
			if err != nil {
				t.Fatal(err)
			}
			defer senderConnection.Close()
			sender := senderConnection.(*net.UnixConn)
			if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if test == "deadline-receive" {
				if err := receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			fd, err := desktopDarwinSocketCloseOnExec(syscall.AF_INET, syscall.SOCK_DGRAM)
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.Close(fd)
			type result struct {
				n, oob, flags int
				control       []byte
				err           error
			}
			raw, err := receiver.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			observed := &desktopDarwinDescriptorReadObserver{RawConn: raw, entered: make(chan struct{}), idle: make(chan struct{})}
			joined := make(chan result, 1)
			locked := test == "receive-excludes-fork"
			if locked {
				syscall.ForkLock.Lock()
				defer func() {
					if locked {
						syscall.ForkLock.Unlock()
					}
				}()
			}
			go func() {
				body, control := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
				n, oob, flags, _, err := desktopDarwinReadMsgRawCloseOnExec(observed, body, control)
				joined <- result{n, oob, flags, control, err}
			}()
			if test == "idle-fork" {
				select {
				case <-observed.idle:
				case <-time.After(time.Second):
					_ = receiver.Close()
					<-joined
					t.Fatal("original descriptor receiver did not reach actual idle readiness")
				}
				// A blocking receive must not hold the global fork exclusion.
				acquired := make(chan struct{})
				go func() { syscall.ForkLock.Lock(); syscall.ForkLock.Unlock(); close(acquired) }()
				select {
				case <-acquired:
				case <-time.After(time.Second):
					_ = receiver.Close()
					<-joined
					<-acquired
					t.Fatal("idle descriptor receiver blocked unrelated fork")
				}
			}
			if test == "closed-receive" {
				_ = receiver.Close()
			} else if test != "deadline-receive" {
				if _, _, err := sender.WriteMsgUnix([]byte{1}, syscall.UnixRights(fd), nil); err != nil {
					t.Fatal(err)
				}
			}
			if locked {
				select {
				case <-observed.entered:
				case <-time.After(time.Second):
					syscall.ForkLock.Unlock()
					locked = false
					_ = receiver.Close()
					<-joined
					t.Fatal("original descriptor receiver did not enter its native callback")
				}
				select {
				case result := <-joined:
					syscall.ForkLock.Unlock()
					locked = false
					if result.oob > 0 {
						messages, _ := syscall.ParseSocketControlMessage(result.control[:result.oob])
						for _, message := range messages {
							rights, _ := syscall.ParseUnixRights(&message)
							for _, fd := range rights {
								syscall.Close(fd)
							}
						}
					}
					t.Fatal("descriptor receipt crossed active fork exclusion", result.err)
				case <-time.After(100 * time.Millisecond):
				}
				syscall.ForkLock.Unlock()
				locked = false
			}
			var actual result
			select {
			case actual = <-joined:
			case <-time.After(3 * time.Second):
				_ = receiver.Close()
				<-joined
				t.Fatal("original descriptor receiver failed to join")
			}
			if test == "closed-receive" || test == "deadline-receive" {
				wanted := net.ErrClosed
				if test == "deadline-receive" {
					wanted = os.ErrDeadlineExceeded
				}
				if !errors.Is(actual.err, wanted) || actual.oob != 0 {
					t.Fatal("native descriptor receive lost original close/deadline", actual.err)
				}
				return
			}
			messages, parseErr := syscall.ParseSocketControlMessage(actual.control[:actual.oob])
			if actual.err != nil || parseErr != nil || actual.n != 1 || actual.flags != 0 || len(messages) != 1 {
				t.Fatal("actual descriptor transfer lost its bounded result", actual.err, parseErr)
			}
			rights, err := syscall.ParseUnixRights(&messages[0])
			for _, received := range rights {
				defer syscall.Close(received)
			}
			if err != nil || len(rights) != 1 {
				t.Fatal("actual descriptor transfer changed its original descriptor", err)
			}
			check(t, rights[0])
		})
	}
}
