//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"router-vpn/internal/linuxprocess"
)

// This peer is obtained from an actual connected Unix socket. Neither a
// request's process number nor persistent service metadata can construct it.
type linuxStandardServicePeer struct {
	image      os.FileInfo
	generation *linuxStandardServiceGeneration
	pidfd      *os.File
	pidfdInfo  os.FileInfo
	task       *linuxprocess.Witness
	record     linuxprocess.Observation
	command    *os.File
	arguments  []byte
}

func linuxStandardPeerProcID(fd *os.File, peerPID int) (int, error) {
	if fd == nil || peerPID < 1 {
		return 0, errors.New("standard service lost its actual kernel peer")
	}
	raw, err := fd.SyscallConn()
	if err != nil {
		return 0, err
	}
	var body []byte
	var readErr error
	err = raw.Control(func(number uintptr) {
		file, failure := os.Open("/proc/self/fdinfo/" + strconv.FormatUint(uint64(number), 10))
		if failure != nil {
			readErr = failure
			return
		}
		defer file.Close()
		body, readErr = io.ReadAll(io.LimitReader(file, 4097))
	})
	if err != nil || readErr != nil || len(body) == 0 || len(body) > 4096 {
		return 0, errors.Join(err, readErr, errors.New("standard service peer pidfd has no bounded native identity"))
	}
	pid, namespaces := "", ""
	for _, line := range strings.Split(string(body), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Pid":
			if pid != "" {
				return 0, errors.New("duplicate peer pidfd identity")
			}
			pid = strings.TrimSpace(value)
		case "NSpid":
			if namespaces != "" {
				return 0, errors.New("duplicate peer pidfd namespace")
			}
			namespaces = strings.TrimSpace(value)
		}
	}
	procID, err := strconv.Atoi(pid)
	parts := strings.Fields(namespaces)
	if err != nil || procID < 1 || strconv.Itoa(procID) != pid || len(parts) < 1 || len(parts) > 32 || parts[0] != pid || parts[len(parts)-1] != strconv.Itoa(peerPID) {
		return 0, errors.New("standard service peer pidfd changed its original PID namespace mapping")
	}
	for _, part := range parts {
		value, err := strconv.ParseUint(part, 10, 31)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != part {
			return 0, errors.New("invalid standard service peer namespace")
		}
	}
	return procID, nil
}

func captureLinuxStandardServicePeer(ctx context.Context, connection *net.UnixConn, image os.FileInfo, arguments []string, namespace os.FileInfo) (_ *linuxStandardServicePeer, failure error) {
	if ctx == nil || connection == nil || image == nil || namespace == nil || len(arguments) == 0 {
		return nil, errors.New("standard service has no captured peer constraints")
	}
	p := &linuxStandardServicePeer{image: image}
	defer func() {
		if failure != nil {
			_ = p.Close()
		}
	}()
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credential *syscall.Ucred
	var nativeErr error
	err = raw.Control(func(fd uintptr) {
		credential, nativeErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if nativeErr != nil {
			return
		}
		// SO_PEERPIDFD returns this connected peer's kernel capability. It is
		// deliberately not pidfd_open(printed_pid), including during reconnect.
		var descriptor int32
		size := uint32(unsafe.Sizeof(descriptor))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_SOCKET, 77, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			nativeErr = errno
			return
		}
		p.pidfd = os.NewFile(uintptr(descriptor), "original-standard-service-peer")
		if size != 4 {
			nativeErr = errors.New("standard service peer pidfd returned an invalid native size")
		}
	})
	if err != nil || nativeErr != nil || credential == nil || credential.Uid != 0 || credential.Gid != 0 || credential.Pid < 1 || p.pidfd == nil {
		return nil, errors.Join(err, nativeErr, errors.New("standard service requires its actual privileged Unix peer and original pidfd"))
	}
	if err = linuxprocess.SetCloseOnExec(p.pidfd); err != nil {
		return nil, err
	}
	p.pidfdInfo, err = p.pidfd.Stat()
	if err != nil {
		return nil, err
	}
	procID, err := linuxStandardPeerProcID(p.pidfd, int(credential.Pid))
	if err != nil {
		return nil, err
	}
	if retired, err := legacyExitPIDFDState(p.pidfd); err != nil || retired {
		return nil, errors.Join(err, errors.New("standard service peer already retired"))
	}
	// The number here comes only from the retained kernel pidfd's fdinfo.
	// CaptureDirectory retains the resulting original proc directory; all
	// subsequent checks use that capability rather than looking the PID up.
	directory, err := os.Open("/proc/" + strconv.Itoa(procID))
	if err != nil {
		return nil, err
	}
	commandFD, err := syscall.Openat(int(directory.Fd()), "cmdline", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	p.command = os.NewFile(uintptr(commandFD), "original-standard-peer-command")
	p.arguments = []byte(strings.Join(arguments, "\x00") + "\x00")
	body, readErr := io.ReadAll(io.LimitReader(p.command, 8193))
	if readErr != nil || len(body) > 8192 || !bytes.Equal(body, p.arguments) {
		_ = directory.Close()
		return nil, errors.Join(readErr, errors.New("standard service peer is not its fixed installed command"))
	}
	p.task, err = linuxprocess.CaptureDirectory(ctx, directory, int(credential.Pid))
	if err != nil {
		return nil, err
	}
	p.record, err = p.task.Current(ctx)
	if err != nil {
		return nil, err
	}
	expectedImage, err := desktopLinuxNodeObjectOf(image)
	if err != nil {
		return nil, err
	}
	expectedNamespace, err := desktopLinuxNodeObjectOf(namespace)
	if err != nil || p.record.Image != linuxprocess.Object(expectedImage) || p.record.NetworkNamespace != linuxprocess.Object(expectedNamespace) || p.record.ProcProcessID != procID {
		return nil, errors.Join(err, errors.New("standard service peer differs from its captured installed image or namespace"))
	}
	if err = p.Current(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *linuxStandardServicePeer) Current(ctx context.Context) error {
	if p != nil && p.generation != nil {
		if err := p.generation.Current(ctx); err != nil {
			return err
		}
	}
	if p == nil || p.pidfd == nil || p.task == nil || p.command == nil || len(p.arguments) == 0 || ctx == nil {
		return errors.New("standard service peer has no retained capability")
	}
	info, err := p.pidfd.Stat()
	if err != nil || !os.SameFile(info, p.pidfdInfo) {
		return errors.Join(err, errors.New("standard service peer lost original pidfd"))
	}
	procID, err := linuxStandardPeerProcID(p.pidfd, p.record.ProcessID)
	if err != nil || procID != p.record.ProcProcessID {
		return errors.Join(err, errors.New("standard service peer changed its native task"))
	}
	if retired, err := legacyExitPIDFDState(p.pidfd); err != nil || retired {
		return errors.Join(err, errors.New("standard service original peer retired"))
	}
	actual, err := p.task.Current(ctx)
	if err != nil {
		return err
	}
	if actual != p.record {
		return errors.New("standard service original peer image or namespace changed")
	}
	body := make([]byte, 8193)
	n, err := p.command.ReadAt(body, 0)
	if err != nil && !errors.Is(err, io.EOF) || n > 8192 || !bytes.Equal(body[:n], p.arguments) {
		return errors.Join(err, errors.New("standard service original peer changed its captured command role"))
	}
	return ctx.Err()
}

func (p *linuxStandardServicePeer) Retired() (bool, error) {
	if p == nil || p.pidfd == nil {
		return false, errors.New("standard service has no original peer retirement capability")
	}
	info, err := p.pidfd.Stat()
	if err != nil || !os.SameFile(info, p.pidfdInfo) {
		return false, errors.Join(err, errors.New("standard service peer retirement lost original pidfd"))
	}
	return legacyExitPIDFDState(p.pidfd)
}

func (p *linuxStandardServicePeer) Close() error {
	if p == nil {
		return nil
	}
	var result error
	if p.generation != nil {
		result = errors.Join(result, p.generation.Close())
		p.generation = nil
	}
	if p.command != nil {
		err := p.command.Close()
		if err == nil || errors.Is(err, os.ErrClosed) {
			p.command = nil
		} else {
			result = errors.Join(result, err)
		}
	}
	if p.task != nil {
		err := p.task.Close(context.Background())
		result = errors.Join(result, err)
		if err == nil {
			p.task = nil
		}
	}
	if p.pidfd != nil {
		err := p.pidfd.Close()
		if err == nil || errors.Is(err, os.ErrClosed) {
			p.pidfd = nil
		} else {
			result = errors.Join(result, err)
		}
	}
	return result
}
