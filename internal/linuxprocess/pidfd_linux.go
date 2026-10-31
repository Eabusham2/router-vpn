//go:build linux

package linuxprocess

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// CreatedWitness consumes the pidfd returned atomically by the caller's
// successful exec.Cmd.Start (SysProcAttr.PidFD), and the child's independently
// authenticated task-directory witness. It never opens a pidfd by numeric PID,
// signals a process, waits for it, or adopts a process from a decoded record.
// The creator must retain its original exec.Cmd and native protection owner.
type CreatedWitness struct {
	gate       chan struct{}
	descriptor *os.File
	fdinfo     *os.File
	identity   Object
	task       *Witness
	parent     Observation
	child      Observation
	complete   bool
	revoked    bool
	closed     bool
	closeErr   error
}

// CaptureCreated consumes the exact supplied handles even on partial failure.
// parent is borrowed from the original creator; its exact fdinfo directory
// supplies readback, while its observation and image constrain the child.
// None of these inputs confers journal or firewall mutation authority.
func CaptureCreated(ctx context.Context, descriptor *os.File, task *Witness, parent *Witness, image Object) (*CreatedWitness, error) {
	w := &CreatedWitness{gate: make(chan struct{}, 1), descriptor: descriptor, task: task}
	defer func() { w.gate <- struct{}{} }()
	if task != nil && task == parent {
		w.task = nil
		return w, errors.New("Linux child cannot consume its borrowed original parent as a task witness")
	}
	if ctx == nil || ctx.Err() != nil || descriptor == nil || task == nil || parent == nil {
		return w, errors.New("Linux child requires its actual clone-created pidfd and authenticated task directory")
	}
	var err error
	w.parent, err = parent.Current(ctx)
	if err != nil || w.parent.ProcessID != os.Getpid() {
		return w, errors.Join(err, errors.New("Linux child pidfd lost its actual retained creator"))
	}
	w.fdinfo, err = parent.duplicateFDInfo(ctx)
	if err != nil {
		return w, err
	}
	info, err := descriptor.Stat()
	if err != nil {
		return w, err
	}
	w.identity, err = objectOf(info)
	if err != nil {
		return w, err
	}
	w.child, err = task.Current(ctx)
	if err != nil || w.child.ProcessID == w.parent.ProcessID || w.child.ProcProcessID == w.parent.ProcProcessID ||
		w.child.ProcParentID != w.parent.ProcProcessID || w.child.BootID != w.parent.BootID || w.child.Image != image ||
		w.child.NetworkNamespace != w.parent.NetworkNamespace || w.child.PIDNamespace != w.parent.PIDNamespace {
		return w, errors.Join(err, errors.New("Linux child differs from its exact created parent, image or namespaces"))
	}
	if err := w.currentDescriptor(); err != nil {
		return w, err
	}
	if err := ctx.Err(); err != nil {
		return w, err
	}
	w.complete = true
	return w, nil
}

func pidFDIdentity(body []byte, nativePID, procPID int) error {
	if len(body) == 0 || len(body) > 4096 || nativePID < 1 || procPID < 1 {
		return errors.New("Linux child pidfd has no bounded namespace identity")
	}
	pidSeen, namespaceSeen := false, false
	for _, line := range strings.Split(string(body), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(value)
		switch key {
		case "Pid":
			if pidSeen || len(fields) != 1 || fields[0] != strconv.Itoa(procPID) {
				return errors.New("Linux child pidfd no longer names its original proc task")
			}
			pidSeen = true
		case "NSpid":
			if namespaceSeen || len(fields) < 1 || len(fields) > 32 || fields[0] != strconv.Itoa(procPID) || fields[len(fields)-1] != strconv.Itoa(nativePID) {
				return errors.New("Linux child pidfd changed its original PID namespace mapping")
			}
			namespaceSeen = true
			for _, field := range fields {
				value, err := strconv.ParseUint(field, 10, 31)
				if err != nil || value == 0 || strconv.FormatUint(value, 10) != field {
					return errors.New("Linux child pidfd has a malformed namespace PID")
				}
			}
		}
	}
	if !pidSeen || !namespaceSeen {
		return errors.New("Linux child descriptor is not a live native pidfd")
	}
	return nil
}

func (w *CreatedWitness) currentDescriptor() error {
	info, err := w.descriptor.Stat()
	identity, identityErr := objectOf(info)
	if err != nil || identityErr != nil || identity != w.identity {
		return errors.Join(err, identityErr, errors.New("Linux child lost its original pidfd descriptor"))
	}
	raw, err := w.descriptor.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	err = raw.Control(func(fd uintptr) {
		// Control retains this exact file description while fdinfo resolves the
		// descriptor. A concurrent Close cannot recycle its numeric fd here.
		file, openErr := openRetainedFDInfo(w.fdinfo, fd)
		if openErr != nil {
			result = openErr
			return
		}
		filesystemErr := checkProcFilesystem(file)
		body, readErr := readBounded(file, 4096)
		closeErr := file.Close()
		if filesystemErr != nil || readErr != nil || closeErr != nil {
			result = errors.Join(filesystemErr, readErr, closeErr)
			return
		}
		if result = pidFDIdentity(body, w.child.ProcessID, w.child.ProcProcessID); result != nil {
			return
		}
		type pollDescriptor struct {
			FD      int32
			Events  int16
			Revents int16
		}
		poll := pollDescriptor{FD: int32(fd), Events: 1}
		zero := syscall.Timespec{}
		for attempt := 0; attempt < 3; attempt++ {
			ready, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&poll)), 1,
				uintptr(unsafe.Pointer(&zero)), 0, 0, 0)
			if errno == syscall.EINTR {
				continue
			}
			if errno != 0 {
				result = errno
			} else if ready != 0 || poll.Revents != 0 {
				result = errors.New("Linux child pidfd observed native process retirement")
			}
			return
		}
		result = errors.New("Linux child pidfd liveness readback was repeatedly interrupted")
	})
	return errors.Join(err, result)
}

func (w *CreatedWitness) enter(ctx context.Context) error {
	if w == nil || ctx == nil || w.gate == nil {
		return errors.New("Linux child has no captured native witness")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.gate:
		return nil
	}
}

func (w *CreatedWitness) Current(ctx context.Context) (Observation, error) {
	if err := w.enter(ctx); err != nil {
		return Observation{}, err
	}
	defer func() { w.gate <- struct{}{} }()
	if ctx.Err() != nil || !w.complete || w.revoked || w.closed {
		return Observation{}, errors.New("Linux child native witness is incomplete or retired")
	}
	if err := w.currentDescriptor(); err != nil {
		w.revoked = true
		return Observation{}, err
	}
	actual, err := w.task.Current(ctx)
	if err != nil || actual != w.child {
		w.revoked = true
		return Observation{}, errors.Join(err, errors.New("Linux child changed its original authenticated task"))
	}
	if err := w.currentDescriptor(); err != nil {
		w.revoked = true
		return Observation{}, err
	}
	return actual, ctx.Err()
}

func (w *CreatedWitness) Close(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if err := w.enter(ctx); err != nil {
		return err
	}
	defer func() { w.gate <- struct{}{} }()
	w.revoked = true
	if w.task != nil {
		if err := w.task.Close(ctx); err != nil {
			return err
		}
		w.task = nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.descriptor != nil {
		if err := w.descriptor.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			w.closeErr = errors.Join(w.closeErr, err)
			return err
		}
		w.descriptor = nil
	}
	if w.fdinfo != nil {
		if err := w.fdinfo.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			w.closeErr = errors.Join(w.closeErr, err)
			return err
		}
		w.fdinfo = nil
	}
	if w.closeErr != nil {
		return w.closeErr
	}
	w.closed = true
	return nil
}
