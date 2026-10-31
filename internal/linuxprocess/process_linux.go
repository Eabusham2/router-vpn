//go:build linux

package linuxprocess

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const procFilesystem = 0x9fa0

// Witness owns an actual /proc task directory and additional kernel-opened
// witnesses. An inherited/transferred directory is never reopened by PID.
// Linux keeps this directory bound to its original task after PID reuse.
// The witness observes identity only; its caller retains launch, wait, journal
// and native-protection authority independently.
type Witness struct {
	gate                      chan struct{}
	directory                 *os.File
	directoryIdentity         Object
	image, network, namespace *os.File
	fdinfo                    *os.File
	fdinfoIdentity            Object
	observation               Observation
	complete, revoked, closed bool
	closeErr                  error
}

// SetCloseOnExec prevents an inherited file from escaping through a later
// descendant exec. It reads, preserves, sets and verifies the descriptor flags
// while SyscallConn retains this original file; no numeric fd can be recycled
// during the operation. The caller retains the file on both success and error.
func SetCloseOnExec(file *os.File) error {
	if file == nil {
		return errors.New("Linux inherited descriptor has no retained file")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var nativeErr error
	err = raw.Control(func(fd uintptr) {
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if errno != 0 {
			nativeErr = os.NewSyscallError("fcntl(F_GETFD)", errno)
			return
		}
		expected := flags | syscall.FD_CLOEXEC
		if _, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, expected); errno != 0 {
			nativeErr = os.NewSyscallError("fcntl(F_SETFD)", errno)
			return
		}
		actual, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if errno != 0 {
			nativeErr = os.NewSyscallError("fcntl(F_GETFD) readback", errno)
		} else if actual != expected {
			nativeErr = errors.New("Linux inherited descriptor did not retain its close-on-exec flags")
		}
	})
	return errors.Join(err, nativeErr)
}

func CaptureSelf(ctx context.Context) (*Witness, error) {
	directory, err := os.Open("/proc/self")
	if err != nil {
		return nil, err
	}
	return CaptureDirectory(ctx, directory, os.Getpid())
}

// CaptureDirectory consumes only this exact received descriptor, including
// on a partial failure. It neither scans /proc nor opens /proc/<claimed PID>.
// expectedPID is supplied by actual creation/SCM credentials in the receiver's
// PID namespace, not by a decoded message's claimed sender.
func CaptureDirectory(ctx context.Context, directory *os.File, expectedPID int) (*Witness, error) {
	w := &Witness{directory: directory, gate: make(chan struct{}, 1)}
	defer func() { w.gate <- struct{}{} }()
	if directory != nil {
		if err := SetCloseOnExec(directory); err != nil {
			return w, err
		}
	}
	if ctx == nil || ctx.Err() != nil || directory == nil || expectedPID < 1 || uint64(expectedPID) > 1<<31-1 {
		return w, errors.New("Linux process capture requires its actual retained directory and caller")
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		return w, errors.Join(err, errors.New("Linux process capture did not receive a directory"))
	}
	w.directoryIdentity, err = objectOf(info)
	if err != nil {
		return w, err
	}
	if err = checkProcFilesystem(directory); err != nil {
		return w, err
	}
	if expectedPID == os.Getpid() {
		w.fdinfo, err = w.open("fdinfo", true)
		if err != nil {
			return w, err
		}
		info, statErr := w.fdinfo.Stat()
		w.fdinfoIdentity, err = objectOf(info)
		if statErr != nil || err != nil || !info.IsDir() || checkProcFilesystem(w.fdinfo) != nil {
			return w, errors.Join(statErr, err, errors.New("Linux process lost its original native fdinfo directory"))
		}
	}
	w.image, err = w.open("exe", false)
	if err != nil {
		return w, err
	}
	w.network, err = w.open("ns/net", false)
	if err != nil {
		return w, err
	}
	w.namespace, err = w.open("ns/pid", false)
	if err != nil {
		return w, err
	}
	w.observation, err = w.read(expectedPID)
	if err != nil || w.observation.Validate() != nil {
		return w, errors.Join(err, errors.New("Linux process capture lost its complete native observation"))
	}
	if err := ctx.Err(); err != nil {
		return w, err
	}
	w.complete = true
	return w, nil
}

func objectOf(info os.FileInfo) (Object, error) {
	if info == nil {
		return Object{}, errors.New("Linux process file has no native stat")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Ino == 0 {
		return Object{}, errors.New("Linux process file lost its native inode")
	}
	return Object{Device: uint64(native.Dev), Inode: native.Ino, Mode: native.Mode, UID: native.Uid, GID: native.Gid}, nil
}

func checkProcFilesystem(file *os.File) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var result syscall.Statfs_t
	var nativeErr error
	err = raw.Control(func(fd uintptr) { nativeErr = syscall.Fstatfs(int(fd), &result) })
	if err != nil || nativeErr != nil || result.Type != procFilesystem {
		return errors.Join(err, nativeErr, errors.New("Linux process witness is outside the native proc filesystem"))
	}
	return nil
}

// Only constant kernel task entries reach this helper. exe/ns are intentional
// proc magic links; user-supplied paths and filenames never reach openat.
func (w *Witness) open(name string, nofollow bool) (*os.File, error) {
	switch name {
	case "stat", "status", "fdinfo":
		if !nofollow {
			return nil, errors.New("Linux process text read requires a fixed native entry")
		}
	case "exe", "ns/net", "ns/pid":
		if nofollow {
			return nil, errors.New("Linux process object read requires its kernel link")
		}
	default:
		return nil, errors.New("Linux process cannot open an arbitrary task path")
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC
	if nofollow {
		flags |= syscall.O_NOFOLLOW
	}
	if name == "fdinfo" {
		flags |= syscall.O_DIRECTORY
	}
	raw, err := w.directory.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var nativeErr error
	err = raw.Control(func(parent uintptr) { fd, nativeErr = syscall.Openat(int(parent), name, flags, 0) })
	if err != nil || nativeErr != nil {
		return nil, errors.Join(err, nativeErr)
	}
	return os.NewFile(uintptr(fd), "retained-linux-process-"+name), nil
}

func readBounded(file *os.File, maximum int) ([]byte, error) {
	if file == nil {
		return nil, errors.New("Linux process lost a retained read descriptor")
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	if err != nil || len(body) == 0 || len(body) > maximum {
		return nil, errors.Join(err, errors.New("Linux process read exceeds its native bound"))
	}
	return body, nil
}

func (w *Witness) text(name string, maximum int) ([]byte, error) {
	file, err := w.open(name, true)
	if err != nil {
		return nil, err
	}
	body, readErr := readBounded(file, maximum)
	return body, errors.Join(readErr, file.Close())
}

func ReadBootID() (string, error) {
	file, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	filesystemErr := checkProcFilesystem(file)
	body, readErr := readBounded(file, 37)
	closeErr := file.Close()
	if filesystemErr != nil || readErr != nil || closeErr != nil || len(body) != 37 || body[36] != '\n' || !ValidBootID(string(body[:36])) {
		return "", errors.Join(filesystemErr, readErr, closeErr, errors.New("Linux process lost its bounded kernel boot identity"))
	}
	return string(body[:36]), nil
}

func statusIdentity(body []byte, processID, procProcessID, parentID int) error {
	if len(body) == 0 || len(body) > 65536 {
		return errors.New("Linux process status exceeds its native bound")
	}
	wanted := map[string]bool{"Pid": false, "Tgid": false, "PPid": false, "NSpid": false, "NStgid": false, "Uid": false, "Gid": false}
	for _, line := range strings.Split(string(body), "\n") {
		key, value, found := strings.Cut(line, ":")
		seen, needed := wanted[key]
		if !found || !needed {
			continue
		}
		if seen {
			return errors.New("Linux process status repeated a native identity field")
		}
		wanted[key] = true
		fields := strings.Fields(value)
		switch key {
		case "Uid", "Gid":
			if len(fields) != 4 || fields[0] != "0" || fields[1] != "0" || fields[2] != "0" || fields[3] != "0" {
				return errors.New("Linux process lost its complete privileged credentials")
			}
		case "NSpid", "NStgid":
			if len(fields) < 1 || len(fields) > 32 || fields[0] != strconv.Itoa(procProcessID) || fields[len(fields)-1] != strconv.Itoa(processID) {
				return errors.New("Linux process changed its native PID namespace mapping")
			}
			for _, field := range fields {
				value, err := strconv.ParseUint(field, 10, 31)
				if err != nil || value == 0 || strconv.FormatUint(value, 10) != field {
					return errors.New("Linux process has an invalid native namespace PID")
				}
			}
		default:
			want := procProcessID
			if key == "PPid" {
				want = parentID
			}
			if len(fields) != 1 || fields[0] != strconv.Itoa(want) {
				return errors.New("Linux process stat/status disagree about the original task")
			}
		}
	}
	for _, found := range wanted {
		if !found {
			return errors.New("Linux process status omitted a required native identity")
		}
	}
	return nil
}

func (w *Witness) read(processID int) (Observation, error) {
	info, err := w.directory.Stat()
	identity, identityErr := objectOf(info)
	if err != nil || identityErr != nil || identity != w.directoryIdentity || !info.IsDir() || identity.UID != 0 || identity.GID != 0 {
		return Observation{}, errors.Join(err, identityErr, errors.New("Linux process lost its retained native task directory"))
	}
	if w.fdinfo != nil {
		info, err := w.fdinfo.Stat()
		identity, identityErr := objectOf(info)
		if err != nil || identityErr != nil || identity != w.fdinfoIdentity || !info.IsDir() {
			return Observation{}, errors.Join(err, identityErr, errors.New("Linux process lost its original retained fdinfo directory"))
		}
	}
	beforeRaw, err := w.text("stat", 8192)
	if err != nil {
		return Observation{}, err
	}
	before, err := ParseStat(beforeRaw)
	if err != nil || before.State == 'Z' || before.State == 'X' || before.State == 'x' {
		return Observation{}, errors.Join(err, errors.New("Linux process is no longer a live native task"))
	}
	status, err := w.text("status", 65536)
	if err != nil {
		return Observation{}, err
	}
	if err := statusIdentity(status, processID, before.ProcessID, before.ParentID); err != nil {
		return Observation{}, err
	}
	boot, err := ReadBootID()
	if err != nil {
		return Observation{}, err
	}
	observation := Observation{BootID: boot, ProcessID: processID, ProcProcessID: before.ProcessID, ProcParentID: before.ParentID, StartTicks: before.Start}
	for _, native := range []struct {
		name string
		file *os.File
		out  *Object
	}{{"exe", w.image, &observation.Image}, {"ns/net", w.network, &observation.NetworkNamespace}, {"ns/pid", w.namespace, &observation.PIDNamespace}} {
		original, err := native.file.Stat()
		if err != nil {
			return Observation{}, err
		}
		*native.out, err = objectOf(original)
		if err != nil {
			return Observation{}, err
		}
		actual, err := w.open(native.name, false)
		if err != nil {
			return Observation{}, err
		}
		current, statErr := actual.Stat()
		closeErr := actual.Close()
		if statErr != nil || closeErr != nil || !os.SameFile(original, current) {
			return Observation{}, errors.Join(statErr, closeErr, errors.New("Linux process changed its retained executable or namespace"))
		}
		if native.name == "exe" {
			st, ok := original.Sys().(*syscall.Stat_t)
			if !ok || st.Nlink != 1 {
				return Observation{}, errors.New("Linux process executable lost its sole protected directory entry")
			}
		}
	}
	afterRaw, err := w.text("stat", 8192)
	if err != nil {
		return Observation{}, err
	}
	after, err := ParseStat(afterRaw)
	if err != nil || before.ProcessID != after.ProcessID || before.ParentID != after.ParentID || before.Start != after.Start || after.State == 'Z' || after.State == 'X' || after.State == 'x' {
		return Observation{}, errors.Join(err, errors.New("Linux process changed its native birth during readback"))
	}
	return observation, observation.Validate()
}

func (w *Witness) enter(ctx context.Context) error {
	if w == nil || ctx == nil || w.gate == nil {
		return errors.New("Linux process witness has no captured owner")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.gate:
		return nil
	}
}

func (w *Witness) current(ctx context.Context) (Observation, error) {
	if ctx.Err() != nil || !w.complete || w.revoked || w.closed {
		return Observation{}, errors.New("Linux process witness is incomplete or retired")
	}
	actual, err := w.read(w.observation.ProcessID)
	if err != nil || actual != w.observation {
		w.revoked = true
		return Observation{}, errors.Join(err, errors.New("Linux process witness cannot revive a replaced native identity"))
	}
	return actual, ctx.Err()
}

func (w *Witness) Current(ctx context.Context) (Observation, error) {
	if err := w.enter(ctx); err != nil {
		return Observation{}, err
	}
	defer func() { w.gate <- struct{}{} }()
	return w.current(ctx)
}

func (w *Witness) DuplicateDirectory(ctx context.Context) (*os.File, error) {
	if err := w.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { w.gate <- struct{}{} }()
	if _, err := w.current(ctx); err != nil {
		return nil, err
	}
	return duplicateFile(ctx, w.directory, "original-linux-process-directory")
}

func (w *Witness) duplicateFDInfo(ctx context.Context) (*os.File, error) {
	if err := w.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { w.gate <- struct{}{} }()
	if _, err := w.current(ctx); err != nil {
		return nil, err
	}
	if w.observation.ProcessID != os.Getpid() || w.fdinfo == nil {
		return nil, errors.New("Linux child pidfd readback requires the original creator's native fdinfo directory")
	}
	return duplicateFile(ctx, w.fdinfo, "original-linux-parent-fdinfo-directory")
}

func duplicateFile(ctx context.Context, file *os.File, name string) (*os.File, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd uintptr
	var nativeErr syscall.Errno
	err = raw.Control(func(original uintptr) {
		fd, _, nativeErr = syscall.Syscall(syscall.SYS_FCNTL, original, syscall.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil || nativeErr != 0 {
		if nativeErr != 0 {
			return nil, errors.Join(err, nativeErr)
		}
		return nil, err
	}
	return os.NewFile(fd, name), ctx.Err()
}

func (w *Witness) Close(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if err := w.enter(ctx); err != nil {
		return err
	}
	defer func() { w.gate <- struct{}{} }()
	w.revoked = true
	for _, file := range []**os.File{&w.image, &w.network, &w.namespace, &w.fdinfo, &w.directory} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if *file != nil {
			if err := (*file).Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				w.closeErr = errors.Join(w.closeErr, err)
				return err
			}
			*file = nil
		}
	}
	if w.closeErr != nil {
		return w.closeErr
	}
	w.closed = true
	return nil
}
