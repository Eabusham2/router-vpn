//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var ErrElevationCancelled = errors.New("Windows administrator permission was cancelled")

type shellExecuteInfo struct {
	Size, Mask                        uint32
	Window                            syscall.Handle
	Verb, File, Parameters, Directory *uint16
	Show                              int32
	Instance                          syscall.Handle
	IDList                            uintptr
	Class                             *uint16
	ClassKey                          syscall.Handle
	HotKey                            uint32
	Icon, Process                     syscall.Handle
}

// LaunchElevated asks Windows for consent to run exactly the pinned executable.
// Arguments contain only public rendezvous information. All secrets belong to
// the later independently authenticated pipe handshake.
//
// Native UAC consent is joined, not abandoned when ctx expires. If Windows
// creates a process after cancellation, the returned non-nil Process still
// belongs to the caller and must be retained through its bootstrap exit. This
// function never hides a late process behind a cancellation-only return.
func LaunchElevated(ctx context.Context, image *Image, arguments []string) (*Process, error) {
	api, err := native()
	if err != nil {
		return nil, err
	}
	return launchSuspendedElevated(ctx, image, arguments, api, func(info *shellExecuteInfo) (bool, error) {
		ok, _, err := api.shellExecute.Call(uintptr(unsafe.Pointer(info)))
		return ok != 0, err
	})
}

func launchElevated(ctx context.Context, image *Image, arguments []string, api *nativeAPI, execute func(*shellExecuteInfo) (bool, error)) (*Process, error) {
	if ctx == nil || image == nil || api == nil || execute == nil {
		return nil, errors.New("Windows elevation requires a captured executable and live caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	image.mu.Lock()
	defer image.mu.Unlock()
	if image.closed || len(image.handles) == 0 {
		return nil, ErrClosed
	}
	var quoted []string
	for _, argument := range arguments {
		if len(argument) > 1024 || strings.ContainsAny(argument, "\x00\r\n") {
			return nil, errors.New("Windows elevation argument is invalid")
		}
		quoted = append(quoted, syscall.EscapeArg(argument))
	}
	if len(quoted) > 8 || len(strings.Join(quoted, " ")) > 4096 {
		return nil, errors.New("Windows elevation argument set is unbounded")
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(image.path)
	parameters, _ := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	directory, _ := syscall.UTF16PtrFromString(filepath.Dir(image.path))
	info := shellExecuteInfo{Mask: 0x540, /* NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI */
		Verb: verb, File: file, Parameters: parameters, Directory: directory}
	info.Size = uint32(unsafe.Sizeof(info))
	if info.Size != 112 {
		return nil, errors.New("Windows elevation ABI changed")
	}
	type result struct {
		process *Process
		err     error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		status, _, _ := api.initializeCOM.Call(0, 2|4 /* apartment threaded, disable OLE1 DDE */)
		if uint32(status) > 1 {
			done <- result{err: fmt.Errorf("Windows elevation COM initialization failed (0x%08x)", uint32(status))}
			return
		}
		defer api.uninitializeCOM.Call()
		ok, callErr := execute(&info)
		var process *Process
		var processErr error
		if info.Process != 0 {
			// A valid Shell handle stays owned even if its PID readback fails.
			// The public suspended path must still terminate/join that exact
			// object and return any unjoined owner with its failure.
			if info.Process == syscall.InvalidHandle {
				processErr = errors.New("Windows elevation returned an invalid process handle")
			} else {
				process = &Process{handle: info.Process, closed: make(chan struct{})}
				pid, _, e := api.processID.Call(uintptr(info.Process))
				if pid == 0 || pid > 0xffffffff {
					processErr = nativeError("captured Shell process identity", e)
				} else {
					process.pid = uint32(pid)
				}
			}
		}
		if !ok {
			if errors.Is(callErr, syscall.Errno(1223)) {
				callErr = ErrElevationCancelled
			} else {
				callErr = nativeError("administrator launch", callErr)
			}
			done <- result{process, errors.Join(callErr, processErr)}
			return
		}
		if processErr != nil || process == nil {
			done <- result{process, errors.Join(processErr, errors.New("Windows elevation returned no owned process handle"))}
			return
		}
		done <- result{process, ctx.Err()}
	}()
	value := <-done
	runtime.KeepAlive(verb)
	runtime.KeepAlive(file)
	runtime.KeepAlive(parameters)
	runtime.KeepAlive(directory)
	return value.process, value.err
}

type jobLimits struct {
	ProcessTime, JobTime                                       int64
	Flags                                                      uint32
	MinimumWorkingSet, MaximumWorkingSet                       uintptr
	ActiveProcesses                                            uint32
	Affinity                                                   uintptr
	Priority, Scheduling                                       uint32
	IO                                                         [6]uint64
	ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
}

var processLifetimeJob struct {
	sync.Mutex
	handle syscall.Handle
}

// OwnProcessLifetime attaches this controller to a private kill-on-close Job
// before application initialization can start any child. The non-inheritable
// Job handle intentionally has process lifetime: normal controller shutdown
// first drains its owners; Windows closes this final handle during process exit
// and terminates any remaining descendants. A destructor cannot accidentally
// kill its own still-running controller before the cleanup receipt is flushed.
func OwnProcessLifetime() error {
	api, err := native()
	if err != nil {
		return err
	}
	processLifetimeJob.Lock()
	defer processLifetimeJob.Unlock()
	current := ^uintptr(0) // GetCurrentProcess pseudo-handle.
	if processLifetimeJob.handle != 0 {
		var member uint32
		ok, _, callErr := api.inJob.Call(current, uintptr(processLifetimeJob.handle), uintptr(unsafe.Pointer(&member)))
		if ok == 0 || member != 1 {
			return nativeError("retained process Job membership", callErr)
		}
		return nil
	}
	identity, err := currentIdentity()
	if err != nil {
		return err
	}
	var handle syscall.Handle
	err = withDescriptor(identity.SID, func(attributes *syscall.SecurityAttributes) error {
		value, _, callErr := api.createJob.Call(uintptr(unsafe.Pointer(attributes)), 0)
		handle = syscall.Handle(value)
		if handle == 0 {
			return nativeError("owned process Job creation", callErr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	limits := jobLimits{Flags: 0x2000 /* JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE */}
	if unsafe.Sizeof(limits) != 144 {
		_ = syscall.CloseHandle(handle)
		return errors.New("Windows process Job ABI changed")
	}
	ok, _, callErr := api.setJob.Call(uintptr(handle), 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		return errors.Join(nativeError("owned process Job limits", callErr), syscall.CloseHandle(handle))
	}
	ok, _, callErr = api.assignJob.Call(uintptr(handle), current)
	if ok == 0 {
		return errors.Join(nativeError("owned process Job assignment", callErr), syscall.CloseHandle(handle))
	}
	// After assignment, closing this handle would terminate the caller itself.
	// Retain it even if the independent membership read fails; no startup is
	// admitted, and the imminent process exit owns all kernel cleanup.
	processLifetimeJob.handle = handle
	var member uint32
	ok, _, callErr = api.inJob.Call(current, uintptr(handle), uintptr(unsafe.Pointer(&member)))
	if ok == 0 || member != 1 {
		return nativeError("owned process Job membership readback", callErr)
	}
	return nil
}
