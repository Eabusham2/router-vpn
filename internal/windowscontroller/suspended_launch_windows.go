//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Shell's documented creation site supplies flags to the actual CreateProcess
// call. A non-S_OK OnCreating result prevents creation; AddCreateFlags preserves
// Shell's own flags. No undocumented process-resume API participates here.
// https://learn.microsoft.com/windows/win32/api/shobjidl_core/nf-shobjidl_core-icreatingprocess-oncreating
// https://learn.microsoft.com/windows/win32/api/shobjidl_core/nf-shobjidl_core-icreateprocessinputs-addcreateflags
var shellUnknownIID = syscall.GUID{Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var shellServiceIID = syscall.GUID{Data1: 0x6d5140c1, Data2: 0x7436, Data3: 0x11ce, Data4: [8]byte{0x80, 0x34, 0, 0xaa, 0, 0x60, 9, 0xfa}}
var shellCreatingIID = syscall.GUID{Data1: 0xc2b937a9, Data2: 0x3110, Data3: 0x4398, Data4: [8]byte{0x8a, 0x56, 0xf3, 0x4c, 0x63, 0x42, 0xd2, 0x44}}

type shellCreationInterface struct {
	vtable *[4]uintptr
	owner  *shellCreationSite
}

type shellCreationSite struct {
	service, creating             shellCreationInterface
	serviceVtable, creatingVtable [4]uintptr
	ctx                           context.Context
	references, calls             atomic.Int32
	before, after, result         atomic.Uint32
	denied                        atomic.Bool
}

var shellCreationSites struct {
	sync.Mutex
	owners map[*shellCreationSite]struct{}
}

func shellCreationQuery(this *shellCreationInterface, iid *syscall.GUID, destination *unsafe.Pointer) uintptr {
	if this == nil || this.owner == nil || iid == nil || destination == nil {
		return 0x80004003 // E_POINTER
	}
	*destination = nil
	site := this.owner
	switch *iid {
	case shellUnknownIID, shellServiceIID:
		*destination = unsafe.Pointer(&site.service)
	case shellCreatingIID:
		*destination = unsafe.Pointer(&site.creating)
	default:
		return 0x80004002 // E_NOINTERFACE
	}
	site.references.Add(1)
	return 0
}

func shellCreationAddRef(this *shellCreationInterface) uintptr {
	return uintptr(this.owner.references.Add(1))
}

func shellCreationRelease(this *shellCreationInterface) uintptr {
	site := this.owner
	remaining := site.references.Add(-1)
	if remaining == 0 {
		shellCreationSites.Lock()
		delete(shellCreationSites.owners, site)
		shellCreationSites.Unlock()
	}
	return uintptr(remaining)
}

func shellCreationQueryService(this *shellCreationInterface, service, iid *syscall.GUID, destination *unsafe.Pointer) uintptr {
	if destination == nil {
		return 0x80004003
	}
	*destination = nil
	if service == nil || *service != shellCreatingIID {
		return 0x80004002
	}
	return shellCreationQuery(this, iid, destination)
}

func shellOnCreating(this *shellCreationInterface, inputs unsafe.Pointer) uintptr {
	if this == nil || this.owner == nil {
		return 0x80004003
	}
	site := this.owner
	reject := func(status uint32) uintptr {
		site.denied.Store(true)
		site.result.Store(status)
		return uintptr(status)
	}
	if site.calls.Add(1) != 1 || inputs == nil {
		return reject(0x8000ffff) // E_UNEXPECTED
	}
	if site.ctx.Err() != nil {
		return reject(0x800704c7) // HRESULT_FROM_WIN32(ERROR_CANCELLED)
	}
	vtable := *(**[6]uintptr)(inputs)
	if vtable == nil || vtable[3] == 0 || vtable[5] == 0 {
		return reject(0x80004003)
	}
	var before, after uint32
	status, _, _ := syscall.SyscallN(vtable[3], uintptr(inputs), uintptr(unsafe.Pointer(&before)))
	site.before.Store(before)
	if uint32(status) != 0 {
		return reject(uint32(status))
	}
	status, _, _ = syscall.SyscallN(vtable[5], uintptr(inputs), 4 /* CREATE_SUSPENDED */)
	if uint32(status) != 0 {
		return reject(uint32(status))
	}
	status, _, _ = syscall.SyscallN(vtable[3], uintptr(inputs), uintptr(unsafe.Pointer(&after)))
	site.after.Store(after)
	if uint32(status) != 0 {
		return reject(uint32(status))
	}
	if after&4 == 0 || after&before != before || site.calls.Load() != 1 || site.denied.Load() {
		return reject(0x8000ffff)
	}
	if site.ctx.Err() != nil {
		return reject(0x800704c7)
	}
	site.result.Store(0)
	return 0
}

func newShellCreationSite(ctx context.Context) (*shellCreationSite, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("suspended Shell creation requires its live caller")
	}
	shellCreationSites.Lock()
	defer shellCreationSites.Unlock()
	if len(shellCreationSites.owners) >= 64 {
		return nil, errors.New("Windows Shell retains too many unfinished creation sites")
	}
	site := &shellCreationSite{ctx: ctx}
	site.references.Store(1)
	site.result.Store(0x8000ffff)
	site.serviceVtable = [4]uintptr{syscall.NewCallback(shellCreationQuery), syscall.NewCallback(shellCreationAddRef), syscall.NewCallback(shellCreationRelease), syscall.NewCallback(shellCreationQueryService)}
	site.creatingVtable = [4]uintptr{site.serviceVtable[0], site.serviceVtable[1], site.serviceVtable[2], syscall.NewCallback(shellOnCreating)}
	site.service = shellCreationInterface{vtable: &site.serviceVtable, owner: site}
	site.creating = shellCreationInterface{vtable: &site.creatingVtable, owner: site}
	if shellCreationSites.owners == nil {
		shellCreationSites.owners = make(map[*shellCreationSite]struct{})
	}
	// Native COM references can outlive the synchronous call. Release removes
	// this GC root only after both Shell and our own reference have finished.
	shellCreationSites.owners[site] = struct{}{}
	return site, nil
}

func (site *shellCreationSite) prove() error {
	if site == nil || site.calls.Load() != 1 || site.denied.Load() || site.result.Load() != 0 ||
		site.after.Load()&4 == 0 || site.after.Load()&site.before.Load() != site.before.Load() {
		return errors.New("Windows Shell did not prove its exact suspended creation callback")
	}
	return nil
}

// shellCreationNameLocked obtains a Shell-compatible spelling from the held
// file, never from argv, PATH or a saved drive name. This spelling is only a
// creation request. The actual suspended image must be proved independently
// through its native kernel path before any thread is resumed.
func (image *Image) shellCreationNameLocked(api *nativeAPI) (string, syscall.Handle, error) {
	if image.closed || len(image.handles) == 0 || !strings.HasPrefix(strings.ToLower(image.path), strings.ToLower(volumeGUIDPrefix)) {
		return "", 0, ErrClosed
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := api.finalPath.Call(uintptr(image.handles[len(image.handles)-1]), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0 /* VOLUME_NAME_DOS */)
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", 0, nativeError("Shell creation spelling from retained image", callErr)
	}
	path := strings.TrimPrefix(syscall.UTF16ToString(buffer[:length]), `\\?\`)
	checked, err := localExecutablePath(path)
	if err != nil || len(checked) < 3 || checked[1] != ':' || checked[2] != '\\' {
		return "", 0, errors.Join(err, errors.New("captured image has no local Shell creation spelling"))
	}
	name, err := syscall.UTF16PtrFromString(checked)
	if err != nil {
		return "", 0, err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000, 0)
	if err != nil {
		return "", 0, nativeError("retain Shell creation spelling", err)
	}
	var actual syscall.ByHandleFileInformation
	err = syscall.GetFileInformationByHandle(handle, &actual)
	want := image.identity
	if err != nil || actual.FileAttributes&(0x400|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 || want.NumberOfLinks == 0 ||
		actual.VolumeSerialNumber != want.VolumeSerialNumber || actual.FileIndexHigh != want.FileIndexHigh || actual.FileIndexLow != want.FileIndexLow || actual.NumberOfLinks != want.NumberOfLinks {
		closeErr := syscall.CloseHandle(handle)
		if closeErr != nil {
			image.handles = append(image.handles, handle)
		}
		return "", 0, errors.Join(err, closeErr, errors.New("Shell creation spelling no longer selects the retained image"))
	}
	runtime.KeepAlive(buffer)
	return checked, handle, nil
}

func launchSuspendedElevated(ctx context.Context, image *Image, arguments []string, api *nativeAPI, execute func(*shellExecuteInfo) (bool, error)) (*Process, error) {
	if ctx == nil || image == nil || api == nil || execute == nil {
		return nil, errors.New("suspended Windows elevation requires captured owners")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	original, err := CurrentIdentity()
	if err != nil || !original.Primary {
		return nil, errors.Join(err, errors.New("Windows elevation lost the original primary desktop token"))
	}
	site, err := newShellCreationSite(ctx)
	if err != nil {
		return nil, err
	}
	defer shellCreationRelease(&site.service)
	process, launchErr := launchElevated(ctx, image, arguments, api, func(info *shellExecuteInfo) (bool, error) {
		path, held, err := image.shellCreationNameLocked(api)
		if err != nil {
			return false, err
		}
		name, _ := syscall.UTF16PtrFromString(path)
		info.File, info.Directory = name, nil
		info.Mask |= 0x08000000 // SEE_MASK_FLAG_HINST_IS_SITE
		info.Instance = syscall.Handle(uintptr(unsafe.Pointer(&site.service)))
		ok, callErr := execute(info)
		if err := syscall.CloseHandle(held); err != nil {
			image.handles = append(image.handles, held)
			callErr, ok = errors.Join(callErr, err), false
		}
		runtime.KeepAlive(name)
		return ok, callErr
	})
	if process == nil {
		return nil, launchErr
	}
	reject := func(cause error) (*Process, error) {
		return process, errors.Join(cause, retireSuspendedShell(process))
	}
	if launchErr != nil {
		return reject(launchErr)
	}
	if err := site.prove(); err != nil {
		return reject(err)
	}
	thread, err := captureSuspendedShellThread(api, process)
	if thread != 0 {
		process.mu.Lock()
		process.launchThread = thread
		process.mu.Unlock()
	}
	if err != nil {
		return reject(err)
	}
	if err := verifySuspendedShellImage(api, process, image); err != nil {
		return reject(err)
	}
	elevated, err := process.Identity()
	if err != nil || !elevated.Primary || !elevated.Elevated || !elevated.Administrator || elevated.SessionID != original.SessionID {
		return reject(errors.Join(err, errors.New("suspended Shell child has no exact administrator token in the captured desktop session")))
	}
	if err := resumeSuspendedShellThread(ctx, api, process, thread); err != nil {
		return reject(err)
	}
	return process, nil
}

func retireSuspendedShell(process *Process) error {
	handle, release, err := process.borrow()
	if err != nil {
		return err
	}
	defer release()
	terminated := syscall.TerminateProcess(handle, 98)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := process.Wait(ctx); err != nil {
		// The returned Process still owns both kernel handles. No PID reopen,
		// debug privilege or unjoined reference close can conceal this failure.
		return errors.Join(terminated, err, errors.New("the rejected suspended Shell owner remains retained and unjoined"))
	}
	return nil
}

func captureSuspendedShellThread(api *nativeAPI, process *Process) (syscall.Handle, error) {
	handle, release, err := process.borrow()
	if err != nil {
		return 0, err
	}
	defer release()
	if pid, _, e := api.processID.Call(uintptr(handle)); pid == 0 || pid != uintptr(process.PID()) {
		return 0, errors.Join(e, errors.New("suspended Shell process lost its retained identity"))
	}
	names := []string{"CreateToolhelp32Snapshot", "Thread32First", "Thread32Next", "OpenThread", "GetProcessIdOfThread", "SuspendThread"}
	procedures := make([]*syscall.Proc, len(names))
	for index, name := range names {
		procedures[index], err = api.processID.Dll.FindProc(name)
		if err != nil {
			return 0, err
		}
	}
	snapshot, _, callErr := procedures[0].Call(4 /* TH32CS_SNAPTHREAD */, 0)
	if syscall.Handle(snapshot) == syscall.InvalidHandle {
		return 0, nativeError("suspended Shell thread inventory", callErr)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))
	type threadEntry struct {
		Size, Usage, ID, Owner uint32
		Base, Delta            int32
		Flags                  uint32
	}
	entry := threadEntry{Size: uint32(unsafe.Sizeof(threadEntry{}))}
	if entry.Size != 28 {
		return 0, errors.New("suspended Shell thread ABI changed")
	}
	var retained syscall.Handle
	count := 0
	ok, _, callErr := procedures[1].Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	for scanned := 0; ok != 0; scanned++ {
		if scanned >= 100000 {
			return retained, errors.New("suspended Shell thread inventory exceeded its bound")
		}
		if entry.Owner == process.PID() {
			count++
			if count != 1 {
				return retained, errors.New("suspended Shell child has more than its single initial thread")
			}
			value, _, openErr := procedures[3].Call(0x0800|0x0002 /* QUERY_LIMITED_INFORMATION | SUSPEND_RESUME */, 0, uintptr(entry.ID))
			retained = syscall.Handle(value)
			if retained == 0 {
				return 0, nativeError("retain suspended Shell initial thread", openErr)
			}
			actualPID, _, ownerErr := procedures[4].Call(uintptr(retained))
			if actualPID != uintptr(process.PID()) {
				return retained, errors.Join(ownerErr, errors.New("suspended Shell initial thread belongs to another process"))
			}
			previous, _, suspendErr := procedures[5].Call(uintptr(retained))
			if uint32(previous) != 1 {
				return retained, errors.Join(suspendErr, errors.New("Shell child did not retain exactly its original creation suspension"))
			}
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ok, _, callErr = procedures[2].Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	if !errors.Is(callErr, syscall.ERROR_NO_MORE_FILES) || count != 1 || retained == 0 {
		return retained, errors.Join(nativeError("complete suspended Shell thread inventory", callErr), errors.New("Shell child has no single retained initial thread"))
	}
	return retained, nil
}

func verifySuspendedShellImage(api *nativeAPI, process *Process, image *Image) (failure error) {
	handle, release, err := process.borrow()
	if err != nil {
		return err
	}
	defer release()
	image.mu.Lock()
	defer image.mu.Unlock()
	if image.closed || len(image.handles) == 0 {
		return ErrClosed
	}
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	ok, _, callErr := api.processImage.Call(uintptr(handle), 1 /* PROCESS_NAME_NATIVE */, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if ok == 0 || length == 0 || length >= uint32(len(buffer)) {
		return nativeError("suspended Shell native image name", callErr)
	}
	path := syscall.UTF16ToString(buffer[:length])
	const prefix = `\Device\`
	rest, valid := strings.CutPrefix(path, prefix)
	volume, suffix, slash := strings.Cut(rest, `\`)
	if !valid || !slash || volume == "" || suffix == "" {
		return errors.New("suspended Shell image is not a local native volume object")
	}
	for _, part := range strings.Split(rest, `\`) {
		if part == "" || strings.TrimRight(part, ". ") != part || strings.ContainsAny(part, ":/\x00") {
			return errors.New("suspended Shell native image has an ambiguous component")
		}
	}
	// Compare the kernel's native name directly with the native name of the
	// held local-volume file before reopening anything. The retained ancestry
	// prevents an intermediate alias or renamed parent from choosing its target.
	expectedLength, _, expectedErr := api.finalPath.Call(uintptr(image.handles[len(image.handles)-1]), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 2 /* VOLUME_NAME_NT */)
	if expectedLength == 0 || expectedLength >= uintptr(len(buffer)) {
		return nativeError("retained Shell image native name", expectedErr)
	}
	if !strings.EqualFold(syscall.UTF16ToString(buffer[:expectedLength]), path) {
		return errors.New("suspended Shell process mapped a different captured native image path")
	}
	name, err := syscall.UTF16PtrFromString(`\\?\GLOBALROOT` + path)
	if err != nil {
		return err
	}
	actualHandle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000, 0)
	if err != nil {
		return nativeError("suspended Shell native image object", err)
	}
	defer func() {
		if err := syscall.CloseHandle(actualHandle); err != nil {
			image.handles = append(image.handles, actualHandle)
			failure = errors.Join(failure, err)
		}
	}()
	var actual, retained syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(actualHandle, &actual); err != nil {
		return err
	}
	if err := syscall.GetFileInformationByHandle(image.handles[len(image.handles)-1], &retained); err != nil {
		return err
	}
	want := image.identity
	if actual.FileAttributes&(0x400|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 || want.NumberOfLinks == 0 || retained.NumberOfLinks != want.NumberOfLinks ||
		retained.VolumeSerialNumber != want.VolumeSerialNumber || retained.FileIndexHigh != want.FileIndexHigh || retained.FileIndexLow != want.FileIndexLow ||
		actual.VolumeSerialNumber != want.VolumeSerialNumber || actual.FileIndexHigh != want.FileIndexHigh || actual.FileIndexLow != want.FileIndexLow || actual.NumberOfLinks != want.NumberOfLinks {
		return errors.New("suspended Shell process mapped a different captured image object")
	}
	length2, _, callErr := api.finalPath.Call(uintptr(actualHandle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 1 /* VOLUME_NAME_GUID */)
	if length2 == 0 || length2 >= uintptr(len(buffer)) || !strings.EqualFold(syscall.UTF16ToString(buffer[:length2]), image.path) {
		return nativeError("suspended Shell native image volume readback", callErr)
	}
	runtime.KeepAlive(buffer)
	return process.Alive()
}

func resumeSuspendedShellThread(ctx context.Context, api *nativeAPI, process *Process, thread syscall.Handle) error {
	owner, err := api.processID.Dll.FindProc("GetProcessIdOfThread")
	if err != nil {
		return err
	}
	resume, err := api.processID.Dll.FindProc("ResumeThread")
	if err != nil {
		return err
	}
	// Our readback added one suspension. Remove only those two captured counts,
	// checking the same retained process/thread and caller before each step.
	for _, expected := range []uint32{2, 1} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := process.Alive(); err != nil {
			return err
		}
		pid, _, ownerErr := owner.Call(uintptr(thread))
		if thread == 0 || pid != uintptr(process.PID()) {
			return errors.Join(ownerErr, errors.New("Shell resume lost its exact retained thread owner"))
		}
		previous, _, callErr := resume.Call(uintptr(thread))
		if uint32(previous) != expected {
			return errors.Join(callErr, fmt.Errorf("Shell initial thread changed its captured suspension count (got=%d want=%d)", uint32(previous), expected))
		}
	}
	return nil
}
