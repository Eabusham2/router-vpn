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
	"testing"
	"time"
	"unsafe"
)

// These are the documented SDK IUnknown, IServiceProvider and ICreatingProcess
// contracts. SID_ExecuteCreatingProcess is IID_ICreatingProcess. No undocumented
// post-creation COM interface or process-resume API participates in this probe.
// https://learn.microsoft.com/windows/win32/api/shobjidl_core/nn-shobjidl_core-icreatingprocess
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/ShObjIdl_core.h
var fixtureShellUnknownIID = syscall.GUID{Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var fixtureShellServiceIID = syscall.GUID{Data1: 0x6d5140c1, Data2: 0x7436, Data3: 0x11ce, Data4: [8]byte{0x80, 0x34, 0, 0xaa, 0, 0x60, 9, 0xfa}}
var fixtureShellCreatingIID = syscall.GUID{Data1: 0xc2b937a9, Data2: 0x3110, Data3: 0x4398, Data4: [8]byte{0x8a, 0x56, 0xf3, 0x4c, 0x63, 0x42, 0xd2, 0x44}}

type fixtureShellCOMInterface struct {
	vtable *[4]uintptr
	owner  *fixtureSuspendedShellSite
}

type fixtureSuspendedShellSite struct {
	service, creating             fixtureShellCOMInterface
	serviceVtable, creatingVtable [4]uintptr
	references, calls             atomic.Int32
	before, after, result         atomic.Uint32
}

var fixtureSuspendedShellSites struct {
	sync.Mutex
	owners      []*fixtureSuspendedShellSite
	retirements []*fixtureSuspendedShellOwner
}

type fixtureSuspendedShellOwner struct {
	process, job syscall.Handle
	pid          uint32
	terminateJob *syscall.Proc
	joined       bool
}

func (owner *fixtureSuspendedShellOwner) retire() error {
	if !owner.joined {
		terminateErr := syscall.TerminateProcess(owner.process, 98)
		if terminateErr != nil && owner.pid != 0 {
			// The original handle stays held, so this PID cannot be recycled.
			cleanup, openErr := syscall.OpenProcess(0x00100001, false, owner.pid)
			if openErr == nil {
				terminateErr = errors.Join(syscall.TerminateProcess(cleanup, 98), syscall.CloseHandle(cleanup))
			} else {
				terminateErr = errors.Join(terminateErr, openErr)
			}
		}
		terminated, _, jobErr := owner.terminateJob.Call(uintptr(owner.job), 98)
		if terminated != 0 {
			jobErr = nil
		}
		wait, waitErr := syscall.WaitForSingleObject(owner.process, 5000)
		if waitErr != nil || wait != syscall.WAIT_OBJECT_0 {
			// Do not drop either owner merely because a bounded join failed.
			return errors.Join(terminateErr, jobErr, waitErr, fmt.Errorf("suspended Shell exact child is still unjoined (wait=%d)", wait))
		}
		owner.joined = true
	}
	var closeErr error
	if owner.process != 0 {
		if err := syscall.CloseHandle(owner.process); err != nil {
			closeErr = errors.Join(closeErr, err)
		} else {
			owner.process = 0
		}
	}
	if owner.job != 0 {
		if err := syscall.CloseHandle(owner.job); err != nil {
			closeErr = errors.Join(closeErr, err)
		} else {
			owner.job = 0
		}
	}
	return closeErr
}

func fixtureShellSite(this *fixtureShellCOMInterface) *fixtureSuspendedShellSite {
	return this.owner
}

func fixtureShellQuery(this *fixtureShellCOMInterface, iid *syscall.GUID, destination *unsafe.Pointer) uintptr {
	if this == nil || this.owner == nil || iid == nil || destination == nil {
		return 0x80004003 // E_POINTER
	}
	*destination = nil
	site := fixtureShellSite(this)
	switch *iid {
	case fixtureShellUnknownIID, fixtureShellServiceIID:
		*destination = unsafe.Pointer(&site.service)
	case fixtureShellCreatingIID:
		*destination = unsafe.Pointer(&site.creating)
	default:
		return 0x80004002 // E_NOINTERFACE
	}
	site.references.Add(1)
	return 0
}

func fixtureShellAddRef(this *fixtureShellCOMInterface) uintptr {
	return uintptr(fixtureShellSite(this).references.Add(1))
}

func fixtureShellRelease(this *fixtureShellCOMInterface) uintptr {
	return uintptr(fixtureShellSite(this).references.Add(-1))
}

func fixtureShellQueryService(this *fixtureShellCOMInterface, service, iid *syscall.GUID, destination *unsafe.Pointer) uintptr {
	if destination == nil {
		return 0x80004003
	}
	*destination = nil
	if service == nil || *service != fixtureShellCreatingIID {
		return 0x80004002
	}
	return fixtureShellQuery(this, iid, destination)
}

func fixtureShellOnCreating(this *fixtureShellCOMInterface, inputs unsafe.Pointer) uintptr {
	site := fixtureShellSite(this)
	if !site.calls.CompareAndSwap(0, 1) || inputs == nil {
		site.result.Store(0x8000ffff) // E_UNEXPECTED
		return 0x8000ffff
	}
	// ICreateProcessInputs: IUnknown, GetCreateFlags, SetCreateFlags,
	// AddCreateFlags. Add preserves Shell's existing flags.
	vtable := *(**[6]uintptr)(inputs)
	var before, after uint32
	status, _, _ := syscall.SyscallN(vtable[3], uintptr(inputs), uintptr(unsafe.Pointer(&before)))
	site.before.Store(before)
	if uint32(status)&0x80000000 == 0 {
		status, _, _ = syscall.SyscallN(vtable[5], uintptr(inputs), 4 /* CREATE_SUSPENDED */)
	}
	if uint32(status)&0x80000000 == 0 {
		status, _, _ = syscall.SyscallN(vtable[3], uintptr(inputs), uintptr(unsafe.Pointer(&after)))
	}
	site.after.Store(after)
	if uint32(status)&0x80000000 == 0 && after&4 == 0 {
		status = 0x8000ffff
	}
	site.result.Store(uint32(status))
	return status
}

func fixtureNewSuspendedShellSite() (*fixtureSuspendedShellSite, error) {
	fixtureSuspendedShellSites.Lock()
	defer fixtureSuspendedShellSites.Unlock()
	if len(fixtureSuspendedShellSites.owners) >= 8 {
		return nil, errors.New("suspended Shell diagnostic exceeded its bounded site count")
	}
	site := &fixtureSuspendedShellSite{}
	site.references.Store(1)
	site.serviceVtable = [4]uintptr{syscall.NewCallback(fixtureShellQuery), syscall.NewCallback(fixtureShellAddRef), syscall.NewCallback(fixtureShellRelease), syscall.NewCallback(fixtureShellQueryService)}
	site.creatingVtable = [4]uintptr{site.serviceVtable[0], site.serviceVtable[1], site.serviceVtable[2], syscall.NewCallback(fixtureShellOnCreating)}
	site.service = fixtureShellCOMInterface{vtable: &site.serviceVtable, owner: site}
	site.creating = fixtureShellCOMInterface{vtable: &site.creatingVtable, owner: site}
	// The bounded, test-only objects stay alive until this test process exits,
	// including if Shell retains a COM reference beyond its synchronous return.
	fixtureSuspendedShellSites.owners = append(fixtureSuspendedShellSites.owners, site)
	return site, nil
}

func fixtureShellSuspendReadback(api *nativeAPI, pid uint32) (string, error) {
	kernel := api.processID.Dll
	names := []string{"CreateToolhelp32Snapshot", "Thread32First", "Thread32Next", "OpenThread", "GetProcessIdOfThread", "SuspendThread"}
	procedures := make([]*syscall.Proc, len(names))
	for index, name := range names {
		var err error
		procedures[index], err = kernel.FindProc(name)
		if err != nil {
			return "", err
		}
	}
	snapshot, _, callErr := procedures[0].Call(4 /* TH32CS_SNAPTHREAD */, 0)
	if syscall.Handle(snapshot) == syscall.InvalidHandle {
		return "", nativeError("suspended diagnostic thread inventory", callErr)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))
	type threadEntry struct {
		Size, Usage, ID, Owner uint32
		Base, Delta            int32
		Flags                  uint32
	}
	entry := threadEntry{Size: uint32(unsafe.Sizeof(threadEntry{}))}
	if entry.Size != 28 {
		return "", errors.New("suspended diagnostic thread ABI changed")
	}
	var observations []string
	var proofErr error
	ok, _, callErr := procedures[1].Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	for count := 0; ok != 0; count++ {
		if count >= 100000 || len(observations) >= 32 {
			return strings.Join(observations, ","), errors.New("suspended diagnostic thread inventory exceeded its bound")
		}
		if entry.Owner == pid {
			handle, _, openErr := procedures[3].Call(0x0800|0x0002 /* QUERY_LIMITED_INFORMATION | SUSPEND_RESUME */, 0, uintptr(entry.ID))
			if handle == 0 {
				return strings.Join(observations, ","), nativeError("suspended diagnostic retained thread", openErr)
			}
			actualPID, _, pidErr := procedures[4].Call(handle)
			if actualPID != uintptr(pid) {
				syscall.CloseHandle(syscall.Handle(handle))
				return strings.Join(observations, ","), errors.Join(pidErr, errors.New("suspended diagnostic thread changed its exact process owner"))
			}
			// This readback only adds suspension. No diagnostic path resumes a
			// thread; the exact retained process is terminated and joined below.
			previous, _, suspendErr := procedures[5].Call(handle)
			closeErr := syscall.CloseHandle(syscall.Handle(handle))
			observations = append(observations, fmt.Sprintf("%d:%d", entry.ID, uint32(previous)))
			if uint32(previous) != 1 {
				proofErr = errors.Join(proofErr, suspendErr, errors.New("Shell did not return exactly one original creation suspension"))
			}
			proofErr = errors.Join(proofErr, closeErr)
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ok, _, callErr = procedures[2].Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	if !errors.Is(callErr, syscall.ERROR_NO_MORE_FILES) {
		proofErr = errors.Join(proofErr, nativeError("suspended diagnostic complete thread inventory", callErr))
	}
	if len(observations) != 1 {
		proofErr = errors.Join(proofErr, errors.New("Shell did not return the single suspended initial thread"))
	}
	return strings.Join(observations, ","), proofErr
}

// Called only after the existing fully elevated fixture has retained its new
// DOS link, rejected a rebind, and opened the exact captured image through that
// alias. It is evidence about Shell's creation site, never permission to launch
// an unverified alias from another UAC logon namespace or to resume an image.
func fixtureSuspendedShellDiagnostic(t *testing.T, image *Image, alias *uint16) {
	t.Helper()
	identity, err := CurrentIdentity()
	if err != nil || !identity.Elevated || !identity.Administrator || !identity.Primary {
		t.Log("suspended Shell diagnostic requires its already elevated fixture owner:", err)
		return
	}
	api, err := native()
	if err != nil {
		t.Log("suspended Shell diagnostic native API:", err)
		return
	}
	site, err := fixtureNewSuspendedShellSite()
	if err != nil {
		t.Log(err)
		return
	}
	pipe, err := NewPipe()
	if err != nil {
		t.Log("suspended Shell diagnostic pipe:", err)
		return
	}
	defer pipe.Close()
	verb, _ := syscall.UTF16PtrFromString("runas")
	arguments := fixtureArguments("hold", pipe, fixtureExecutable(t))
	for index, argument := range arguments {
		arguments[index] = syscall.EscapeArg(argument)
	}
	parameters, _ := syscall.UTF16PtrFromString(strings.Join(arguments, " "))
	info := shellExecuteInfo{Mask: 0x08000540, /* HINST_IS_SITE | NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI */
		Verb: verb, File: alias, Parameters: parameters, Instance: syscall.Handle(uintptr(unsafe.Pointer(&site.service)))}
	info.Size = uint32(unsafe.Sizeof(info))
	job, _, jobErr := api.createJob.Call(0, 0)
	if job == 0 {
		t.Log("suspended Shell diagnostic could not own its private cleanup Job:", jobErr)
		return
	}
	// The private Job is a second termination owner after Shell returns. It is
	// never named, inherited, assigned to an unrelated process, or published.
	defer func() {
		if job != 0 {
			_ = syscall.CloseHandle(syscall.Handle(job))
		}
	}()
	limits := jobLimits{Flags: 0x2000}
	if ok, _, err := api.setJob.Call(job, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
		t.Log("suspended Shell diagnostic could not arm cleanup Job:", err)
		return
	}
	terminateJob, err := api.createJob.Dll.FindProc("TerminateJobObject")
	if err != nil {
		t.Log("suspended Shell diagnostic has no exact Job termination API:", err)
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status, _, _ := api.initializeCOM.Call(0, 2|4)
	if uint32(status) > 1 {
		t.Logf("suspended Shell diagnostic COM initialization: 0x%08x", uint32(status))
		return
	}
	defer api.uninitializeCOM.Call()
	ok, _, launchErr := api.shellExecute.Call(uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(alias)
	runtime.KeepAlive(verb)
	runtime.KeepAlive(parameters)
	runtime.KeepAlive(site)
	if info.Process == 0 {
		t.Logf("suspended Shell diagnostic launch_ok=%t launch=%v callback_count=%d flags_before=0x%x flags_after=0x%x callback_result=0x%08x owned_process=false", ok != 0, launchErr, site.calls.Load(), site.before.Load(), site.after.Load(), site.result.Load())
		return
	}
	// Transfer both retained handles before every process readback/error branch.
	// A failed join gets a bounded test-cleanup retry. If even that fails, the
	// bounded process-lifetime record retains both owners and the armed Job;
	// no last unjoined reference is discarded or successful retirement claimed.
	owner := &fixtureSuspendedShellOwner{process: info.Process, job: syscall.Handle(job), terminateJob: terminateJob}
	job = 0
	fixtureSuspendedShellSites.Lock()
	fixtureSuspendedShellSites.retirements = append(fixtureSuspendedShellSites.retirements, owner)
	fixtureSuspendedShellSites.Unlock()
	defer func() {
		if err := owner.retire(); err != nil {
			t.Log("suspended Shell diagnostic retained its exact process/Job for cleanup retry:", err)
			t.Cleanup(func() {
				if err := owner.retire(); err != nil {
					t.Error("suspended Shell diagnostic retained unresolved exact process/Job ownership:", err)
					return
				}
				t.Logf("suspended Shell diagnostic exact child terminated and joined after retry: pid=%d, no resume requested", owner.pid)
			})
			return
		}
		t.Logf("suspended Shell diagnostic exact child terminated and joined: pid=%d, no resume requested", owner.pid)
	}()
	actualPID, _, pidErr := api.processID.Call(uintptr(info.Process))
	if actualPID == 0 || actualPID > 0xffffffff {
		t.Log("suspended Shell diagnostic returned no exact process identity:", pidErr)
		return
	}
	pid := uint32(actualPID)
	owner.pid = pid
	granted, accessErr := fixtureShellGrantedAccess(api, info.Process)
	process := &Process{handle: info.Process, pid: pid, closed: make(chan struct{})}
	imageErr := process.VerifyImage(image)
	token, tokenErr := process.Identity()
	if tokenErr == nil && (!token.Primary || !token.Elevated || !token.Administrator || token.SID != identity.SID) {
		tokenErr = errors.New("suspended Shell diagnostic changed its already elevated fixture principal")
	}
	t.Logf("suspended Shell diagnostic returned launch_ok=%t launch=%v callback_count=%d flags_before=0x%x flags_after=0x%x callback_result=0x%08x granted_access=0x%x process_suspend_resume=%t access_read=%v image=%v token=%v", ok != 0, launchErr, site.calls.Load(), site.before.Load(), site.after.Load(), site.result.Load(), granted, granted&0x0800 != 0, accessErr, imageErr, tokenErr)
	if assigned, _, assignErr := api.assignJob.Call(uintptr(owner.job), uintptr(info.Process)); assigned == 0 {
		t.Log("suspended Shell diagnostic could not retain its secondary cleanup Job:", assignErr)
		return
	}
	if imageErr != nil || tokenErr != nil || site.calls.Load() != 1 || site.result.Load()&0x80000000 != 0 || site.after.Load()&4 == 0 {
		t.Logf("suspended Shell diagnostic launch_ok=%t launch=%v callback_count=%d flags_before=0x%x flags_after=0x%x callback_result=0x%08x granted_access=0x%x access_read=%v image=%v token=%v", ok != 0, launchErr, site.calls.Load(), site.before.Load(), site.after.Load(), site.result.Load(), granted, accessErr, imageErr, tokenErr)
		return
	}
	threads, suspendErr := fixtureShellSuspendReadback(api, pid)
	observe, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	acceptErr := pipe.Accept(observe)
	cancel()
	noHello := errors.Is(acceptErr, context.DeadlineExceeded)
	t.Logf("suspended Shell diagnostic launch_ok=%t launch=%v callback_count=%d flags_before=0x%x flags_after=0x%x callback_result=0x%08x granted_access=0x%x process_suspend_resume=%t access_read=%v image=%v token=%v thread_previous_counts=%q suspension=%v no_fixture_connection=%t connection_result=%v; no resume requested", ok != 0, launchErr, site.calls.Load(), site.before.Load(), site.after.Load(), site.result.Load(), granted, granted&0x0800 != 0, accessErr, imageErr, tokenErr, threads, suspendErr, noHello, acceptErr)
}

func fixtureShellGrantedAccess(api *nativeAPI, handle syscall.Handle) (uint32, error) {
	dll, err := syscall.LoadDLL(api.systemDirectory + `\ntdll.dll`)
	if err != nil {
		return 0, err
	}
	defer dll.Release()
	query, err := dll.FindProc("NtQueryObject")
	if err != nil {
		return 0, err
	}
	// PUBLIC_OBJECT_BASIC_INFORMATION from the documented NtQueryObject ABI.
	var information struct {
		Attributes, GrantedAccess, HandleCount, PointerCount uint32
		Reserved                                             [10]uint32
	}
	var returned uint32
	status, _, _ := query.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&information)), unsafe.Sizeof(information), uintptr(unsafe.Pointer(&returned)))
	if uint32(status) != 0 || unsafe.Sizeof(information) != 56 || returned != 56 {
		return 0, fmt.Errorf("suspended Shell handle access query NTSTATUS=0x%08x bytes=%d", uint32(status), returned)
	}
	return information.GrantedAccess, nil
}
