//go:build windows

package windowscontroller

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const fixtureRestrictedWorkerEnvironment = "ROUTERVPN_CONTROLLER_DACL_WORKER"

type fixturePrivilegeLUID struct {
	Low  uint32
	High int32
}

// Every DACL operation, including the real production VerifyPeer call and its
// reopened-process mutant, runs in this separate same-user process. Deleting
// SeDebug from a derived primary token prevents an elevated build host from
// bypassing the target DACL; the parent's privileges are never adjusted.
func fixtureInRestrictedDACLWorker(t *testing.T) bool {
	t.Helper()
	const test = "TestWindowsControllerFoundationRetainsGrantedLaunchHandle"
	if t.Name() != test {
		t.Fatal("restricted controller worker refused an unrelated test")
	}
	api := fixtureRestrictedAPIs(t)
	if marker := os.Getenv(fixtureRestrictedWorkerEnvironment); marker != "" {
		if marker != test {
			t.Fatal("restricted controller worker lost its captured test")
		}
		token, err := syscall.OpenCurrentProcessToken()
		if err != nil {
			t.Fatal(err)
		}
		defer token.Close()
		identity, _, identityErr := readTokenIdentity(token)
		privileges, privilegeErr := fixtureTokenPrivileges(token)
		debug, lookupErr := fixtureDebugPrivilege(api)
		if identityErr != nil || privilegeErr != nil || lookupErr != nil || !identity.Primary || identity.SID == "" ||
			!identity.Elevated || !identity.Administrator {
			t.Fatal("restricted DACL worker has no verified same-user primary authority", identityErr, privilegeErr, lookupErr)
		}
		if _, present := privileges[debug]; present {
			t.Fatal("restricted DACL worker retained SeDebugPrivilege")
		}
		return true
	}
	worker := fixtureStartRestrictedDACLWorker(t, api, test)
	if err := worker.wait(25 * time.Second); err != nil {
		t.Fatal("restricted DACL worker did not join:", err, worker.output())
	}
	var exit uint32
	if err := syscall.GetExitCodeProcess(worker.process.Process, &exit); err != nil || exit != 0 {
		t.Fatalf("restricted DACL worker failed (exit=%d): %v\n%s", exit, err, worker.output())
	}
	output := worker.output()
	if !strings.Contains(output, "--- PASS: "+test+" (") || strings.Contains(output, "--- SKIP:") || strings.Contains(output, "DATA RACE") {
		t.Fatal("restricted DACL worker did not execute its actual retained-handle assertion:", output)
	}
	t.Log(output)
	return false
}

type fixtureRestrictedAPI struct {
	native                                                  *nativeAPI
	restrict, lookup                                        *syscall.Proc
	initialize, update, delete, resume, terminate, queryJob *syscall.Proc
}

func fixtureRestrictedAPIs(t *testing.T) *fixtureRestrictedAPI {
	t.Helper()
	n, err := native()
	if err != nil {
		t.Fatal(err)
	}
	api := &fixtureRestrictedAPI{native: n}
	for _, item := range []struct {
		dll    *syscall.DLL
		name   string
		target **syscall.Proc
	}{
		{n.convertSD.Dll, "CreateRestrictedToken", &api.restrict},
		{n.convertSD.Dll, "LookupPrivilegeValueW", &api.lookup},
		{n.event.Dll, "InitializeProcThreadAttributeList", &api.initialize},
		{n.event.Dll, "UpdateProcThreadAttribute", &api.update},
		{n.event.Dll, "DeleteProcThreadAttributeList", &api.delete},
		{n.event.Dll, "ResumeThread", &api.resume},
		{n.event.Dll, "TerminateJobObject", &api.terminate},
		{n.event.Dll, "QueryInformationJobObject", &api.queryJob},
	} {
		*item.target, err = item.dll.FindProc(item.name)
		if err != nil {
			t.Fatal(err)
		}
	}
	return api
}

func fixtureDebugPrivilege(api *fixtureRestrictedAPI) (fixturePrivilegeLUID, error) {
	name, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	var luid fixturePrivilegeLUID
	ok, _, callErr := api.lookup.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&luid)))
	runtime.KeepAlive(name)
	if ok == 0 {
		return luid, nativeError("fixture SeDebug privilege identity", callErr)
	}
	return luid, nil
}

func fixtureTokenPrivileges(token syscall.Token) (map[fixturePrivilegeLUID]uint32, error) {
	var size, returned uint32
	err := syscall.GetTokenInformation(token, 3 /* TokenPrivileges */, nil, 0, &size)
	if !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 65536 {
		return nil, errors.Join(err, errors.New("fixture token privilege bound is invalid"))
	}
	data := make([]byte, size)
	if err := syscall.GetTokenInformation(token, 3, &data[0], size, &returned); err != nil || returned != size {
		return nil, errors.Join(err, errors.New("fixture token privilege readback changed shape"))
	}
	count := binary.LittleEndian.Uint32(data[:4])
	if uint64(count)*12+4 != uint64(len(data)) {
		return nil, errors.New("fixture token privilege array is truncated")
	}
	result := make(map[fixturePrivilegeLUID]uint32, count)
	for offset := 4; offset < len(data); offset += 12 {
		luid := fixturePrivilegeLUID{binary.LittleEndian.Uint32(data[offset:]), int32(binary.LittleEndian.Uint32(data[offset+4:]))}
		if _, exists := result[luid]; exists {
			return nil, errors.New("fixture token repeats a privilege")
		}
		result[luid] = binary.LittleEndian.Uint32(data[offset+8:])
	}
	return result, nil
}

func fixtureSamePrimary(a, b TokenIdentity) bool {
	// A derived token has its own ModifiedID. Its actual user, logon session,
	// primary-token type, elevation and enabled administrator group stay fixed.
	return a.Primary && b.Primary && a.SID == b.SID && a.AuthenticationID == b.AuthenticationID &&
		a.SessionID == b.SessionID && a.Elevated == b.Elevated && a.Administrator == b.Administrator
}

type fixtureRestrictedWorker struct {
	api        *fixtureRestrictedAPI
	directory  string
	desktop    string
	inspect    func(syscall.ProcessInformation, *Image)
	job        syscall.Handle
	process    syscall.ProcessInformation
	image      *Image
	report     *os.File
	parent     syscall.Token
	privileges map[fixturePrivilegeLUID]uint32
}

func fixtureStartRestrictedDACLWorker(t *testing.T, api *fixtureRestrictedAPI, test string) *fixtureRestrictedWorker {
	return fixtureStartRestrictedPrimaryWorker(t, api, test, fixtureRestrictedWorkerEnvironment)
}

func fixtureStartRestrictedPrimaryWorker(t *testing.T, api *fixtureRestrictedAPI, test, marker string) *fixtureRestrictedWorker {
	t.Helper()
	directory := t.TempDir()
	worker := &fixtureRestrictedWorker{api: api, directory: directory}
	t.Cleanup(func() {
		if err := worker.close(); err != nil {
			t.Error("restricted DACL worker did not retire its exact native owners:", err)
		}
	})
	if err := syscall.OpenProcessToken(^syscall.Handle(0), syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE|syscall.TOKEN_ASSIGN_PRIMARY, &worker.parent); err != nil {
		t.Fatal(err)
	}
	parentIdentity, _, err := readTokenIdentity(worker.parent)
	if err != nil || !parentIdentity.Primary || !parentIdentity.Elevated || !parentIdentity.Administrator {
		t.Fatal("DACL fixture requires the captured elevated build user", err)
	}
	worker.privileges, err = fixtureTokenPrivileges(worker.parent)
	if err != nil {
		t.Fatal(err)
	}
	debug, err := fixtureDebugPrivilege(api)
	if err != nil {
		t.Fatal(err)
	}
	deleted := struct {
		LUID       fixturePrivilegeLUID
		Attributes uint32
	}{LUID: debug}
	if unsafe.Sizeof(deleted) != 12 {
		t.Fatal("restricted token privilege ABI changed")
	}
	var token syscall.Token
	ok, _, callErr := api.restrict.Call(uintptr(worker.parent), 0, 0, 0, 1, uintptr(unsafe.Pointer(&deleted)), 0, 0, uintptr(unsafe.Pointer(&token)))
	if token != 0 {
		defer token.Close()
	}
	if ok == 0 || token == 0 {
		t.Fatal(nativeError("same-user restricted primary token", callErr))
	}
	wanted := maps.Clone(worker.privileges)
	delete(wanted, debug)
	restrictedIdentity, _, identityErr := readTokenIdentity(token)
	restrictedPrivileges, privilegeErr := fixtureTokenPrivileges(token)
	if identityErr != nil || privilegeErr != nil || !fixtureSamePrimary(parentIdentity, restrictedIdentity) || !maps.Equal(wanted, restrictedPrivileges) {
		t.Fatal("derived primary token changed more than SeDebug privilege", identityErr, privilegeErr)
	}
	return fixtureStartPrimaryWorker(t, worker, token, test, marker, 2, func(actual syscall.Token) error {
		identity, _, identityErr := readTokenIdentity(actual)
		privileges, privilegeErr := fixtureTokenPrivileges(actual)
		if identityErr != nil || privilegeErr != nil || !fixtureSamePrimary(parentIdentity, identity) || !maps.Equal(wanted, privileges) {
			return errors.Join(identityErr, privilegeErr, errors.New("DACL worker changed its captured primary authority"))
		}
		return nil
	})
}

// Both restricted fixtures use the same actual creation-time Job and exact
// inherited handles. The caller independently validates the requested and
// actual primary tokens before this owner resumes the returned initial thread.
func fixtureStartPrimaryWorker(t *testing.T, worker *fixtureRestrictedWorker, token syscall.Token, test, marker string, maximum uint32, validate func(syscall.Token) error) *fixtureRestrictedWorker {
	t.Helper()
	if worker == nil || worker.api == nil || worker.parent == 0 || worker.directory == "" || token == 0 || maximum == 0 || maximum > 4 || validate == nil {
		t.Fatal("restricted primary worker lost its captured creation authority")
	}
	api := worker.api
	directory := worker.directory
	parentIdentity, _, err := readTokenIdentity(worker.parent)
	if err != nil || !parentIdentity.Primary {
		t.Fatal("restricted primary worker lost its retained parent token", err)
	}
	var ok uintptr
	var callErr error
	err = withDescriptor(parentIdentity.SID, func(attributes *syscall.SecurityAttributes) error {
		value, _, callErr := api.native.createJob.Call(uintptr(unsafe.Pointer(attributes)), 0)
		worker.job = syscall.Handle(value)
		if value == 0 {
			return nativeError("restricted fixture private Job", callErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	limits := jobLimits{Flags: 0x2008 /* KILL_ON_JOB_CLOSE | ACTIVE_PROCESS */, ActiveProcesses: maximum}
	if unsafe.Sizeof(limits) != 144 {
		t.Fatal("restricted fixture Job ABI changed")
	}
	ok, _, callErr = api.native.setJob.Call(uintptr(worker.job), 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		t.Fatal(nativeError("restricted fixture bounded nonbreakaway Job", callErr))
	}
	var observed jobLimits
	var returned uint32
	ok, _, callErr = api.queryJob.Call(uintptr(worker.job), 9, uintptr(unsafe.Pointer(&observed)), unsafe.Sizeof(observed), uintptr(unsafe.Pointer(&returned)))
	if ok == 0 || returned != uint32(unsafe.Sizeof(observed)) || observed.Flags != limits.Flags || observed.ActiveProcesses != maximum {
		t.Fatal(nativeError("restricted fixture Job limits readback", callErr))
	}
	writer, err := os.CreateTemp(directory, "dacl-worker-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	// Separate file objects keep parent ReadAt from changing the child's
	// inherited stdout position. Only this new private report admits writes.
	worker.report, err = os.Open(writer.Name())
	if err != nil {
		t.Fatal(err)
	}
	var output syscall.Handle
	if err := syscall.DuplicateHandle(^syscall.Handle(0), syscall.Handle(writer.Fd()), ^syscall.Handle(0), &output, 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(output)
	nul, _ := syscall.UTF16PtrFromString("NUL")
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	input, err := syscall.CreateFile(nul, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, &attributes, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(input)
	var size uintptr
	ok, _, callErr = api.initialize.Call(0, 2, 0, uintptr(unsafe.Pointer(&size)))
	if ok != 0 || !errors.Is(callErr, syscall.ERROR_INSUFFICIENT_BUFFER) || size < 8 || size > 65536 {
		t.Fatal("restricted worker attribute bound is unproved", callErr)
	}
	storage := make([]uintptr, (size+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	list := unsafe.Pointer(&storage[0])
	ok, _, callErr = api.initialize.Call(uintptr(list), 2, 0, uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		t.Fatal(nativeError("restricted worker attribute initialization", callErr))
	}
	jobs, handles := []syscall.Handle{worker.job}, []syscall.Handle{input, output}
	defer func() {
		api.delete.Call(uintptr(list))
		runtime.KeepAlive(storage)
		runtime.KeepAlive(jobs)
		runtime.KeepAlive(handles)
	}()
	for _, attribute := range []struct {
		kind   uintptr
		values []syscall.Handle
	}{{0x0002000d /* JOB_LIST */, jobs}, {0x00020002 /* HANDLE_LIST */, handles}} {
		ok, _, callErr = api.update.Call(uintptr(list), 0, attribute.kind, uintptr(unsafe.Pointer(&attribute.values[0])), uintptr(len(attribute.values))*unsafe.Sizeof(input), 0, 0)
		if ok == 0 {
			t.Fatal(nativeError("restricted worker exact Job/handle attribute", callErr))
		}
	}
	worker.image, err = PinCurrentImage()
	if err != nil {
		t.Fatal(err)
	}
	// The full native runner may execute through a short TEMP component. Use
	// the held file's normalized DOS spelling for this suspended candidate,
	// rather than the module loader's original short spelling. The unchanged
	// native-name and file-object proof below still precedes all child code.
	// A DOS spelling is not elevated-launch authority: this fixture retains
	// the actual CreateProcessAsUser initial thread before any execution.
	var executable string
	func() {
		worker.image.mu.Lock()
		defer worker.image.mu.Unlock()
		buffer := make([]uint16, 32768)
		length, _, callErr := api.native.finalPath.Call(uintptr(worker.image.handles[len(worker.image.handles)-1]),
			uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0 /* FILE_NAME_NORMALIZED | VOLUME_NAME_DOS */)
		if length == 0 || length >= uintptr(len(buffer)) {
			t.Fatal(nativeError("restricted worker retained normalized executable", callErr))
		}
		executable, err = localExecutablePath(strings.TrimPrefix(syscall.UTF16ToString(buffer[:length]), `\\?\`))
		runtime.KeepAlive(buffer)
		if err != nil {
			t.Fatal("restricted worker retained file has no local normalized executable", err)
		}
	}()
	application, _ := syscall.UTF16PtrFromString(executable)
	command, _ := syscall.UTF16FromString(syscall.EscapeArg(executable) + " -test.run=^" + test + "$ -test.count=1 -test.timeout=20s -test.v")
	var environment []uint16
	for _, entry := range []string{marker + "=" + test, "SystemRoot=" + filepath.Dir(api.native.systemDirectory), "TEMP=" + directory, "TMP=" + directory, "GORACE=atexit_sleep_ms=0"} {
		encoded, err := syscall.UTF16FromString(entry)
		if err != nil {
			t.Fatal(err)
		}
		environment = append(environment, encoded...)
	}
	environment = append(environment, 0)
	startup := struct {
		Info       syscall.StartupInfo
		Attributes unsafe.Pointer
	}{Attributes: list}
	startup.Info.Cb = uint32(unsafe.Sizeof(startup))
	startup.Info.Flags = syscall.STARTF_USESTDHANDLES
	startup.Info.StdInput, startup.Info.StdOutput, startup.Info.StdErr = input, output, output
	if worker.desktop != "" {
		startup.Info.Desktop, err = syscall.UTF16PtrFromString(worker.desktop)
		if err != nil {
			t.Fatal(err)
		}
	}
	// The restricted-caller exception is the documented AsUser boundary. This
	// fixture never adjusts or grants parent privileges; the post-call readback
	// also checks that the API restored any temporary existing privilege use.
	// No post-create Job assignment is accepted. The non-inherited Job kills
	// both worker and child on owner loss.
	err = syscall.CreateProcessAsUser(token, application, &command[0], nil, nil, true,
		0x08080404, /* NO_WINDOW | EXTENDED_STARTUPINFO | UNICODE_ENVIRONMENT | SUSPENDED */
		&environment[0], nil, &startup.Info, &worker.process)
	runtime.KeepAlive(application)
	runtime.KeepAlive(command)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(startup)
	if err != nil || worker.process.Process == 0 || worker.process.Thread == 0 {
		t.Fatal("restricted DACL worker was not created in its exact Job", err)
	}
	var member uint32
	ok, _, callErr = api.native.inJob.Call(uintptr(worker.process.Process), uintptr(worker.job), uintptr(unsafe.Pointer(&member)))
	if ok == 0 || member != 1 {
		t.Fatal(nativeError("restricted worker creation-time Job readback", callErr))
	}
	var actual syscall.Token
	if err := syscall.OpenProcessToken(worker.process.Process, syscall.TOKEN_QUERY, &actual); err != nil {
		t.Fatal(err)
	}
	validationErr := validate(actual)
	closeErr := actual.Close()
	if validationErr != nil || closeErr != nil {
		t.Fatal("suspended worker did not retain its actual restricted primary token", validationErr, closeErr)
	}
	var duplicate syscall.Handle
	if err := syscall.DuplicateHandle(^syscall.Handle(0), worker.process.Process, ^syscall.Handle(0), &duplicate, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	proof, err := adoptProcess(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	proofErr := verifySuspendedShellImage(api.native, proof, worker.image)
	proofCloseErr := proof.Close()
	if proofErr != nil || proofCloseErr != nil {
		t.Fatal("restricted worker lost its exact captured image before resume", proofErr, proofCloseErr)
	}
	if worker.inspect != nil {
		worker.inspect(worker.process, worker.image)
	}
	parentAfter, err := fixtureTokenPrivileges(worker.parent)
	if err != nil || !maps.Equal(worker.privileges, parentAfter) {
		t.Fatal("restricted worker creation changed its parent's privileges", err)
	}
	resumed, _, callErr := api.resume.Call(uintptr(worker.process.Thread))
	if resumed != 1 {
		t.Fatal(nativeError("restricted DACL worker resume", callErr))
	}
	return worker
}

func (worker *fixtureRestrictedWorker) output() string {
	if worker.report == nil {
		return ""
	}
	buffer := make([]byte, (1<<20)+1)
	count, err := worker.report.ReadAt(buffer, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "restricted worker output read failed: " + err.Error()
	}
	if count > 1<<20 {
		return "restricted worker output exceeded its captured bound"
	}
	return string(buffer[:count])
}

func (worker *fixtureRestrictedWorker) wait(timeout time.Duration) error {
	state, err := syscall.WaitForSingleObject(worker.process.Process, uint32(timeout/time.Millisecond))
	if err != nil || state != syscall.WAIT_OBJECT_0 {
		return errors.Join(err, errors.New("restricted worker process is not joined"))
	}
	return nil
}

func (worker *fixtureRestrictedWorker) close() error {
	var result error
	if worker.job != 0 {
		ok, _, callErr := worker.api.terminate.Call(uintptr(worker.job), 125)
		if ok == 0 {
			result = nativeError("restricted worker exact Job termination", callErr)
		}
	}
	if worker.process.Process != 0 {
		if err := worker.wait(5 * time.Second); err != nil {
			// Even a partially returned native process remains owned by this
			// exact handle. Never use a discovered PID as cleanup authority.
			result = errors.Join(result, syscall.TerminateProcess(worker.process.Process, 125))
			if err := worker.wait(5 * time.Second); err != nil {
				return errors.Join(result, err)
			}
		}
	}
	if worker.job != 0 {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var accounting struct {
				TotalUser, TotalKernel, PeriodUser, PeriodKernel int64
				PageFaults, Total, Active, Terminated            uint32
			}
			var returned uint32
			ok, _, callErr := worker.api.queryJob.Call(uintptr(worker.job), 1, uintptr(unsafe.Pointer(&accounting)), unsafe.Sizeof(accounting), uintptr(unsafe.Pointer(&returned)))
			if ok == 0 || returned != uint32(unsafe.Sizeof(accounting)) {
				return errors.Join(result, nativeError("restricted worker Job drain readback", callErr))
			}
			if accounting.Active == 0 {
				break
			}
			if time.Now().After(deadline) {
				return errors.Join(result, errors.New("restricted worker Job retains an unjoined descendant"))
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if worker.parent != 0 {
		actual, err := fixtureTokenPrivileges(worker.parent)
		if err != nil || !maps.Equal(worker.privileges, actual) {
			result = errors.Join(result, err, errors.New("restricted DACL test changed the parent privilege set"))
		}
		result = errors.Join(result, worker.parent.Close())
		worker.parent = 0
	}
	for _, owner := range []struct {
		handle *syscall.Handle
		name   string
	}{{&worker.process.Thread, "thread"}, {&worker.process.Process, "process"}, {&worker.job, "Job"}} {
		if *owner.handle != 0 {
			if err := syscall.CloseHandle(*owner.handle); err != nil {
				result = errors.Join(result, fmt.Errorf("restricted worker %s close: %w", owner.name, err))
			} else {
				*owner.handle = 0
			}
		}
	}
	if worker.report != nil {
		result = errors.Join(result, worker.report.Close())
		worker.report = nil
	}
	return errors.Join(result, worker.image.Close())
}
