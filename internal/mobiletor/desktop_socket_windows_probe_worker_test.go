//go:build windows && routervpn_windows_wfp

package mobiletor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const desktopWindowsProbeWorkerEnvironment = "ROUTERVPN_WFP_PROBE_PARENT_WORKER"

var desktopWindowsProbeWorkerJob syscall.Handle

// The complete ordinary-user probe fixture runs in a separate worker. Its
// outer Job is attached by CreateProcessW's explicit Job-list attribute. The
// worker owns a second, non-breakaway kill-on-close Job before acquiring any
// fresh account/token. A basic CreateProcessWithTokenW child must independently
// prove membership of this exact inner Job before ResumeThread. No post-create
// assignment is accepted as a substitute for that creation-time ownership.
func desktopWindowsProbeInOwnedWorker(t *testing.T) bool {
	t.Helper()
	if marker := os.Getenv(desktopWindowsProbeWorkerEnvironment); marker != "" {
		if marker != t.Name() || strings.Contains(marker, "/") {
			t.Fatal("probe worker did not retain its exact parent test")
		}
		api := desktopWindowsProbeWorkerAPI(t)
		job, err := desktopWindowsProbeNewJob(api, 2)
		if err != nil {
			t.Fatal(err)
		}
		assign, err := api.createJob.Dll.FindProc("AssignProcessToJobObject")
		if err != nil {
			_ = syscall.CloseHandle(job)
			t.Fatal(err)
		}
		ok, _, callErr := assign.Call(uintptr(job), ^uintptr(0))
		if ok == 0 {
			_ = syscall.CloseHandle(job)
			t.Fatal(desktopWindowsCallFailure("owned probe worker self Job", callErr))
		}
		// Closing this non-inherited handle terminates this worker itself.
		// Retain it until actual process exit, including any subsequent failure.
		desktopWindowsProbeWorkerJob = job
		var member uint32
		ok, _, callErr = api.inJob.Call(^uintptr(0), uintptr(job), uintptr(unsafe.Pointer(&member)))
		if ok == 0 || member != 1 {
			t.Fatal(desktopWindowsCallFailure("owned probe worker Job readback", callErr))
		}
		return true
	}
	worker := desktopWindowsProbeStartWorker(t, t.Name())
	if err := worker.wait(45 * time.Second); err != nil {
		t.Fatal("owned probe worker did not finish:", err, worker.output())
	}
	var exit uint32
	if err := syscall.GetExitCodeProcess(worker.process.Process, &exit); err != nil || exit != 0 {
		t.Fatalf("owned probe worker failed (exit=%d): %v\n%s", exit, err, worker.output())
	}
	// Preserve the real child test output, including each protected-object case
	// and the exact production-mutant failure witness. This is not a synthesized
	// pass marker or a thread impersonation stand-in for an ordinary process.
	t.Log(worker.output())
	return false
}

func desktopWindowsProbeWorkerAPI(t *testing.T) *desktopWindowsProbeProcessAPI {
	t.Helper()
	native, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		t.Fatal(err)
	}
	api, err := desktopWindowsProbeProcessAPIs(&DesktopWindowsSocketIdentity{api: native})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := api.user.Release(); err != nil {
			t.Error("probe worker system DLL did not retire", err)
		}
	})
	return api
}

func desktopWindowsProbeNewJob(api *desktopWindowsProbeProcessAPI, count uint32) (syscall.Handle, error) {
	value, _, callErr := api.createJob.Call(0, 0)
	if value == 0 {
		return 0, desktopWindowsCallFailure("probe worker Job creation", callErr)
	}
	job := syscall.Handle(value)
	limits := desktopWindowsProbeJobLimits{Flags: 0x2008, ActiveProcesses: count}
	if unsafe.Sizeof(limits) != 144 {
		_ = syscall.CloseHandle(job)
		return 0, errors.New("probe worker Job ABI changed")
	}
	ok, _, callErr := api.setJob.Call(value, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		return 0, errors.Join(desktopWindowsCallFailure("probe worker Job limits", callErr), syscall.CloseHandle(job))
	}
	return job, nil
}

type desktopWindowsProbeWorker struct {
	api       *desktopWindowsProbeProcessAPI
	job       syscall.Handle
	process   syscall.ProcessInformation
	report    *os.File
	terminate *syscall.Proc
	query     *syscall.Proc
}

func desktopWindowsProbeStartWorker(t *testing.T, test string) *desktopWindowsProbeWorker {
	t.Helper()
	if test != "TestDesktopSocketWindowsWFPProbeOrdinaryAbsence" && test != "TestDesktopSocketWindowsWFPProbeOrdinaryProtectedObjects" && test != "TestDesktopSocketWindowsWFPProbeWorkerLifetime" {
		t.Fatal("probe worker refused an unrelated test process")
	}
	api := desktopWindowsProbeWorkerAPI(t)
	directory := t.TempDir()
	worker := &desktopWindowsProbeWorker{api: api}
	var err error
	worker.terminate, err = api.createJob.Dll.FindProc("TerminateJobObject")
	if err == nil {
		worker.query, err = api.createJob.Dll.FindProc("QueryInformationJobObject")
	}
	if err != nil {
		t.Fatal(err)
	}
	worker.job, err = desktopWindowsProbeNewJob(api, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := worker.close(); err != nil {
			t.Error("owned probe worker did not fully retire", err)
		}
	})
	worker.report, err = os.CreateTemp(directory, "probe-worker-output-")
	if err != nil {
		t.Fatal(err)
	}
	writer := worker.report
	defer writer.Close()
	reader, err := os.Open(writer.Name())
	if err != nil {
		t.Fatal(err)
	}
	// DuplicateHandle shares its file-position object. Keep the parent's
	// ReadAt on a separately opened file object so observing partial output
	// cannot seek underneath a still-running child's stdout writes.
	worker.report = reader
	var inheritedOutput syscall.Handle
	if err := syscall.DuplicateHandle(^syscall.Handle(0), syscall.Handle(writer.Fd()), ^syscall.Handle(0), &inheritedOutput, 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(inheritedOutput)
	nul, _ := syscall.UTF16PtrFromString("NUL")
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	input, err := syscall.CreateFile(nul, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, &attributes, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(input)
	var size uintptr
	ok, _, callErr := api.initializeAttributes.Call(0, 2, 0, uintptr(unsafe.Pointer(&size)))
	if ok != 0 || !errors.Is(callErr, syscall.ERROR_INSUFFICIENT_BUFFER) || size < 8 || size > 65536 {
		t.Fatal("probe worker attribute size is unproved", callErr)
	}
	storage := make([]uintptr, (size+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	list := unsafe.Pointer(&storage[0])
	ok, _, callErr = api.initializeAttributes.Call(uintptr(list), 2, 0, uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		t.Fatal(desktopWindowsCallFailure("probe worker attribute initialization", callErr))
	}
	jobs := []syscall.Handle{worker.job}
	handles := []syscall.Handle{input, inheritedOutput}
	defer func() {
		api.deleteAttributes.Call(uintptr(list))
		runtime.KeepAlive(storage)
		runtime.KeepAlive(jobs)
		runtime.KeepAlive(handles)
	}()
	for _, attribute := range []struct {
		kind   uintptr
		values []syscall.Handle
	}{{0x0002000d, jobs}, {0x00020002, handles}} {
		ok, _, callErr = api.updateAttributes.Call(uintptr(list), 0, attribute.kind, uintptr(unsafe.Pointer(&attribute.values[0])), uintptr(len(attribute.values))*unsafe.Sizeof(input), 0, 0)
		if ok == 0 {
			t.Fatal(desktopWindowsCallFailure("probe worker exact Job/handle attribute", callErr))
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	application, _ := syscall.UTF16PtrFromString(executable)
	command, _ := syscall.UTF16FromString(syscall.EscapeArg(executable) + " -test.run=^" + test + "$ -test.count=1 -test.timeout=40s -test.v")
	var environment []uint16
	for _, entry := range append([]string{desktopWindowsProbeWorkerEnvironment + "=" + test}, "SystemRoot="+os.Getenv("SystemRoot"), "TEMP="+os.TempDir(), "TMP="+os.TempDir()) {
		encoded, err := syscall.UTF16FromString(entry)
		if err != nil {
			t.Fatal(err)
		}
		environment = append(environment, encoded...)
	}
	environment = append(environment, 0)
	startup := desktopWindowsProbeStartup{Attributes: list}
	startup.Info.Cb = uint32(unsafe.Sizeof(startup))
	startup.Info.Flags = syscall.STARTF_USESTDHANDLES
	startup.Info.StdInput, startup.Info.StdOutput, startup.Info.StdErr = input, inheritedOutput, inheritedOutput
	// Only stdout/stderr and NUL are inherited. In particular, neither the
	// outer Job nor any account token is inherited, so parent death closes the
	// Job's last handle even if the worker is suspended during startup.
	err = syscall.CreateProcess(application, &command[0], nil, nil, true, 0x08080404,
		&environment[0], nil, &startup.Info, &worker.process)
	runtime.KeepAlive(application)
	runtime.KeepAlive(command)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(startup)
	if err != nil || worker.process.Process == 0 || worker.process.Thread == 0 {
		t.Fatal("probe worker was not atomically created in its owned Job", err)
	}
	var member uint32
	ok, _, callErr = api.inJob.Call(uintptr(worker.process.Process), uintptr(worker.job), uintptr(unsafe.Pointer(&member)))
	if ok == 0 || member != 1 {
		t.Fatal(desktopWindowsCallFailure("probe worker creation-time Job readback", callErr))
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(worker.process.Process, syscall.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	sid, elevated, administrator, identityErr := desktopWindowsProbeProcessToken(token)
	closeErr := token.Close()
	parent, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	parentSID, _, parentErr := desktopWindowsTokenIdentity(parent)
	parentClose := parent.Close()
	if identityErr != nil || closeErr != nil || parentErr != nil || parentClose != nil || !elevated || !administrator || string(sid) != string(parentSID) {
		t.Fatal("owned probe worker replaced its captured administrator identity", identityErr, closeErr, parentErr, parentClose)
	}
	resumed, _, callErr := api.resume.Call(uintptr(worker.process.Thread))
	if resumed != 1 {
		t.Fatal(desktopWindowsCallFailure("owned probe worker resume", callErr))
	}
	return worker
}

func (worker *desktopWindowsProbeWorker) output() string {
	if worker.report == nil {
		return ""
	}
	buffer := make([]byte, 1<<20+1)
	count, err := worker.report.ReadAt(buffer, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "probe worker output read failed: " + err.Error()
	}
	if count > 1<<20 {
		return "probe worker output exceeded its captured bound"
	}
	return string(buffer[:count])
}

func (worker *desktopWindowsProbeWorker) wait(timeout time.Duration) error {
	state, err := syscall.WaitForSingleObject(worker.process.Process, uint32(timeout/time.Millisecond))
	if err != nil || state != syscall.WAIT_OBJECT_0 {
		return errors.Join(err, errors.New("owned probe worker did not join"))
	}
	return nil
}

func (worker *desktopWindowsProbeWorker) close() error {
	var result error
	if worker.job != 0 {
		// This exact unnamed Job contains only the owned worker and any child
		// it actually inherited. Explicitly drain failures before dropping the
		// last owner handle; never terminate a PID discovered from another app.
		ok, _, callErr := worker.terminate.Call(uintptr(worker.job), 125)
		if ok == 0 {
			result = desktopWindowsCallFailure("owned probe worker Job termination", callErr)
		}
	}
	if worker.process.Process != 0 {
		if state, err := syscall.WaitForSingleObject(worker.process.Process, 5000); err != nil || state != syscall.WAIT_OBJECT_0 {
			// A partially returned native process still belongs to this exact
			// handle even if creation-time membership could not be proved.
			result = errors.Join(result, syscall.TerminateProcess(worker.process.Process, 125), worker.wait(5*time.Second))
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
			ok, _, callErr := worker.query.Call(uintptr(worker.job), 1, uintptr(unsafe.Pointer(&accounting)), unsafe.Sizeof(accounting), uintptr(unsafe.Pointer(&returned)))
			if ok == 0 || returned != uint32(unsafe.Sizeof(accounting)) {
				result = errors.Join(result, desktopWindowsCallFailure("probe worker Job drain readback", callErr))
				break
			}
			if accounting.Active == 0 {
				break
			}
			if time.Now().After(deadline) {
				result = errors.Join(result, errors.New("owned probe Job retained an unjoined process"))
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		result = errors.Join(result, syscall.CloseHandle(worker.job))
		worker.job = 0
	}
	for _, handle := range []*syscall.Handle{&worker.process.Thread, &worker.process.Process} {
		if *handle != 0 {
			result = errors.Join(result, syscall.CloseHandle(*handle))
			*handle = 0
		}
	}
	if worker.report != nil {
		result = errors.Join(result, worker.report.Close())
		worker.report = nil
	}
	return result
}

func TestDesktopSocketWindowsWFPProbeWorkerLifetime(t *testing.T) {
	if os.Getenv(desktopWindowsProbeWorkerEnvironment) != "" {
		if !desktopWindowsProbeInOwnedWorker(t) {
			t.Fatal("probe worker lifetime branch was not acquired")
		}
		process := desktopWindowsProbeTestProcess(t)
		process.hold = true
		_, err := process.run(desktopWindowsProbeTestScope(t))
		t.Fatal("held ordinary probe child returned before its worker was retired", err)
	}
	for _, mode := range []string{"worker-death", "outer-owner-close"} {
		t.Run(mode, func(t *testing.T) {
			worker := desktopWindowsProbeStartWorker(t, "TestDesktopSocketWindowsWFPProbeWorkerLifetime")
			var child syscall.Handle
			deadline := time.Now().Add(15 * time.Second)
			for child == 0 {
				for _, line := range strings.Split(worker.output(), "\n") {
					const prefix = "PROBE_OWNED_CHILD "
					if !strings.HasPrefix(line, prefix) {
						continue
					}
					pid, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, prefix)), 10, 32)
					if err != nil || pid == 0 {
						t.Fatal("probe worker returned an invalid public child identity")
					}
					child, err = syscall.OpenProcess(0x00100000|0x1000|1, false, uint32(pid))
					if err != nil {
						t.Fatal(err)
					}
					break
				}
				if child == 0 && time.Now().After(deadline) {
					t.Fatal("probe worker never proved its held ordinary child:", worker.output())
				}
				if child == 0 {
					if state, err := syscall.WaitForSingleObject(worker.process.Process, 0); err != nil || state == syscall.WAIT_OBJECT_0 {
						t.Fatal("probe worker exited before proving its held ordinary child:", err, worker.output())
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			defer func() {
				// Negative controls intentionally break kernel owner-death cleanup.
				// Retain this exact owned handle so their failure never strands the
				// deliberately held child or kills a later reused PID.
				if state, err := syscall.WaitForSingleObject(child, 0); err != nil || state != syscall.WAIT_OBJECT_0 {
					if err := syscall.TerminateProcess(child, 125); err != nil {
						t.Error("held ordinary fixture fallback did not terminate", err)
					}
					if state, err := syscall.WaitForSingleObject(child, 5000); err != nil || state != syscall.WAIT_OBJECT_0 {
						t.Error("held ordinary fixture fallback did not join", err)
					}
				}
				_ = syscall.CloseHandle(child)
			}()
			var member uint32
			ok, _, callErr := worker.api.inJob.Call(uintptr(child), uintptr(worker.job), uintptr(unsafe.Pointer(&member)))
			if ok == 0 || member != 1 {
				t.Fatal("ordinary child did not inherit both retained Job owners", callErr)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			control := exec.Command(executable, "-test.run=^TestDesktopWindowsProbeLifetimeControl$", "-test.count=1", "-test.timeout=30s")
			control.Env = append(os.Environ(), "ROUTERVPN_WFP_LIFETIME_CONTROL=1")
			if err := control.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = control.Process.Kill(); _ = control.Wait() }()
			controlHandle, err := syscall.OpenProcess(0x00100000|0x1000, false, uint32(control.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.CloseHandle(controlHandle)
			member = 1
			ok, _, callErr = worker.api.inJob.Call(uintptr(controlHandle), uintptr(worker.job), uintptr(unsafe.Pointer(&member)))
			if ok == 0 || member != 0 {
				t.Fatal("lifetime negative control accidentally belongs to the worker Job", callErr)
			}
			if mode == "worker-death" {
				if err := syscall.TerminateProcess(worker.process.Process, 125); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := syscall.CloseHandle(worker.job); err != nil {
					t.Fatal(err)
				}
				worker.job = 0
			}
			if err := worker.wait(5 * time.Second); err != nil {
				t.Fatal(err)
			}
			if state, err := syscall.WaitForSingleObject(child, 3000); err != nil || state != syscall.WAIT_OBJECT_0 {
				t.Fatal("probe worker death left its ordinary child alive", err)
			}
			if state, err := syscall.WaitForSingleObject(controlHandle, 0); err != nil || state != syscall.WAIT_TIMEOUT {
				t.Fatal("probe Job retirement affected the unrelated process control", err)
			}
		})
	}
}

func TestDesktopWindowsProbeLifetimeControl(t *testing.T) {
	if os.Getenv("ROUTERVPN_WFP_LIFETIME_CONTROL") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		<-ctx.Done()
	}
}
