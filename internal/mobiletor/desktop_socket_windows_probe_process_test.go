//go:build windows && routervpn_windows_wfp

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// This fixture never impersonates one thread while an async probe runs on
// another. The child has the fresh disabled account as its actual primary
// process token. Only its new executable, result file and private desktop admit
// that exact SID; no WFP, engine, sublayer, filter, existing account or unrelated
// ACL changes. An explicit private desktop avoids any reliance on access to the
// inherited window station/desktop. The basic token process must inherit its
// dedicated worker's exact retained Job at creation, independently checked
// before ResumeThread. No new rights or ambient privileges are granted.
type desktopWindowsProbeProcess struct {
	identity                       *DesktopWindowsSocketIdentity
	primary                        syscall.Token
	directory, executable, sidHash string
	desktopName                    string
	station, desktop               syscall.Handle
	api                            *desktopWindowsProbeProcessAPI
	hold                           bool
}

type desktopWindowsProbeProcessAPI struct {
	duplicate, create, fileSecurity         *syscall.Proc
	createJob, setJob, inJob, resume        *syscall.Proc
	initializeAttributes, updateAttributes  *syscall.Proc
	deleteAttributes, currentThread         *syscall.Proc
	createStation, getStation, setStation   *syscall.Proc
	closeStation, createDesktop, getDesktop *syscall.Proc
	setDesktop, closeDesktop                *syscall.Proc
	user                                    *syscall.DLL
}

var desktopWindowsProbeDesktopGate sync.Mutex

type desktopWindowsProbeStartup struct {
	Info       syscall.StartupInfo
	Attributes unsafe.Pointer
}

type desktopWindowsProbeJobLimits struct {
	ProcessTime, JobTime                                       int64
	Flags                                                      uint32
	MinimumWorkingSet, MaximumWorkingSet                       uintptr
	ActiveProcesses                                            uint32
	Affinity                                                   uintptr
	Priority, Scheduling                                       uint32
	IO                                                         [6]uint64
	ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
}

type desktopWindowsProbeReply struct {
	SIDHash       string    `json:"sid_sha256"`
	PID           uint32    `json:"pid"`
	Primary       bool      `json:"primary"`
	Elevated      bool      `json:"elevated"`
	Administrator bool      `json:"administrator"`
	Lookups       [3]uint32 `json:"lookups"`
	Absent        bool      `json:"absent"`
	ProbeError    string    `json:"probe_error,omitempty"`
	SetupError    string    `json:"setup_error,omitempty"`
}

func desktopWindowsProbeProcessToken(token syscall.Token) ([]byte, bool, bool, error) {
	sid, statistics, err := desktopWindowsTokenIdentity(token)
	if err != nil || statistics.TokenType != 1 {
		return nil, false, false, errors.Join(err, errors.New("probe child lacks an actual primary token"))
	}
	var elevated, returned uint32
	if err := syscall.GetTokenInformation(token, 20, (*byte)(unsafe.Pointer(&elevated)), 4, &returned); err != nil || returned != 4 || elevated > 1 {
		return nil, false, false, errors.Join(err, errors.New("probe child elevation is unproved"))
	}
	var size uint32
	err = syscall.GetTokenInformation(token, 2, nil, 0, &size)
	if !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) || size < 8 || size > 65536 {
		return nil, false, false, errors.Join(err, errors.New("probe child token groups are unproved"))
	}
	groups := make([]byte, size)
	if err := syscall.GetTokenInformation(token, 2, &groups[0], size, &returned); err != nil || returned != size {
		return nil, false, false, errors.Join(err, errors.New("probe child token groups changed shape"))
	}
	type nativeGroup struct {
		SID        *syscall.SID
		Attributes uint32
	}
	count := *(*uint32)(unsafe.Pointer(&groups[0]))
	if count == 0 || uint64(count)*uint64(unsafe.Sizeof(nativeGroup{}))+8 > uint64(len(groups)) {
		return nil, false, false, errors.New("probe child token group array is truncated")
	}
	administrator := false
	for _, group := range unsafe.Slice((*nativeGroup)(unsafe.Pointer(&groups[8])), int(count)) {
		if group.SID == nil {
			return nil, false, false, errors.New("probe child token group has no SID")
		}
		value, err := group.SID.String()
		if err != nil {
			return nil, false, false, err
		}
		if value == "S-1-5-32-544" && group.Attributes&4 != 0 && group.Attributes&0x10 == 0 {
			administrator = true
		}
	}
	runtime.KeepAlive(groups)
	return sid, elevated != 0, administrator, nil
}

func desktopWindowsProbeProcessAPIs(identity *DesktopWindowsSocketIdentity) (*desktopWindowsProbeProcessAPI, error) {
	api := new(desktopWindowsProbeProcessAPI)
	directory := filepath.Dir(identity.api.processImage.Dll.Name)
	if !filepath.IsAbs(directory) {
		return nil, errors.New("probe user32 requires the captured system directory")
	}
	var err error
	api.user, err = syscall.LoadDLL(filepath.Join(directory, "user32.dll"))
	if err != nil {
		return nil, err
	}
	for _, item := range []struct {
		dll    *syscall.DLL
		name   string
		target **syscall.Proc
	}{
		{identity.api.logon.Dll, "DuplicateTokenEx", &api.duplicate},
		{identity.api.logon.Dll, "CreateProcessWithTokenW", &api.create},
		{identity.api.logon.Dll, "SetFileSecurityW", &api.fileSecurity},
		{identity.api.processImage.Dll, "CreateJobObjectW", &api.createJob},
		{identity.api.processImage.Dll, "SetInformationJobObject", &api.setJob},
		{identity.api.processImage.Dll, "IsProcessInJob", &api.inJob},
		{identity.api.processImage.Dll, "ResumeThread", &api.resume},
		{identity.api.processImage.Dll, "InitializeProcThreadAttributeList", &api.initializeAttributes},
		{identity.api.processImage.Dll, "UpdateProcThreadAttribute", &api.updateAttributes},
		{identity.api.processImage.Dll, "DeleteProcThreadAttributeList", &api.deleteAttributes},
		{identity.api.processImage.Dll, "GetCurrentThreadId", &api.currentThread},
		{api.user, "CreateWindowStationW", &api.createStation},
		{api.user, "GetProcessWindowStation", &api.getStation},
		{api.user, "SetProcessWindowStation", &api.setStation},
		{api.user, "CloseWindowStation", &api.closeStation},
		{api.user, "CreateDesktopW", &api.createDesktop},
		{api.user, "GetThreadDesktop", &api.getDesktop},
		{api.user, "SetThreadDesktop", &api.setDesktop},
		{api.user, "CloseDesktop", &api.closeDesktop},
	} {
		proc, err := item.dll.FindProc(item.name)
		if err != nil {
			_ = api.user.Release()
			return nil, err
		}
		*item.target = proc
	}
	return api, nil
}

func desktopWindowsProbeWithDescriptor(sid, access string, apply func(unsafe.Pointer) error) error {
	wfp, err := desktopWFPLoad()
	if err != nil {
		return err
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;" + access + ";;;" + sid + ")")
	if err != nil {
		return err
	}
	var descriptor unsafe.Pointer
	var size uint32
	ok, _, callErr := wfp.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	if descriptor != nil {
		defer wfp.freeLocal.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil || size < 20 {
		return desktopWindowsCallFailure("private probe fixture descriptor", callErr)
	}
	err = apply(descriptor)
	runtime.KeepAlive(sddl)
	return err
}

func (f *desktopWindowsProbeProcess) allowOwnedFile(path, sid, access string) error {
	if filepath.Dir(path) != f.directory && path != f.directory {
		return errors.New("probe fixture refused an unrelated filesystem ACL")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("probe fixture ACL requires its real owned inode"))
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return desktopWindowsProbeWithDescriptor(sid, access, func(descriptor unsafe.Pointer) error {
		ok, _, callErr := f.api.fileSecurity.Call(uintptr(unsafe.Pointer(name)), 0x80000004 /* protected DACL only */, uintptr(descriptor))
		runtime.KeepAlive(name)
		if ok == 0 {
			return desktopWindowsCallFailure("private probe fixture ACL", callErr)
		}
		return nil
	})
}

func (f *desktopWindowsProbeProcess) prepareDesktop(principal string) error {
	// These sequential console fixtures create no windows or hooks. Serialize
	// the brief process-wide association, restore it before child creation, and
	// never return an unverified desktop-bearing thread to Go's thread pool.
	desktopWindowsProbeDesktopGate.Lock()
	defer desktopWindowsProbeDesktopGate.Unlock()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		restored := false
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		result := func() (resultErr error) {
			station, _, callErr := f.api.getStation.Call()
			if station == 0 {
				restored = true
				return desktopWindowsCallFailure("capture probe process station", callErr)
			}
			thread, _, _ := f.api.currentThread.Call()
			desktop, _, callErr := f.api.getDesktop.Call(thread)
			if desktop == 0 {
				restored = true
				return desktopWindowsCallFailure("capture probe thread desktop", callErr)
			}
			defer func() {
				stationOK, _, stationErr := f.api.setStation.Call(station)
				desktopOK, _, desktopErr := f.api.setDesktop.Call(desktop)
				actualStation, _, _ := f.api.getStation.Call()
				actualDesktop, _, _ := f.api.getDesktop.Call(thread)
				restored = stationOK != 0 && desktopOK != 0 && actualStation == station && actualDesktop == desktop
				if !restored {
					resultErr = errors.Join(resultErr, stationErr, desktopErr, errors.New("probe did not restore its process station and thread desktop"))
				}
			}()
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return err
			}
			stationName := "RouterVPN-Probe-" + hex.EncodeToString(nonce[:])
			stationUTF16, _ := syscall.UTF16PtrFromString(stationName)
			desktopUTF16, _ := syscall.UTF16PtrFromString("Probe")
			return desktopWindowsProbeWithDescriptor(principal, "GA", func(descriptor unsafe.Pointer) error {
				attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
				value, _, callErr := f.api.createStation.Call(uintptr(unsafe.Pointer(stationUTF16)), 1 /* CWF_CREATE_ONLY */, 0x10000000 /* GENERIC_ALL */, uintptr(unsafe.Pointer(&attributes)))
				if value == 0 {
					return desktopWindowsCallFailure("private probe window station creation", callErr)
				}
				f.station = syscall.Handle(value)
				if ok, _, callErr := f.api.setStation.Call(value); ok == 0 {
					return desktopWindowsCallFailure("private probe window station association", callErr)
				}
				value, _, callErr = f.api.createDesktop.Call(uintptr(unsafe.Pointer(desktopUTF16)), 0, 0, 0, 0x10000000 /* GENERIC_ALL */, uintptr(unsafe.Pointer(&attributes)))
				if value == 0 {
					return desktopWindowsCallFailure("private probe desktop creation", callErr)
				}
				f.desktop = syscall.Handle(value)
				f.desktopName = stationName + "\\Probe"
				runtime.KeepAlive(stationUTF16)
				runtime.KeepAlive(desktopUTF16)
				return nil
			})
		}()
		done <- result
	}()
	return <-done
}

func desktopWindowsProbeTestProcess(t *testing.T) *desktopWindowsProbeProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	p, err := NewDesktopWindowsSocketIdentity(ctx, desktopWindowsWFPTestCapture(t))
	if p != nil {
		t.Cleanup(func() {
			defer cancel()
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := p.Close(cleanup); err != nil {
				t.Error("probe identity did not retire after its actual children joined", err)
			}
		})
	} else {
		t.Cleanup(cancel)
	}
	if err != nil {
		t.Fatal("fresh disabled probe identity", err)
	}
	f := &desktopWindowsProbeProcess{identity: p, directory: t.TempDir()}
	f.api, err = desktopWindowsProbeProcessAPIs(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.api.user.Release(); err != nil {
			t.Error("probe user32 reference did not close", err)
		}
	})
	t.Cleanup(func() {
		for _, owned := range []struct {
			handle syscall.Handle
			close  *syscall.Proc
			name   string
		}{{f.desktop, f.api.closeDesktop, "desktop"}, {f.station, f.api.closeStation, "window station"}} {
			if owned.handle != 0 {
				if ok, _, callErr := owned.close.Call(uintptr(owned.handle)); ok == 0 {
					t.Error("owned probe "+owned.name+" did not close after child join", callErr)
				}
			}
		}
	})
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := p.call(cleanup, true, func() error {
			if f.primary == 0 {
				return nil
			}
			err := f.primary.Close()
			if err == nil {
				f.primary = 0
			}
			return err
		}); err != nil {
			t.Error("probe primary token did not join and close", err)
		}
	})
	if err := p.call(ctx, false, func() error {
		ok, _, callErr := f.api.duplicate.Call(uintptr(p.token), syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE|syscall.TOKEN_ASSIGN_PRIMARY, 0, 2, 1, uintptr(unsafe.Pointer(&f.primary)))
		if ok == 0 || f.primary == 0 {
			return desktopWindowsCallFailure("probe primary token conversion", callErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sid, elevated, administrator, err := desktopWindowsProbeProcessToken(f.primary)
	parent, parentErr := syscall.OpenCurrentProcessToken()
	if parentErr != nil {
		t.Fatal(parentErr)
	}
	parentSID, _, parentIdentityErr := desktopWindowsTokenIdentity(parent)
	parentCloseErr := parent.Close()
	if err != nil || elevated || administrator || !bytes.Equal(sid, p.sid) || bytes.Equal(sid, parentSID) || parentIdentityErr != nil || parentCloseErr != nil {
		t.Fatal("probe primary token is not a distinct ordinary user", err, parentIdentityErr, parentCloseErr)
	}
	f.sidHash = fmt.Sprintf("%x", sha256.Sum256(sid))
	principal, err := (*syscall.SID)(unsafe.Pointer(&sid[0])).String()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	f.executable = filepath.Join(f.directory, "probe-child.test.exe")
	output, err := os.OpenFile(f.executable, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	if err := errors.Join(copyErr, output.Sync(), output.Close()); err != nil {
		t.Fatal(err)
	}
	if err := f.allowOwnedFile(f.executable, principal, "GRGX"); err != nil {
		t.Fatal(err)
	}
	if err := f.allowOwnedFile(f.directory, principal, "GRGX"); err != nil {
		t.Fatal(err)
	}
	if err := f.prepareDesktop(principal); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *desktopWindowsProbeProcess) run(scope []byte) (reply desktopWindowsProbeReply, resultErr error) {
	if f.identity.ctx.Err() != nil {
		return reply, errors.New("probe identity was cancelled before child acquisition")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	report, err := os.CreateTemp(f.directory, "probe-result-*.json")
	if err != nil {
		return reply, err
	}
	defer report.Close()
	defer os.Remove(report.Name())
	principal, err := (*syscall.SID)(unsafe.Pointer(&f.identity.sid[0])).String()
	if err != nil {
		return reply, err
	}
	if err := f.allowOwnedFile(report.Name(), principal, "GW"); err != nil {
		return reply, err
	}
	job := desktopWindowsProbeWorkerJob
	if job == 0 || os.Getenv(desktopWindowsProbeWorkerEnvironment) == "" {
		return reply, errors.New("ordinary probe child requires its exact dedicated Job owner")
	}
	application, _ := syscall.UTF16PtrFromString(f.executable)
	command, _ := syscall.UTF16FromString(syscall.EscapeArg(f.executable) + " -test.run=^TestDesktopWindowsProtectionProbeProcess$ -test.count=1 -test.timeout=10s")
	directory, _ := syscall.UTF16PtrFromString(f.directory)
	var environment []uint16
	entries := []string{
		"ROUTERVPN_WFP_PROBE_REPLY=" + report.Name(),
		"ROUTERVPN_WFP_PROBE_SCOPE=" + base64.StdEncoding.EncodeToString(scope),
		"ROUTERVPN_WFP_PROBE_SID=" + f.sidHash,
		"SystemRoot=" + os.Getenv("SystemRoot"),
		"TEMP=" + f.directory, "TMP=" + f.directory,
	}
	if f.hold {
		entries = append(entries, "ROUTERVPN_WFP_PROBE_HOLD=1")
	}
	for _, entry := range entries {
		encoded, err := syscall.UTF16FromString(entry)
		if err != nil {
			return reply, err
		}
		environment = append(environment, encoded...)
	}
	environment = append(environment, 0)
	if f.station == 0 || f.desktop == 0 || f.desktopName == "" {
		return reply, errors.New("probe child has no private captured window station and desktop")
	}
	desktop, err := syscall.UTF16PtrFromString(f.desktopName)
	if err != nil {
		return reply, err
	}
	startup := desktopWindowsProbeStartup{}
	startup.Info.Cb = uint32(unsafe.Sizeof(startup.Info))
	startup.Info.Desktop = desktop
	var process syscall.ProcessInformation
	// No inherited handles, no loaded profile, and no alternate-network-only logon:
	// the actual child primary token must be the isolated user on every thread.
	// Job inheritance is a required kernel observation, never metadata or an
	// assumed property of the alternate-token API. A child outside the exact
	// retained owner is terminated without ever resuming it.
	ok, callErr := f.createChild(application, &command[0], 0x08000404 /* no window, Unicode, suspended */, &environment[0], directory, &startup, &process)
	runtime.KeepAlive(application)
	runtime.KeepAlive(command)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(directory)
	runtime.KeepAlive(desktop)
	if process.Process != 0 {
		defer func() {
			state, _ := syscall.WaitForSingleObject(process.Process, 0)
			if state != syscall.WAIT_OBJECT_0 {
				resultErr = errors.Join(resultErr, syscall.TerminateProcess(process.Process, 125))
				state, err := syscall.WaitForSingleObject(process.Process, 5000)
				if err != nil || state != syscall.WAIT_OBJECT_0 {
					resultErr = errors.Join(resultErr, err, errors.New("owned probe child did not join"))
				}
			}
			resultErr = errors.Join(resultErr, syscall.CloseHandle(process.Process))
		}()
	}
	if process.Thread != 0 {
		defer syscall.CloseHandle(process.Thread)
	}
	if ok == 0 || process.Process == 0 || process.Thread == 0 {
		creationErr := desktopWindowsCallFailure("ordinary probe child basic CreateProcessWithTokenW", callErr)
		if errors.Is(callErr, syscall.Errno(87)) && process.Process == 0 && process.Thread == 0 {
			// Diagnose this exact rejected parameter boundary without allowing a
			// child to execute outside the creation-time Job. All controls target
			// the same held zero-byte file, which cannot be a Windows executable.
			creationErr = errors.Join(creationErr, f.diagnoseCreateParameters(startup, environment))
		}
		return reply, creationErr
	}
	var inJob uint32
	ok, _, callErr = f.api.inJob.Call(uintptr(process.Process), uintptr(job), uintptr(unsafe.Pointer(&inJob)))
	if ok == 0 || inJob != 1 {
		return reply, errors.Join(callErr, errors.New("ordinary probe child did not inherit its exact creation-time worker Job"))
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(process.Process, syscall.TOKEN_QUERY, &token); err != nil {
		return reply, err
	}
	sid, elevated, administrator, identityErr := desktopWindowsProbeProcessToken(token)
	closeErr := token.Close()
	if identityErr != nil || closeErr != nil || !bytes.Equal(sid, f.identity.sid) || elevated || administrator {
		return reply, errors.Join(identityErr, closeErr, errors.New("created probe child retained another user or administrator authority"))
	}
	resumed, _, callErr := f.api.resume.Call(uintptr(process.Thread))
	if resumed != 1 {
		return reply, desktopWindowsCallFailure("probe child resume", callErr)
	}
	if f.hold {
		// Public PID only, after independent token and both creation/ownership
		// boundaries. The outer test retains a real process handle and checks
		// membership of its separate outer Job before exercising owner death.
		fmt.Fprintln(os.Stdout, "PROBE_OWNED_CHILD", process.ProcessId)
	}
	for {
		state, err := syscall.WaitForSingleObject(process.Process, 20)
		if err != nil {
			return reply, err
		}
		if state == syscall.WAIT_OBJECT_0 {
			break
		}
		if ctx.Err() != nil {
			return reply, ctx.Err()
		}
	}
	var exit uint32
	if err := syscall.GetExitCodeProcess(process.Process, &exit); err != nil {
		return reply, err
	}
	if _, err := report.Seek(0, io.SeekStart); err != nil {
		return reply, err
	}
	raw, err := io.ReadAll(io.LimitReader(report, 16385))
	if err != nil || len(raw) > 16384 {
		return reply, errors.Join(err, errors.New("ordinary probe child reply is not bounded"))
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return reply, fmt.Errorf("ordinary probe child exit=%d has no valid reply: %w", exit, err)
	}
	if exit != 0 || reply.SetupError != "" || reply.SIDHash != f.sidHash || reply.PID != process.ProcessId || !reply.Primary || reply.Elevated || reply.Administrator {
		return reply, fmt.Errorf("ordinary probe child did not prove its captured process identity (exit=%d): %s", exit, reply.SetupError)
	}
	return reply, nil
}

func (f *desktopWindowsProbeProcess) createChild(application, command *uint16, flags uintptr, environment, directory *uint16, startup *desktopWindowsProbeStartup, child *syscall.ProcessInformation) (uintptr, error) {
	// Basic WithToken uses the already captured ordinary primary token and the
	// caller's existing SeImpersonate authority. A suspended child must prove
	// inherited membership; this function never assigns it to a Job afterward.
	ok, _, callErr := f.api.create.Call(uintptr(f.primary), 0, uintptr(unsafe.Pointer(application)), uintptr(unsafe.Pointer(command)),
		flags, uintptr(unsafe.Pointer(environment)), uintptr(unsafe.Pointer(directory)), uintptr(unsafe.Pointer(startup)), uintptr(unsafe.Pointer(child)))
	return ok, callErr
}

func (f *desktopWindowsProbeProcess) diagnoseCreateParameters(captured desktopWindowsProbeStartup, environment []uint16) error {
	control, err := os.CreateTemp(f.directory, "create-parameter-control-*.exe")
	if err != nil {
		return err
	}
	path := control.Name()
	if err := control.Close(); err != nil {
		return err
	}
	defer os.Remove(path)
	principal, err := (*syscall.SID)(unsafe.Pointer(&f.identity.sid[0])).String()
	if err != nil {
		return err
	}
	if err := f.allowOwnedFile(path, principal, "GRGX"); err != nil {
		return err
	}
	application, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	held, err := syscall.CreateFile(application, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(held)
	var attributes syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(held, &attributes); err != nil || attributes.FileSizeHigh != 0 || attributes.FileSizeLow != 0 || attributes.FileAttributes&(0x400|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 || attributes.NumberOfLinks != 1 {
		return errors.Join(err, errors.New("process parameter control did not pin an empty regular file"))
	}
	directory, _ := syscall.UTF16PtrFromString(f.directory)
	var statuses []string
	for _, variant := range []struct {
		name       string
		flags      uintptr
		cb         uint32
		attributes unsafe.Pointer
	}{
		{"basic", 0x08000404, uint32(unsafe.Sizeof(syscall.StartupInfo{})), nil},
		{"extended-empty", 0x08080404, uint32(unsafe.Sizeof(captured)), nil},
		{"extended-job", 0x08080404, uint32(unsafe.Sizeof(captured)), captured.Attributes},
		{"extended-basic-cb", 0x08080404, uint32(unsafe.Sizeof(syscall.StartupInfo{})), captured.Attributes},
		{"extended-without-no-window", 0x00080404, uint32(unsafe.Sizeof(captured)), captured.Attributes},
	} {
		startup := desktopWindowsProbeStartup{Info: captured.Info, Attributes: variant.attributes}
		startup.Info.Cb = variant.cb
		command, _ := syscall.UTF16FromString(syscall.EscapeArg(path))
		var child syscall.ProcessInformation
		ok, callErr := f.createChild(application, &command[0], variant.flags, &environment[0], directory, &startup, &child)
		runtime.KeepAlive(command)
		runtime.KeepAlive(startup)
		if child.Process != 0 {
			_ = syscall.TerminateProcess(child.Process, 125)
			state, waitErr := syscall.WaitForSingleObject(child.Process, 5000)
			closeErr := syscall.CloseHandle(child.Process)
			if child.Thread != 0 {
				closeErr = errors.Join(closeErr, syscall.CloseHandle(child.Thread))
				child.Thread = 0
			}
			if waitErr != nil || state != syscall.WAIT_OBJECT_0 || closeErr != nil {
				return errors.Join(waitErr, closeErr, errors.New("invalid-image diagnostic unexpectedly acquired an unjoined process"))
			}
		}
		if child.Thread != 0 {
			_ = syscall.CloseHandle(child.Thread)
			return errors.New("invalid-image diagnostic unexpectedly acquired a standalone thread")
		}
		if ok != 0 || child.Process != 0 || child.Thread != 0 {
			return errors.New("Windows unexpectedly accepted a pinned zero-byte executable control")
		}
		var status syscall.Errno
		if !errors.As(callErr, &status) {
			return errors.New("process parameter diagnostic returned no numeric Windows status")
		}
		statuses = append(statuses, fmt.Sprintf("%s(flags=0x%x,cb=%d):%d", variant.name, variant.flags, variant.cb, uint32(status)))
	}
	runtime.KeepAlive(application)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(directory)
	runtime.KeepAlive(captured)
	return fmt.Errorf("held non-executable process controls (STARTUPINFO=%d, STARTUPINFOEX=%d): %s", unsafe.Sizeof(syscall.StartupInfo{}), unsafe.Sizeof(captured), strings.Join(statuses, "; "))
}

// Only the deliberately launched non-admin process selects this helper. The
// parent gate does not include it in its ordinary test selection.
func TestDesktopWindowsProtectionProbeProcess(t *testing.T) {
	replyPath := os.Getenv("ROUTERVPN_WFP_PROBE_REPLY")
	encodedScope := os.Getenv("ROUTERVPN_WFP_PROBE_SCOPE")
	expected := os.Getenv("ROUTERVPN_WFP_PROBE_SID")
	if replyPath == "" && encodedScope == "" && expected == "" {
		return // Helper only; both required parent cases launch and verify it.
	}
	scope, err := base64.StdEncoding.DecodeString(encodedScope)
	if err != nil || !filepath.IsAbs(replyPath) || len(scope) == 0 || len(scope) > 65536 || len(scope)%2 != 0 || len(expected) != 64 {
		t.Fatal("missing exact owned probe child invocation")
	}
	reply := desktopWindowsProbeReply{PID: uint32(os.Getpid())}
	defer func() {
		raw, err := json.Marshal(reply)
		if err == nil {
			err = os.WriteFile(replyPath, raw, 0600)
		}
		if err != nil {
			t.Error("ordinary probe child could not write its owned reply", err)
		}
	}()
	setup := func() error {
		token, err := syscall.OpenCurrentProcessToken()
		if err != nil {
			return err
		}
		defer token.Close()
		sid, elevated, administrator, err := desktopWindowsProbeProcessToken(token)
		if err != nil {
			return err
		}
		reply.SIDHash = fmt.Sprintf("%x", sha256.Sum256(sid))
		reply.Primary = true
		reply.Elevated = elevated
		reply.Administrator = administrator
		if reply.SIDHash != expected || elevated || administrator {
			return errors.New("ordinary child inherited privileged or replacement authority")
		}
		if _, err := hex.DecodeString(expected); err != nil {
			return err
		}
		if os.Getenv("ROUTERVPN_WFP_PROBE_HOLD") == "1" {
			// This child is already independently non-admin and owned before it
			// runs. Only the lifetime test selects this bounded inert workload.
			time.Sleep(25 * time.Second)
			return errors.New("held probe child outlived its expected owner retirement")
		}
		engine, err := desktopWFPOpen(false)
		if err != nil {
			if engine != nil {
				_ = engine.Close()
			}
			return err
		}
		for index, kind := range []string{"session-lock", "baseline", "session-lock"} {
			key := desktopWindowsManagedKey(kind, scope)
			var pointer *desktopWFPSubLayer
			status, _, _ := engine.api.getLayer.Call(uintptr(engine.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pointer)))
			reply.Lookups[index] = uint32(status)
			if pointer != nil {
				engine.free(unsafe.Pointer(pointer))
			}
		}
		if err := engine.Close(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		reply.Absent, err = probeDesktopWindowsProtectionAbsent(ctx, scope)
		if err != nil {
			reply.ProbeError = err.Error()
		}
		return nil
	}
	if err := setup(); err != nil {
		reply.SetupError = strings.TrimSpace(err.Error())
		t.Error("ordinary probe child setup failed", err)
	}
}
