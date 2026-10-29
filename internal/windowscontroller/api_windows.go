//go:build windows

// Package windowscontroller owns the Windows process and local IPC boundary
// used by the native desktop launcher. It does not select a node, mutate network
// policy, or accept an HTTP listener as proof of controller ownership.
package windowscontroller

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

type nativeAPI struct {
	systemDirectory                                        string
	createPipe, connectPipe, pipeClientPID, pipeServerPID  *syscall.Proc
	pipeInfo, waitPipe, event, overlappedResult            *syscall.Proc
	processID, processImage, finalPath                     *syscall.Proc
	createJob, setJob, assignJob, inJob                    *syscall.Proc
	convertSD, localFree, impersonate, revert, threadToken *syscall.Proc
	shellExecute, initializeCOM, uninitializeCOM           *syscall.Proc
}

var nativeOnce struct {
	sync.Once
	api *nativeAPI
	err error
}

func native() (*nativeAPI, error) {
	nativeOnce.Do(func() {
		// Kernel32 is a Windows KnownDLL. Derive every subsequent library path
		// from the actual OS API, never SystemRoot, PATH or the portable folder.
		kernel := syscall.NewLazyDLL("kernel32.dll")
		directoryProc := kernel.NewProc("GetSystemDirectoryW")
		if err := directoryProc.Find(); err != nil {
			nativeOnce.err = err
			return
		}
		buffer := make([]uint16, 32768)
		n, _, callErr := directoryProc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		if n == 0 || n >= uintptr(len(buffer)) {
			nativeOnce.err = nativeError("system directory", callErr)
			return
		}
		api := &nativeAPI{systemDirectory: syscall.UTF16ToString(buffer[:n])}
		if !filepath.IsAbs(api.systemDirectory) {
			nativeOnce.err = errors.New("Windows returned no absolute system directory")
			return
		}
		libraries := []struct {
			name  string
			procs map[string]**syscall.Proc
		}{
			{"kernel32.dll", map[string]**syscall.Proc{
				"CreateNamedPipeW": &api.createPipe, "ConnectNamedPipe": &api.connectPipe,
				"GetNamedPipeClientProcessId": &api.pipeClientPID, "GetNamedPipeServerProcessId": &api.pipeServerPID,
				"GetNamedPipeInfo": &api.pipeInfo, "WaitNamedPipeW": &api.waitPipe,
				"CreateEventW": &api.event, "GetOverlappedResult": &api.overlappedResult,
				"GetProcessId": &api.processID, "QueryFullProcessImageNameW": &api.processImage,
				"GetFinalPathNameByHandleW": &api.finalPath, "LocalFree": &api.localFree,
				"CreateJobObjectW": &api.createJob, "SetInformationJobObject": &api.setJob,
				"AssignProcessToJobObject": &api.assignJob, "IsProcessInJob": &api.inJob,
			}},
			{"advapi32.dll", map[string]**syscall.Proc{
				"ConvertStringSecurityDescriptorToSecurityDescriptorW": &api.convertSD,
				"ImpersonateNamedPipeClient":                           &api.impersonate, "RevertToSelf": &api.revert,
				"OpenThreadToken": &api.threadToken,
			}},
			{"shell32.dll", map[string]**syscall.Proc{"ShellExecuteExW": &api.shellExecute}},
			{"ole32.dll", map[string]**syscall.Proc{"CoInitializeEx": &api.initializeCOM, "CoUninitialize": &api.uninitializeCOM}},
		}
		var loaded []*syscall.DLL
		for _, library := range libraries {
			dll, err := syscall.LoadDLL(filepath.Join(api.systemDirectory, library.name))
			if err == nil {
				loaded = append(loaded, dll)
				for name, destination := range library.procs {
					*destination, err = dll.FindProc(name)
					if err != nil {
						break
					}
				}
			}
			if err != nil {
				for _, owned := range loaded {
					_ = owned.Release()
				}
				nativeOnce.err = err
				return
			}
		}
		// Published proc references and their captured system modules have the
		// same process lifetime. A live operation never races DLL unloading.
		nativeOnce.api = api
	})
	return nativeOnce.api, nativeOnce.err
}

func nativeError(operation string, err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return errors.New("Windows controller " + operation + " failed without a status")
	}
	return fmt.Errorf("Windows controller %s: %w", operation, err)
}

// withDescriptor confines each access grant to a new object and the exact
// captured local principal. No existing object's ACL is changed.
func withDescriptor(sid string, apply func(*syscall.SecurityAttributes) error) error {
	api, err := native()
	if err != nil {
		return err
	}
	parsed, err := syscall.StringToSid(sid)
	if err != nil {
		return errors.New("Windows controller principal is invalid")
	}
	canonical, err := parsed.String()
	if err != nil || canonical != sid {
		return errors.New("Windows controller principal is not canonical")
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")")
	if err != nil {
		return err
	}
	var descriptor unsafe.Pointer
	var length uint32
	ok, _, callErr := api.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&length)))
	if descriptor != nil {
		defer api.localFree.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil || length < 20 {
		return nativeError("private object descriptor", callErr)
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
	err = apply(&attributes)
	runtime.KeepAlive(sddl)
	runtime.KeepAlive(parsed)
	return err
}
