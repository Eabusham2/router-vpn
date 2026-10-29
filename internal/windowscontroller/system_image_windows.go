//go:build windows

package windowscontroller

import (
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// PinSystemPowerShell captures the OS-supplied Windows PowerShell executable.
// Windows servicing uses hardlinks for this file. Only this pathless factory
// admits them, after checking the retained file and non-root ancestors' actual
// owner/DACL. The existing locks, exact link count and suspended process proof
// still apply. PATH, SystemRoot and a caller-selected path confer no authority.
func PinSystemPowerShell() (*Image, error) {
	api, err := native()
	if err != nil {
		return nil, err
	}
	return pinImage(filepath.Join(api.systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), true)
}

var systemImageSecurityOnce struct {
	sync.Once
	get, valid, length *syscall.Proc
	err                error
}

func verifySystemImageProtection(handle syscall.Handle) (resultErr error) {
	api, err := native()
	if err != nil {
		return err
	}
	systemImageSecurityOnce.Do(func() {
		// Reuse the already captured absolute system advapi32 module. No
		// additional DLL search path or mutable environment is consulted.
		for name, destination := range map[string]**syscall.Proc{
			"GetSecurityInfo":             &systemImageSecurityOnce.get,
			"IsValidSecurityDescriptor":   &systemImageSecurityOnce.valid,
			"GetSecurityDescriptorLength": &systemImageSecurityOnce.length,
		} {
			*destination, systemImageSecurityOnce.err = api.convertSD.Dll.FindProc(name)
			if systemImageSecurityOnce.err != nil {
				return
			}
		}
	})
	if systemImageSecurityOnce.err != nil {
		return systemImageSecurityOnce.err
	}
	var descriptor unsafe.Pointer
	status, _, _ := systemImageSecurityOnce.get.Call(uintptr(handle), 1 /* SE_FILE_OBJECT */, 1|4 /* OWNER | DACL */, 0, 0, 0, 0, uintptr(unsafe.Pointer(&descriptor)))
	if descriptor != nil {
		defer func() {
			if remaining, _, callErr := api.localFree.Call(uintptr(descriptor)); remaining != 0 {
				resultErr = errors.Join(resultErr, nativeError("system image descriptor release", callErr))
			}
		}()
	}
	if status != 0 || descriptor == nil {
		return nativeError("retained system image security", syscall.Errno(status))
	}
	valid, _, _ := systemImageSecurityOnce.valid.Call(uintptr(descriptor))
	if valid == 0 {
		return errors.New("Windows system image has an invalid security descriptor")
	}
	length, _, _ := systemImageSecurityOnce.length.Call(uintptr(descriptor))
	if length < 20 || length > 1<<20 {
		return errors.New("Windows system image security descriptor is unbounded")
	}
	// GetSecurityInfo returns a self-relative descriptor whose components are
	// in this one allocation. Parse a bounded copy before releasing it.
	data := append([]byte(nil), unsafe.Slice((*byte)(descriptor), int(length))...)
	err = validateSystemImageDescriptor(data)
	runtime.KeepAlive(descriptor)
	return err
}
