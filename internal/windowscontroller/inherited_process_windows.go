//go:build windows

package windowscontroller

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	inheritedParentAccess       = 0x00100000 | 0x1000 // SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
	inheritedParentProtectClose = 0x2                 // HANDLE_FLAG_PROTECT_FROM_CLOSE
)

// CaptureInheritedElevatedParent consumes the handle that the captured native
// launcher inherited into its same-token child. It accepts only the exact
// query/wait rights used by LaunchGUIChild, clears further inheritance, and
// keeps the actual kernel process object instead of reopening a public PID.
//
// The numeric value is not authentication. The caller must additionally bind
// the local pipe's actual peer and its pinned expected executable to the
// returned process before accepting any durable acknowledgment. This function
// neither establishes arbitrary parentage nor grants native mutation authority.
func CaptureInheritedElevatedParent(value uint64) (_ *Process, failure error) {
	if value == 0 || value > math.MaxInt64 || uint64(syscall.Handle(value)) != value {
		return nil, errors.New("the native child has no bounded inherited parent handle")
	}
	handle := syscall.Handle(value)
	owned := true
	defer func() {
		if owned {
			// Ownership of this local handle was explicitly transferred. A
			// rejected PROTECT_FROM_CLOSE flag must not strand it. Clearing that
			// local flag is cleanup only; the protected input is never admitted.
			failure = errors.Join(failure, syscall.SetHandleInformation(handle, inheritedParentProtectClose, 0), syscall.CloseHandle(handle))
		}
	}()
	api, err := native()
	if err != nil {
		return nil, err
	}
	flags, err := inheritedProcessHandleFlags(api, handle)
	if err != nil || flags != syscall.HANDLE_FLAG_INHERIT {
		return nil, errors.Join(err, errors.New("the native parent handle is not its inherited creation capability"))
	}
	access, err := inheritedProcessAccess(api, handle)
	if err != nil || access != inheritedParentAccess {
		return nil, errors.Join(err, errors.New("the native parent handle has unexpected access rights"))
	}
	if err := syscall.SetHandleInformation(handle, syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, err
	}
	flags, err = inheritedProcessHandleFlags(api, handle)
	if err != nil || flags != 0 {
		return nil, errors.Join(err, errors.New("the native parent handle retained child inheritance"))
	}
	// adoptProcess consumes this handle even when its kernel type is wrong.
	owned = false
	parent, err := adoptProcess(handle)
	if err != nil {
		return nil, err
	}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, parent.Close())
		}
	}()
	if parent.PID() == uint32(os.Getpid()) {
		return nil, errors.New("the native child substituted itself for its captured parent")
	}
	if err := parent.Alive(); err != nil {
		return nil, err
	}
	current, err := CurrentIdentity()
	if err != nil {
		return nil, err
	}
	actual, err := parent.Identity()
	if err != nil || !sameInheritedElevatedParent(current, actual) {
		return nil, errors.Join(err, errors.New("the native child changed its elevated parent identity"))
	}
	if _, err := parent.StartTimeUTCTicks(); err != nil {
		return nil, err
	}
	if err := parent.Alive(); err != nil {
		return nil, err
	}
	return parent, nil
}

func sameInheritedElevatedParent(current, parent TokenIdentity) bool {
	return current.Elevated && current.Administrator && parent.Elevated && parent.Administrator &&
		sameOriginalUser(current, parent)
}

func inheritedProcessHandleFlags(api *nativeAPI, handle syscall.Handle) (uint32, error) {
	query, err := api.processID.Dll.FindProc("GetHandleInformation")
	if err != nil {
		return 0, err
	}
	var flags uint32
	ok, _, callErr := query.Call(uintptr(handle), uintptr(unsafe.Pointer(&flags)))
	if ok == 0 {
		return 0, nativeError("inherited parent handle flags", callErr)
	}
	return flags, nil
}

func inheritedProcessAccess(api *nativeAPI, handle syscall.Handle) (uint32, error) {
	library, err := syscall.LoadDLL(filepath.Join(api.systemDirectory, "ntdll.dll"))
	if err != nil {
		return 0, err
	}
	defer library.Release()
	query, err := library.FindProc("NtQueryObject")
	if err != nil {
		return 0, err
	}
	// The documented PUBLIC_OBJECT_BASIC_INFORMATION ABI reports granted
	// access independently; no terminate/write/duplicate operation is attempted.
	var information struct {
		Attributes, GrantedAccess, HandleCount, PointerCount uint32
		Reserved                                             [10]uint32
	}
	var returned uint32
	status, _, _ := query.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&information)), unsafe.Sizeof(information), uintptr(unsafe.Pointer(&returned)))
	if uint32(status) != 0 || unsafe.Sizeof(information) != 56 || returned != 56 {
		return 0, fmt.Errorf("native parent access readback failed (NTSTATUS 0x%08x, bytes %d)", uint32(status), returned)
	}
	return information.GrantedAccess, nil
}
