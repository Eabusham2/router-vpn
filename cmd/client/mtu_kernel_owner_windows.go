//go:build windows

package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

// iphlpapi is in the Go standard library's system-DLL allowlist; LazyDLL
// resolves it through System32, not the portable application's directory.
var mtuIPHelper = syscall.NewLazyDLL("iphlpapi.dll")

//go:uintptrescapes
func mtuIPCall(name string, arguments ...uintptr) error {
	proc := mtuIPHelper.NewProc(name)
	if err := proc.Find(); err != nil {
		return err
	}
	code, _, _ := proc.Call(arguments...)
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

func mtuLUIDCurrent(luid uint64) (mtuLUIDIdentity, error) {
	identity := mtuLUIDIdentity{LUID: luid}
	var alias [257]uint16
	if err := mtuIPCall("ConvertInterfaceLuidToGuid", uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&identity.GUID))); err != nil {
		return identity, err
	}
	if err := mtuIPCall("ConvertInterfaceLuidToIndex", uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&identity.Index))); err != nil {
		return identity, err
	}
	if err := mtuIPCall("ConvertInterfaceLuidToAlias", uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&alias[0])), uintptr(len(alias))); err != nil {
		return identity, err
	}
	identity.Alias = syscall.UTF16ToString(alias[:])
	return identity, nil
}

func openMTUKernelOwner(live mtuLiveSnapshot) (mtuKernelOwner, error) {
	if !validMTUKernelCapture(live) || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" || unsafe.Sizeof(mtuIPInterfaceRow{}) != 168 || unsafe.Offsetof(mtuIPInterfaceRow{}.MTU) != 152 {
		return nil, errMTUKernelOwner
	}
	alias, err := syscall.UTF16PtrFromString(live.Interface)
	if err != nil {
		return nil, errMTUKernelOwner
	}
	var luid uint64
	if err := mtuIPCall("ConvertInterfaceAliasToLuid", uintptr(unsafe.Pointer(alias)), uintptr(unsafe.Pointer(&luid))); err != nil {
		return nil, err
	}
	identity, err := mtuLUIDCurrent(luid)
	if err != nil {
		return nil, err
	}
	calls := mtuLUIDCalls{identity: mtuLUIDCurrent,
		read: func(luid uint64, family uint16) (mtuIPInterfaceRow, error) {
			row := mtuIPInterfaceRow{Family: family, LUID: luid}
			err := mtuIPCall("GetIpInterfaceEntry", uintptr(unsafe.Pointer(&row)))
			return row, err
		},
		write: func(row *mtuIPInterfaceRow) error {
			return mtuIPCall("SetIpInterfaceEntry", uintptr(unsafe.Pointer(row)))
		},
	}
	return newMTULUIDKernelOwner(live, identity, calls)
}
