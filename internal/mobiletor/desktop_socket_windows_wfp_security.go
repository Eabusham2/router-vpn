//go:build windows

package mobiletor

import (
	"encoding/binary"
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// WFP's default inherited descriptor also admits Network Configuration
// Operators. The managed baseline and session lock instead grant management
// only to Administrators and SYSTEM. No ACL on another application's object,
// the WFP containers, or the engine itself is changed.
// https://learn.microsoft.com/windows/win32/fwp/access-control
func desktopWFPOwnerSD(api *desktopWFPAPI) ([]byte, error) {
	sddl, _ := syscall.UTF16PtrFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	var pointer unsafe.Pointer
	var size uint32
	ok, _, callErr := api.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&pointer)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(sddl)
	if pointer != nil {
		defer api.freeLocal.Call(uintptr(pointer))
	}
	if ok == 0 || pointer == nil || size < 20 || size > 4096 {
		return nil, errors.Join(callErr, errors.New("WFP owner ACL could not be created"))
	}
	return append([]byte(nil), unsafe.Slice((*byte)(pointer), int(size))...), nil
}

func desktopWFPSIDString(pointer *syscall.SID) (string, error) {
	if pointer == nil {
		return "", errors.New("WFP owner ACL has no SID")
	}
	return pointer.String()
}

func (e *desktopWFPEngine) assertLayerSecurity(key syscall.GUID) error {
	return e.assertObjectSecurity(e.api.getLayerSecurity, key)
}
func (e *desktopWFPEngine) assertObjectSecurity(get *syscall.Proc, key syscall.GUID) error {
	var owner, group *syscall.SID
	var dacl, descriptor unsafe.Pointer
	status, _, _ := get.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&key)), 7,
		uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&group)), uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor)))
	if descriptor != nil {
		defer e.free(descriptor)
	}
	if err := desktopWFPError("read managed object security", status); err != nil {
		return err
	}
	actualOwner, ownerErr := desktopWFPSIDString(owner)
	actualGroup, groupErr := desktopWFPSIDString(group)
	if descriptor == nil || dacl == nil || ownerErr != nil || groupErr != nil || actualOwner != "S-1-5-32-544" || actualGroup != "S-1-5-32-544" {
		return errors.New("WFP managed object has an untrusted security owner")
	}
	var control uint16
	var revision uint32
	ok, _, callErr := e.api.getSDControl.Call(uintptr(descriptor), uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 || revision != 1 || control&0x1004 != 0x1004 { // protected, present DACL
		return errors.Join(callErr, errors.New("WFP managed object inherited an untrusted ACL"))
	}
	header := unsafe.Slice((*byte)(dacl), 8)
	size, count := int(binary.LittleEndian.Uint16(header[2:4])), int(binary.LittleEndian.Uint16(header[4:6]))
	if (header[0] != 2 && header[0] != 4) || size < 8 || size > 4096 || count != 2 {
		return errors.New("WFP managed object ACL changed shape")
	}
	data := unsafe.Slice((*byte)(dacl), size)
	seen := make(map[string]bool, 2)
	position := 8
	for index := 0; index < count; index++ {
		if position+16 > len(data) {
			return errors.New("WFP managed object ACL is truncated")
		}
		aceSize := int(binary.LittleEndian.Uint16(data[position+2 : position+4]))
		if data[position] != 0 || data[position+1] != 0 || aceSize < 16 || position+aceSize > len(data) {
			return errors.New("WFP managed object ACL acquired another ACE")
		}
		mask := binary.LittleEndian.Uint32(data[position+4 : position+8])
		if mask != 0x10000000 && mask != 0x000f07ff { // GA or its SDK FWPM_GENERIC_ALL mapping
			return errors.New("WFP managed object ACL changed its access rights")
		}
		sid := data[position+8 : position+aceSize]
		if sid[0] != 1 || sid[1] > 15 || len(sid) != 8+int(sid[1])*4 {
			return errors.New("WFP managed object ACL has a malformed principal")
		}
		principal, err := desktopWFPSIDString((*syscall.SID)(unsafe.Pointer(&sid[0])))
		if err != nil || principal != "S-1-5-18" && principal != "S-1-5-32-544" || seen[principal] {
			return errors.New("WFP managed object ACL admits another principal")
		}
		seen[principal] = true
		position += aceSize
	}
	if !seen["S-1-5-18"] || !seen["S-1-5-32-544"] {
		return errors.New("WFP managed object ACL lost its administrators")
	}
	return nil
}
