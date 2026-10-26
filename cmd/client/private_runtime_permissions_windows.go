//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	windowsRuntimeReadControl       = 0x00020000
	windowsRuntimeWriteDAC          = 0x00040000
	windowsRuntimeWriteOwner        = 0x00080000
	windowsRuntimeMaximumAllowed    = 0x02000000
	windowsRuntimeReadAttributes    = 0x00000080
	windowsRuntimeOwnerInformation  = 0x00000001
	windowsRuntimeDACLInformation   = 0x00000004
	windowsRuntimeProtectedDACL     = 0x80000000
	windowsRuntimeDACLPresent       = 0x0004
	windowsRuntimeFileObject        = 1
	windowsRuntimeAllowACE          = 0
	windowsRuntimeDenyACE           = 1
	windowsRuntimeInheritOnlyACE    = 0x08
	windowsRuntimeSupportedACEFlags = 0x1f
)

var (
	windowsRuntimeSecurityDLL     = syscall.NewLazyDLL("advapi32.dll")
	windowsRuntimeGetSecurityInfo = windowsRuntimeSecurityDLL.NewProc("GetSecurityInfo")
	windowsRuntimeSetSecurityInfo = windowsRuntimeSecurityDLL.NewProc("SetSecurityInfo")
	windowsRuntimeGetSDControl    = windowsRuntimeSecurityDLL.NewProc("GetSecurityDescriptorControl")
	windowsRuntimeGetSDOwner      = windowsRuntimeSecurityDLL.NewProc("GetSecurityDescriptorOwner")
	windowsRuntimeGetSDDACL       = windowsRuntimeSecurityDLL.NewProc("GetSecurityDescriptorDacl")
	windowsRuntimeConvertSDDL     = windowsRuntimeSecurityDLL.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	windowsRuntimeIsValidACL      = windowsRuntimeSecurityDLL.NewProc("IsValidAcl")
	windowsRuntimeIsValidSID      = windowsRuntimeSecurityDLL.NewProc("IsValidSid")
	windowsRuntimeGetACE          = windowsRuntimeSecurityDLL.NewProc("GetAce")
)

type windowsRuntimeACL struct {
	Revision  byte
	Reserved  byte
	Size      uint16
	Count     uint16
	Reserved2 uint16
}

type windowsRuntimeACE struct {
	Type  byte
	Flags byte
	Size  uint16
}

// GetSecurityInfo allocates this descriptor; owner and DACL point into it. Keep
// the complete allocation alive until all identity/permission checks finish.
type windowsRuntimeSecurity struct {
	descriptor unsafe.Pointer
	owner      *syscall.SID
	dacl       *windowsRuntimeACL
}

func (s windowsRuntimeSecurity) close() {
	if s.descriptor != nil {
		_, _ = syscall.LocalFree(syscall.Handle(s.descriptor))
	}
}

func windowsRuntimeCurrentUser() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return windowsRuntimeSIDString(user.User.Sid)
}

func windowsRuntimeSIDString(sid *syscall.SID) (string, error) {
	if sid == nil {
		return "", errors.New("private runtime security descriptor has no SID")
	}
	valid, _, _ := windowsRuntimeIsValidSID.Call(uintptr(unsafe.Pointer(sid)))
	if valid == 0 {
		return "", errors.New("private runtime security descriptor has an invalid SID")
	}
	return sid.String()
}

func windowsRuntimeTrustedSID(sid, user string) bool {
	// These are the same principals permitted by the installed private-root
	// hardener. Elevated Windows tokens may create Administrators-owned files;
	// that owner is already inside this explicitly trusted boundary.
	return sid == user || sid == "S-1-5-18" || sid == "S-1-5-32-544"
}

func windowsRuntimeInspectSecurity(file *os.File) (windowsRuntimeSecurity, error) {
	var security windowsRuntimeSecurity
	result, _, _ := windowsRuntimeGetSecurityInfo.Call(file.Fd(), windowsRuntimeFileObject,
		windowsRuntimeOwnerInformation|windowsRuntimeDACLInformation,
		uintptr(unsafe.Pointer(&security.owner)), 0, uintptr(unsafe.Pointer(&security.dacl)), 0,
		uintptr(unsafe.Pointer(&security.descriptor)))
	runtime.KeepAlive(file)
	if result != 0 {
		security.close()
		return windowsRuntimeSecurity{}, fmt.Errorf("read private runtime security: %w", syscall.Errno(result))
	}
	return security, nil
}

func windowsRuntimeValidateSecurity(security windowsRuntimeSecurity, user string) error {
	owner, err := windowsRuntimeSIDString(security.owner)
	if err != nil || !windowsRuntimeTrustedSID(owner, user) {
		return errors.New("private runtime has an untrusted Windows owner")
	}
	var control uint16
	var revision uint32
	ok, _, callErr := windowsRuntimeGetSDControl.Call(uintptr(security.descriptor), uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 {
		return fmt.Errorf("read private runtime security control: %w", callErr)
	}
	if control&windowsRuntimeDACLPresent == 0 || security.dacl == nil {
		return errors.New("private runtime has an absent or NULL Windows DACL")
	}
	valid, _, _ := windowsRuntimeIsValidACL.Call(uintptr(unsafe.Pointer(security.dacl)))
	acl := security.dacl
	if valid == 0 || (acl.Revision != 2 && acl.Revision != 4) || acl.Size < 8 || acl.Count == 0 || acl.Count > 1024 {
		return errors.New("private runtime has an invalid or empty Windows DACL")
	}
	base, end := uintptr(unsafe.Pointer(acl)), uintptr(unsafe.Pointer(acl))+uintptr(acl.Size)
	hasGrant := false
	for index := uint32(0); index < uint32(acl.Count); index++ {
		var ace *windowsRuntimeACE
		ok, _, callErr = windowsRuntimeGetACE.Call(uintptr(unsafe.Pointer(acl)), uintptr(index), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 {
			return fmt.Errorf("read private runtime ACE: %w", callErr)
		}
		position := uintptr(unsafe.Pointer(ace))
		if position < base+8 || position > end-4 || ace.Size < 16 || uintptr(ace.Size) > end-position ||
			(ace.Type != windowsRuntimeAllowACE && ace.Type != windowsRuntimeDenyACE) || ace.Flags&^byte(windowsRuntimeSupportedACEFlags) != 0 {
			return errors.New("private runtime DACL contains an unsupported ACE")
		}
		// ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE have an eight-byte header
		// before their variable-length SID. Bound that SID before asking Win32
		// to inspect it; callback/object ACE layouts are intentionally rejected.
		sidPointer := unsafe.Add(unsafe.Pointer(ace), 8)
		subAuthorities := *(*byte)(unsafe.Add(sidPointer, 1))
		if uintptr(8+4*uint32(subAuthorities)) > uintptr(ace.Size)-8 {
			return errors.New("private runtime DACL contains an out-of-bounds SID")
		}
		sid, err := windowsRuntimeSIDString((*syscall.SID)(sidPointer))
		if err != nil {
			return err
		}
		if ace.Type == windowsRuntimeAllowACE {
			if !windowsRuntimeTrustedSID(sid, user) {
				return errors.New("private runtime DACL grants access outside its Windows owner boundary")
			}
			mask := *(*uint32)(unsafe.Add(unsafe.Pointer(ace), 4))
			if mask != 0 && ace.Flags&windowsRuntimeInheritOnlyACE == 0 {
				hasGrant = true
			}
		}
	}
	if !hasGrant {
		return errors.New("private runtime DACL has no effective private grant")
	}
	return nil
}

func openWindowsPrivateRuntime(path string, info os.FileInfo, access uint32) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if err := windowsRuntimeObjectUnchanged(file, info); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func windowsRuntimeObjectUnchanged(file *os.File, info os.FileInfo) error {
	if err := privateRuntimeObjectUnchanged(file, info); err != nil {
		return err
	}
	var attributes syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &attributes); err != nil {
		return err
	}
	if attributes.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("private runtime object is a Windows reparse point")
	}
	return nil
}

func openPrivateRuntimeForRead(path string, info os.FileInfo) (*os.File, error) {
	access := uint32(windowsRuntimeReadControl | windowsRuntimeReadAttributes)
	if info == nil || !info.IsDir() {
		access |= syscall.GENERIC_READ
	}
	return openWindowsPrivateRuntime(path, info, access)
}

func validatePrivateRuntimeOpenPermissions(file *os.File, info os.FileInfo) error {
	if err := windowsRuntimeObjectUnchanged(file, info); err != nil {
		return err
	}
	user, err := windowsRuntimeCurrentUser()
	if err != nil {
		return err
	}
	security, err := windowsRuntimeInspectSecurity(file)
	if err != nil {
		return err
	}
	defer security.close()
	if err := windowsRuntimeValidateSecurity(security, user); err != nil {
		return err
	}
	return windowsRuntimeObjectUnchanged(file, info)
}

func windowsRuntimeSecurityFromSDDL(sddl string) (windowsRuntimeSecurity, error) {
	value, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return windowsRuntimeSecurity{}, err
	}
	var security windowsRuntimeSecurity
	ok, _, callErr := windowsRuntimeConvertSDDL.Call(uintptr(unsafe.Pointer(value)), 1, uintptr(unsafe.Pointer(&security.descriptor)), 0)
	if ok == 0 {
		return windowsRuntimeSecurity{}, fmt.Errorf("create private runtime descriptor: %w", callErr)
	}
	var defaulted, present uint32
	ok, _, callErr = windowsRuntimeGetSDOwner.Call(uintptr(security.descriptor), uintptr(unsafe.Pointer(&security.owner)), uintptr(unsafe.Pointer(&defaulted)))
	if ok != 0 {
		ok, _, callErr = windowsRuntimeGetSDDACL.Call(uintptr(security.descriptor), uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&security.dacl)), uintptr(unsafe.Pointer(&defaulted)))
	}
	if ok == 0 {
		security.close()
		return windowsRuntimeSecurity{}, fmt.Errorf("decode private runtime descriptor: %w", callErr)
	}
	return security, nil
}

func preparePrivateRuntimeDirectoryPermissions(path string, info os.FileInfo) error {
	if info == nil || !info.IsDir() {
		return errors.New("private runtime preparation requires a captured directory")
	}
	// SetSecurityInfo documents that a MAXIMUM_ALLOWED handle suppresses
	// propagation to existing children. Update only this captured directory;
	// new children still inherit its private ACEs when they are created.
	// https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
	file, err := openWindowsPrivateRuntime(path, info, windowsRuntimeMaximumAllowed)
	if err != nil {
		return err
	}
	defer file.Close()
	user, err := windowsRuntimeCurrentUser()
	if err != nil {
		return err
	}
	before, err := windowsRuntimeInspectSecurity(file)
	if err != nil {
		return err
	}
	owner, ownerErr := windowsRuntimeSIDString(before.owner)
	before.close()
	if ownerErr != nil || !windowsRuntimeTrustedSID(owner, user) {
		return errors.New("refusing to harden another Windows owner's runtime directory")
	}
	// Protected inheritance is established before any private native inputs
	// are staged, including in a fresh Portable or temporary runtime root.
	security, err := windowsRuntimeSecurityFromSDDL("O:" + user + "D:P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	defer security.close()
	if err := windowsRuntimeValidateSecurity(security, user); err != nil {
		return err
	}
	if err := windowsRuntimeObjectUnchanged(file, info); err != nil {
		return err
	}
	information := uint32(windowsRuntimeDACLInformation | windowsRuntimeProtectedDACL)
	var newOwner uintptr
	if owner != user {
		information |= windowsRuntimeOwnerInformation
		newOwner = uintptr(unsafe.Pointer(security.owner))
	}
	result, _, _ := windowsRuntimeSetSecurityInfo.Call(file.Fd(), windowsRuntimeFileObject,
		uintptr(information), newOwner, 0, uintptr(unsafe.Pointer(security.dacl)), 0)
	runtime.KeepAlive(security)
	runtime.KeepAlive(file)
	if result != 0 {
		return fmt.Errorf("establish private Windows runtime DACL: %w", syscall.Errno(result))
	}
	return validatePrivateRuntimeOpenPermissions(file, info)
}
