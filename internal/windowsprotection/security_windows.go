//go:build windows

package windowsprotection

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

const (
	protectionReadControl    = 0x00020000
	protectionReadAttributes = 0x00000080
	protectionDelete         = 0x00010000
	protectionDeleteOnClose  = 0x04000000
	protectionFullAccess     = 0x001f01ff
)

type protectionNativeAPI struct {
	createDirectory, finalPath, setInformation, localFree *syscall.Proc
	convert, getSecurity, validSecurity, validACL         *syscall.Proc
	control, owner, dacl, ace, validSID                   *syscall.Proc
}

var protectionNativeOnce struct {
	sync.Once
	api *protectionNativeAPI
	err error
}

func protectionNative() (*protectionNativeAPI, error) {
	protectionNativeOnce.Do(func() {
		system, err := windowscontroller.SystemDirectory()
		if err != nil {
			protectionNativeOnce.err = err
			return
		}
		api := &protectionNativeAPI{}
		var loaded []*syscall.DLL
		for _, module := range []struct {
			name  string
			procs map[string]**syscall.Proc
		}{
			{"kernel32.dll", map[string]**syscall.Proc{
				"CreateDirectoryW": &api.createDirectory, "GetFinalPathNameByHandleW": &api.finalPath,
				"SetFileInformationByHandle": &api.setInformation, "LocalFree": &api.localFree,
			}},
			{"advapi32.dll", map[string]**syscall.Proc{
				"ConvertStringSecurityDescriptorToSecurityDescriptorW": &api.convert,
				"GetSecurityInfo": &api.getSecurity, "IsValidSecurityDescriptor": &api.validSecurity,
				"IsValidAcl": &api.validACL, "IsValidSid": &api.validSID,
				"GetSecurityDescriptorControl": &api.control, "GetSecurityDescriptorOwner": &api.owner,
				"GetSecurityDescriptorDacl": &api.dacl, "GetAce": &api.ace,
			}},
		} {
			library, err := syscall.LoadDLL(filepath.Join(system, module.name))
			if err == nil {
				loaded = append(loaded, library)
				for name, destination := range module.procs {
					*destination, err = library.FindProc(name)
					if err != nil {
						break
					}
				}
			}
			if err != nil {
				for _, library := range loaded {
					_ = library.Release()
				}
				protectionNativeOnce.err = err
				return
			}
		}
		// The resolved native procedures and their system libraries live for the
		// process lifetime. No imported path or environment selects these DLLs.
		protectionNativeOnce.api = api
	})
	return protectionNativeOnce.api, protectionNativeOnce.err
}

type protectionACL struct {
	revision, reserved byte
	size, count, tail  uint16
}

type protectionACE struct {
	kind, flags byte
	size        uint16
	mask        uint32
}

type protectionSecurity struct {
	api        *protectionNativeAPI
	descriptor unsafe.Pointer
}

func (s *protectionSecurity) close() error {
	if s == nil || s.descriptor == nil {
		return nil
	}
	remaining, _, callErr := s.api.localFree.Call(uintptr(s.descriptor))
	if remaining != 0 {
		return fmt.Errorf("release protection security descriptor: %w", callErr)
	}
	s.descriptor = nil
	return nil
}

func (s *protectionSecurity) verify(directory bool) error {
	if s == nil || s.api == nil || s.descriptor == nil {
		return errors.New("protection object has no retained security descriptor")
	}
	valid, _, _ := s.api.validSecurity.Call(uintptr(s.descriptor))
	if valid == 0 {
		return errors.New("protection object has an invalid security descriptor")
	}
	var owner *syscall.SID
	var defaulted, revision, present uint32
	var control uint16
	var acl *protectionACL
	ok, _, _ := s.api.owner.Call(uintptr(s.descriptor), uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || owner == nil {
		return errors.New("protection object has no captured owner")
	}
	valid, _, _ = s.api.validSID.Call(uintptr(unsafe.Pointer(owner)))
	if valid == 0 {
		return errors.New("protection object has an invalid owner")
	}
	principal, err := owner.String()
	if err != nil || principal != "S-1-5-18" && principal != "S-1-5-32-544" {
		return errors.New("protection object is not owned by System or Administrators")
	}
	ok, _, _ = s.api.control.Call(uintptr(s.descriptor), uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 || control&0x1004 != 0x1004 { // SE_DACL_PRESENT | SE_DACL_PROTECTED
		return errors.New("protection object has no protected explicit DACL")
	}
	ok, _, _ = s.api.dacl.Call(uintptr(s.descriptor), uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&acl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present == 0 || acl == nil {
		return errors.New("protection object has an absent or null DACL")
	}
	valid, _, _ = s.api.validACL.Call(uintptr(unsafe.Pointer(acl)))
	if valid == 0 || acl.revision != 2 && acl.revision != 4 || acl.size < 8 || acl.count != 2 {
		return errors.New("protection object has an unknown access policy")
	}
	flags := byte(0)
	if directory {
		flags = 3 // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
	}
	base, end := uintptr(unsafe.Pointer(acl)), uintptr(unsafe.Pointer(acl))+uintptr(acl.size)
	seen := make(map[string]bool, 2)
	for index := uint16(0); index < acl.count; index++ {
		var ace *protectionACE
		ok, _, _ = s.api.ace.Call(uintptr(unsafe.Pointer(acl)), uintptr(index), uintptr(unsafe.Pointer(&ace)))
		position := uintptr(unsafe.Pointer(ace))
		if ok == 0 || ace == nil || position < base+8 || position > end-16 || ace.size < 16 || uintptr(ace.size) > end-position ||
			ace.kind != 0 || ace.flags != flags || ace.mask != protectionFullAccess {
			return errors.New("protection object has a changed or unsupported access entry")
		}
		sid := unsafe.Add(unsafe.Pointer(ace), 8)
		count := *(*byte)(unsafe.Add(sid, 1))
		if *(*byte)(sid) != 1 || count > 15 || 8+4*uint32(count) != uint32(ace.size)-8 {
			return errors.New("protection access principal exceeds its captured entry")
		}
		valid, _, _ = s.api.validSID.Call(uintptr(sid))
		if valid == 0 {
			return errors.New("protection access principal is invalid")
		}
		principal, err := (*syscall.SID)(sid).String()
		if err != nil || seen[principal] || principal != "S-1-5-18" && principal != "S-1-5-32-544" {
			return errors.New("protection object grants access outside its captured administrative boundary")
		}
		seen[principal] = true
	}
	return nil
}

func newProtectionSecurity(api *protectionNativeAPI, directory bool) (_ *protectionSecurity, failure error) {
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	value, err := syscall.UTF16PtrFromString("O:BAG:BAD:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)")
	if err != nil {
		return nil, err
	}
	security := &protectionSecurity{api: api}
	ok, _, callErr := api.convert.Call(uintptr(unsafe.Pointer(value)), 1, uintptr(unsafe.Pointer(&security.descriptor)), 0)
	runtime.KeepAlive(value)
	if ok == 0 || security.descriptor == nil {
		return nil, errors.Join(fmt.Errorf("create protection descriptor: %w", callErr), security.close())
	}
	if err := security.verify(directory); err != nil {
		return nil, errors.Join(err, security.close())
	}
	return security, nil
}

func verifyProtectionSecurity(api *protectionNativeAPI, handle syscall.Handle, directory bool) (failure error) {
	security := &protectionSecurity{api: api}
	status, _, _ := api.getSecurity.Call(uintptr(handle), 1 /* SE_FILE_OBJECT */, 1|4 /* OWNER | DACL */, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&security.descriptor)))
	if status != 0 || security.descriptor == nil {
		return errors.Join(fmt.Errorf("read captured protection security: %w", syscall.Errno(status)), security.close())
	}
	defer func() { failure = errors.Join(failure, security.close()) }()
	return security.verify(directory)
}
