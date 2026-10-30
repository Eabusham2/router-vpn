//go:build windows

package windowsapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

type portableNativeAPI struct {
	createDirectory, localFree                          *syscall.Proc
	convert, get, set, control, owner, dacl, ace, valid *syscall.Proc
}

var portableNativeOnce struct {
	sync.Once
	api *portableNativeAPI
	err error
}

func portableNative() (*portableNativeAPI, error) {
	portableNativeOnce.Do(func() {
		system, err := windowscontroller.SystemDirectory()
		if err != nil {
			portableNativeOnce.err = err
			return
		}
		api := &portableNativeAPI{}
		var modules []*syscall.DLL
		for _, module := range []struct {
			name  string
			procs map[string]**syscall.Proc
		}{
			{"kernel32.dll", map[string]**syscall.Proc{"CreateDirectoryW": &api.createDirectory, "LocalFree": &api.localFree}},
			{"advapi32.dll", map[string]**syscall.Proc{
				"ConvertStringSecurityDescriptorToSecurityDescriptorW": &api.convert,
				"GetSecurityInfo": &api.get, "SetSecurityInfo": &api.set,
				"GetSecurityDescriptorControl": &api.control, "GetSecurityDescriptorOwner": &api.owner,
				"GetSecurityDescriptorDacl": &api.dacl, "GetAce": &api.ace, "IsValidSecurityDescriptor": &api.valid,
			}},
		} {
			library, err := syscall.LoadDLL(filepath.Join(system, module.name))
			if err == nil {
				modules = append(modules, library)
				for name, destination := range module.procs {
					*destination, err = library.FindProc(name)
					if err != nil {
						break
					}
				}
			}
			if err != nil {
				for _, loaded := range modules {
					_ = loaded.Release()
				}
				portableNativeOnce.err = err
				return
			}
		}
		portableNativeOnce.api = api
	})
	return portableNativeOnce.api, portableNativeOnce.err
}

type portableACL struct {
	revision, reserved byte
	size, count, tail  uint16
}

type portableACE struct {
	kind, flags byte
	size        uint16
	mask        uint32
}

type portableSecurity struct {
	api        *portableNativeAPI
	descriptor unsafe.Pointer
	control    uint16
}

func (s *portableSecurity) close() error {
	if s == nil || s.descriptor == nil {
		return nil
	}
	remaining, _, err := s.api.localFree.Call(uintptr(s.descriptor))
	if remaining != 0 {
		return fmt.Errorf("release Portable private descriptor: %w", err)
	}
	s.descriptor = nil
	return nil
}

func (s *portableSecurity) inspect() (string, *portableACL, []portableAccessGrant, error) {
	if s == nil || s.api == nil || s.descriptor == nil {
		return "", nil, nil, errors.New("Portable state has no retained security descriptor")
	}
	valid, _, _ := s.api.valid.Call(uintptr(s.descriptor))
	if valid == 0 {
		return "", nil, nil, errors.New("Portable state has an invalid security descriptor")
	}
	var owner *syscall.SID
	var defaulted, present, revision uint32
	var control uint16
	var acl *portableACL
	ok, _, err := s.api.owner.Call(uintptr(s.descriptor), uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || owner == nil {
		return "", nil, nil, fmt.Errorf("read Portable owner: %w", err)
	}
	principal, err := owner.String()
	if err != nil {
		return "", nil, nil, err
	}
	ok, _, err = s.api.control.Call(uintptr(s.descriptor), uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 || control&0x0004 == 0 {
		return "", nil, nil, errors.New("Portable state has no explicit DACL")
	}
	s.control = control
	ok, _, err = s.api.dacl.Call(uintptr(s.descriptor), uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&acl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present == 0 || acl == nil || (acl.revision != 2 && acl.revision != 4) || acl.size < 8 || acl.count > 1024 {
		return "", nil, nil, errors.New("Portable state has an invalid or null DACL")
	}
	base := uintptr(unsafe.Pointer(acl))
	end := base + uintptr(acl.size)
	grants := make([]portableAccessGrant, 0, acl.count)
	for index := uint16(0); index < acl.count; index++ {
		var ace *portableACE
		ok, _, err = s.api.ace.Call(uintptr(unsafe.Pointer(acl)), uintptr(index), uintptr(unsafe.Pointer(&ace)))
		position := uintptr(unsafe.Pointer(ace))
		if ok == 0 || ace == nil || position < base+8 || position > end-16 || ace.size < 16 || uintptr(ace.size) > end-position ||
			(ace.kind != 0 && ace.kind != 1) || ace.flags&^byte(0x1f) != 0 {
			return "", nil, nil, errors.New("Portable state has a malformed or unsupported access entry")
		}
		sid := unsafe.Add(unsafe.Pointer(ace), 8)
		count := *(*byte)(unsafe.Add(sid, 1))
		if *(*byte)(sid) != 1 || count > 15 || 8+4*uint32(count) != uint32(ace.size)-8 {
			return "", nil, nil, errors.New("Portable state has an invalid access principal")
		}
		name, err := (*syscall.SID)(sid).String()
		if err != nil {
			return "", nil, nil, err
		}
		grants = append(grants, portableAccessGrant{name, ace.kind == 0, ace.flags, ace.mask})
	}
	return principal, acl, grants, nil
}

func portableDescriptor(api *portableNativeAPI, desktop string, directory bool) (*portableSecurity, error) {
	sid, err := syscall.StringToSid(desktop)
	if err != nil {
		return nil, err
	}
	canonical, err := sid.String()
	if err != nil || canonical != desktop {
		return nil, errors.New("Portable desktop principal is not canonical")
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sddl, err := syscall.UTF16PtrFromString("O:" + desktop + "D:P(A;" + inherit + ";FA;;;" + desktop + ")(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)")
	if err != nil {
		return nil, err
	}
	security := &portableSecurity{api: api}
	ok, _, err := api.convert.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&security.descriptor)), 0)
	runtime.KeepAlive(sddl)
	if ok == 0 || security.descriptor == nil {
		return nil, errors.Join(fmt.Errorf("create Portable private descriptor: %w", err), security.close())
	}
	owner, _, grants, err := security.inspect()
	if err == nil {
		err = validatePortablePrivateGrants(owner, desktop, grants)
	}
	if err != nil {
		return nil, errors.Join(err, security.close())
	}
	return security, nil
}

func portableInspectSecurity(api *portableNativeAPI, file *os.File) (*portableSecurity, error) {
	security := &portableSecurity{api: api}
	status, _, _ := api.get.Call(file.Fd(), 1, 1|4, 0, 0, 0, 0, uintptr(unsafe.Pointer(&security.descriptor)))
	runtime.KeepAlive(file)
	if status != 0 || security.descriptor == nil {
		return nil, errors.Join(fmt.Errorf("read captured Portable security: %w", syscall.Errno(status)), security.close())
	}
	return security, nil
}

func portableFileIdentity(file *os.File, directory bool) (syscall.ByHandleFileInformation, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &info); err != nil {
		return info, err
	}
	kind, err := syscall.GetFileType(syscall.Handle(file.Fd()))
	if err != nil || kind != syscall.FILE_TYPE_DISK || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) != directory ||
		!directory && info.NumberOfLinks != 1 || info.FileIndexHigh == 0 && info.FileIndexLow == 0 {
		return info, errors.Join(err, errors.New("Portable state is not its regular single-link file or retained directory"))
	}
	return info, nil
}

func portableHardenCaptured(api *portableNativeAPI, file *os.File, desktop string, directory bool) (failure error) {
	if _, err := portableFileIdentity(file, directory); err != nil {
		return err
	}
	before, err := portableInspectSecurity(api, file)
	if err != nil {
		return err
	}
	owner, _, _, inspectErr := before.inspect()
	err = errors.Join(inspectErr, before.close())
	if err != nil || !portableTrustedPrincipal(owner, desktop) {
		return errors.Join(err, errors.New("refusing to change another Windows owner's Portable state"))
	}
	security, err := portableDescriptor(api, desktop, directory)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, security.close()) }()
	_, acl, _, err := security.inspect()
	if err != nil {
		return err
	}
	// The caller opens with MAXIMUM_ALLOWED, which suppresses propagation to
	// existing children. Only this retained object changes, never an unrelated
	// descendant or another profile. New children inherit these private grants.
	// https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
	status, _, _ := api.set.Call(file.Fd(), 1, 4|0x80000000, 0, 0, uintptr(unsafe.Pointer(acl)), 0)
	runtime.KeepAlive(security)
	runtime.KeepAlive(file)
	if status != 0 {
		return fmt.Errorf("establish captured Portable private DACL: %w", syscall.Errno(status))
	}
	after, err := portableInspectSecurity(api, file)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, after.close()) }()
	owner, _, grants, err := after.inspect()
	if err != nil {
		return err
	}
	if after.control&0x1000 == 0 {
		return errors.New("Portable private state did not protect its inheritance")
	}
	if err := validatePortablePrivateGrants(owner, desktop, grants); err != nil {
		return err
	}
	_, err = portableFileIdentity(file, directory)
	return err
}

func portableOpenExisting(path string, directory bool, share uint32) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, 0x02000000 /* MAXIMUM_ALLOWED */, share, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if _, err := portableFileIdentity(file, directory); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}
