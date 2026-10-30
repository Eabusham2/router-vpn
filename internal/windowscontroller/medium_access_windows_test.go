//go:build windows

package windowscontroller

import (
	"bytes"
	"encoding/binary"
	"errors"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// Read-only native evidence for a child that previously failed during DLL
// initialization. AccessCheck evaluates a duplicated impersonation token as
// data; no thread adopts it and no descriptor, privilege or token is modified.
func fixtureInspectMediumStartup(t *testing.T, api *fixtureRestrictedAPI, token syscall.Token, process syscall.ProcessInformation, image *Image, session uint32) {
	t.Helper()
	var functions [4]*syscall.Proc
	for index, name := range []string{"DuplicateTokenEx", "GetSecurityInfo", "AccessCheck", "GetSecurityDescriptorLength"} {
		var err error
		functions[index], err = api.native.revert.Dll.FindProc(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	var query syscall.Token
	ok, _, callErr := functions[0].Call(uintptr(token), syscall.TOKEN_QUERY, 0, 2 /* SecurityImpersonation */, 2 /* TokenImpersonation */, uintptr(unsafe.Pointer(&query)))
	if query != 0 {
		defer query.Close()
	}
	if ok == 0 || query == 0 {
		t.Fatal(nativeError("Medium startup access-check token", callErr))
	}
	check := func(name string, handle syscall.Handle, kind, all, wanted uint32) {
		var descriptor unsafe.Pointer
		information := uint32(1 | 2 | 4)
		if kind == 6 {
			information |= 0x10 // LABEL_SECURITY_INFORMATION requires READ_CONTROL.
		}
		status, _, _ := functions[1].Call(uintptr(handle), uintptr(kind), uintptr(information), 0, 0, 0, 0, uintptr(unsafe.Pointer(&descriptor)))
		if descriptor != nil {
			defer api.native.localFree.Call(uintptr(descriptor))
		}
		if status != 0 || descriptor == nil {
			t.Fatalf("Medium startup %s security readback failed: %d", name, status)
		}
		length, _, _ := functions[3].Call(uintptr(descriptor))
		if length < 20 || length > 65536 {
			t.Fatal("Medium startup descriptor is unbounded")
		}
		mapping := struct{ Read, Write, Execute, All uint32 }{All: all}
		if kind == 1 {
			mapping.Read, mapping.Write, mapping.Execute = 0x00120089, 0x00120116, 0x001200a0
		} else {
			// Kernel creation normally maps these grants already. We know the
			// full object mask; do not invent mappings for an unexpected generic
			// read/write/execute ACE and call that a measured access result.
			captured := unsafe.Slice((*byte)(descriptor), int(length))
			if binary.LittleEndian.Uint16(captured[2:4])&0x9014 != 0x9014 {
				t.Fatal("Medium startup kernel descriptor is not a captured explicit DACL")
			}
			fixtureVerifyMediumStartupLabel(t, captured)
			start := int(binary.LittleEndian.Uint32(captured[16:20]))
			if start < 20 || start > len(captured)-8 {
				t.Fatal("Medium startup kernel DACL has an invalid bound")
			}
			acl := captured[start:]
			length, count := int(binary.LittleEndian.Uint16(acl[2:4])), int(binary.LittleEndian.Uint16(acl[4:6]))
			if length < 8 || length > len(acl) || count > (length-8)/8 {
				t.Fatal("Medium startup kernel DACL is malformed")
			}
			acl = acl[:length]
			for index, position := 0, 8; index < count; index++ {
				if position > len(acl)-8 {
					t.Fatal("Medium startup kernel ACE is truncated")
				}
				ace := acl[position:]
				length := int(binary.LittleEndian.Uint16(ace[2:4]))
				if length < 16 || length > len(ace) || binary.LittleEndian.Uint32(ace[4:8])&0xe0000000 != 0 {
					t.Fatal("Medium startup kernel access requires an unsupported generic mapping")
				}
				position += length
			}
		}
		privileges := make([]uint32, 1024)
		size := uint32(len(privileges) * 4)
		var granted, allowed uint32
		ok, _, callErr := functions[2].Call(uintptr(descriptor), uintptr(query), uintptr(wanted), uintptr(unsafe.Pointer(&mapping)),
			uintptr(unsafe.Pointer(&privileges[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&allowed)))
		runtime.KeepAlive(mapping)
		runtime.KeepAlive(privileges)
		if ok == 0 || size > uint32(len(privileges)*4) || allowed > 1 {
			t.Fatal(nativeError("Medium startup native AccessCheck", callErr))
		}
		t.Logf("Actual constructed-Medium startup access: %s desired=0x%x granted=0x%x allowed=%t", name, wanted, granted, allowed == 1)
		if kind == 6 && (allowed != 1 || granted&wanted != wanted) {
			t.Fatal("new Medium fixture process/thread denies its own captured token", name)
		}
	}
	t.Logf("Constructed primary-Medium startup: captured session=%d child=%d; original private desktop ACLs and token authority remain unchanged", session, process.ProcessId)
	fixtureLogMediumDefaultDACL(t, token)
	check("owned-process", process.Process, 6, 0x001fffff, 0x001fffff)
	check("owned-thread", process.Thread, 6, 0x001fffff, 0x001fffff)
	func() {
		image.mu.Lock()
		defer image.mu.Unlock()
		check("captured-executable", image.handles[len(image.handles)-1], 1, 0x001f01ff, 0x001200a9)
	}()
	for _, library := range []string{"ntdll.dll", "kernel32.dll", "KernelBase.dll", "user32.dll", "gdi32.dll", "bcryptprimitives.dll"} {
		name, _ := syscall.UTF16PtrFromString(filepath.Join(api.native.systemDirectory, library))
		handle, err := syscall.CreateFile(name, 0x00020000 /* READ_CONTROL */, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatal("Medium startup system image descriptor capture failed", library, err)
		}
		func() {
			defer func() {
				if err := syscall.CloseHandle(handle); err != nil {
					t.Error(err)
				}
			}()
			check(library, handle, 1, 0x001f01ff, 0x001200a9)
		}()
	}
}

// Supply explicit security only while creating this new same-user process and
// initial thread. The parent's token/default DACL and all existing objects stay
// unchanged. The restricted child still has a Medium primary token, deny-only
// Administrators and no privilege except SeChangeNotify.
// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
func fixtureWithMediumStartupSecurity(api *fixtureRestrictedAPI, sid string, create func(*syscall.SecurityAttributes) error) error {
	parsed, err := syscall.StringToSid(sid)
	if err != nil {
		return err
	}
	canonical, err := parsed.String()
	if err != nil || canonical != sid || create == nil || api == nil || api.native == nil {
		return errors.New("Medium fixture creation has no exact local principal")
	}
	sddl, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")S:(ML;;NW;;;ME)")
	if err != nil {
		return err
	}
	var descriptor unsafe.Pointer
	var size uint32
	ok, _, callErr := api.native.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	if descriptor != nil {
		defer api.native.localFree.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil || size < 20 || size > 65536 {
		return nativeError("new Medium process/thread descriptor", callErr)
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
	err = create(&attributes)
	runtime.KeepAlive(sddl)
	runtime.KeepAlive(parsed)
	runtime.KeepAlive(attributes)
	return err
}

func fixtureLogMediumDefaultDACL(t *testing.T, token syscall.Token) {
	t.Helper()
	identity, _, err := readTokenIdentity(token)
	if err != nil {
		t.Fatal(err)
	}
	user, err := syscall.StringToSid(identity.SID)
	if err != nil {
		t.Fatal(err)
	}
	userBytes := unsafe.Slice((*byte)(unsafe.Pointer(user)), user.Len())
	var size, returned uint32
	err = syscall.GetTokenInformation(token, 6 /* TokenDefaultDacl */, nil, 0, &size)
	if !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) || size < 16 || size > 65536 {
		t.Fatal("Medium default DACL has no bounded readback", err)
	}
	data := make([]byte, size)
	if err := syscall.GetTokenInformation(token, 6, &data[0], size, &returned); err != nil || returned != size {
		t.Fatal("Medium default DACL changed shape", err)
	}
	pointer := *(*unsafe.Pointer)(unsafe.Pointer(&data[0]))
	start, address := uintptr(unsafe.Pointer(&data[0])), uintptr(pointer)
	if pointer == nil || address < start || address-start > uintptr(len(data)-8) {
		t.Fatal("Medium default DACL is outside its captured buffer")
	}
	acl := data[address-start:]
	length, count := int(binary.LittleEndian.Uint16(acl[2:4])), int(binary.LittleEndian.Uint16(acl[4:6]))
	if length < 8 || length > len(acl) || count > (length-8)/8 {
		t.Fatal("Medium default DACL is malformed")
	}
	acl = acl[:length]
	for index, position := 0, 8; index < count; index++ {
		if position > len(acl)-8 {
			t.Fatal("Medium default ACE is truncated")
		}
		ace := acl[position:]
		length := int(binary.LittleEndian.Uint16(ace[2:4]))
		if length < 16 || length > len(ace) {
			t.Fatal("Medium default ACE is malformed")
		}
		ace = ace[:length]
		sid, sidLength, err := systemImageSID(ace, 8)
		if err != nil || sidLength != length-8 {
			t.Fatal("Medium default ACE SID is malformed", err)
		}
		principal := "other"
		if sid.authority == 5 && len(sid.parts) == 1 && sid.parts[0] == 18 {
			principal = "system"
		}
		if sid.authority == 5 && len(sid.parts) == 2 && sid.parts[0] == 32 && sid.parts[1] == 544 {
			principal = "administrators"
		}
		if sid.authority == 5 && len(sid.parts) > 0 && sid.parts[0] == 21 {
			principal = "other-account"
		}
		if bytes.Equal(ace[8:], userBytes) {
			principal = "captured-user"
		}
		if sid.authority == 5 && len(sid.parts) > 0 && sid.parts[0] == 5 {
			principal = "logon"
		}
		t.Logf("Constructed Medium default DACL ACE %d: type=%d flags=0x%x mask=0x%x principal=%s", index, ace[0], ace[1], binary.LittleEndian.Uint32(ace[4:8]), principal)
		position += length
	}
	runtime.KeepAlive(data)
	runtime.KeepAlive(user)
}
