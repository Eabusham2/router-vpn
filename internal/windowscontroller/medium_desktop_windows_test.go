//go:build windows

package windowscontroller

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// Only the already captured private helper may temporarily select a window
// station. Its own new noninteractive objects carry an explicit same-user ACL
// and Medium label; no host window station, desktop or token is modified.
func fixturePrivateMediumDesktop(t *testing.T, api *fixtureRestrictedAPI) string {
	t.Helper()
	if os.Getenv(fixtureMediumStationEnvironment) != t.Name() || os.Getenv(fixtureMediumWorkerEnvironment) != "" {
		t.Fatal("private Medium desktop creation requires its isolated helper")
	}
	identity, err := CurrentIdentity()
	if err != nil || !identity.Primary || !identity.Elevated || !identity.Administrator {
		t.Fatal("private Medium desktop helper lost its captured primary authority", err)
	}
	dll, err := syscall.LoadDLL(filepath.Join(api.native.systemDirectory, "user32.dll"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dll.Release(); err != nil {
			t.Error(err)
		}
	})
	names := []string{"CreateWindowStationW", "CloseWindowStation", "GetProcessWindowStation", "SetProcessWindowStation", "CreateDesktopW", "CloseDesktop", "GetThreadDesktop", "SetThreadDesktop", "GetUserObjectSecurity"}
	procedures := make([]*syscall.Proc, len(names))
	for index, name := range names {
		procedures[index], err = dll.FindProc(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	threadID, err := api.native.event.Dll.FindProc("GetCurrentThreadId")
	if err != nil {
		t.Fatal(err)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	stationName := "RouterVPN-Medium-" + hex.EncodeToString(random[:])
	stationText, _ := syscall.UTF16PtrFromString(stationName)
	desktopText, _ := syscall.UTF16PtrFromString("default")
	sddl, _ := syscall.UTF16PtrFromString("O:" + identity.SID + "D:P(A;;GA;;;SY)(A;;GA;;;" + identity.SID + ")S:(ML;;NW;;;ME)")
	var descriptor unsafe.Pointer
	var size uint32
	ok, _, callErr := api.native.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(sddl)
	if descriptor != nil {
		defer api.native.localFree.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil || size < 20 || size > 65536 {
		t.Fatal(nativeError("private Medium USER object descriptor", callErr))
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
	var station, desktop uintptr
	t.Cleanup(func() {
		if desktop != 0 {
			if ok, _, err := procedures[5].Call(desktop); ok == 0 {
				t.Error(nativeError("private Medium desktop close", err))
			}
		}
		if station != 0 {
			if ok, _, err := procedures[1].Call(station); ok == 0 {
				t.Error(nativeError("private Medium window station close", err))
			}
		}
	})
	runtime.LockOSThread()
	restored := false
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
	}()
	originalStation, _, stationErr := procedures[2].Call()
	tid, _, tidErr := threadID.Call()
	originalDesktop, _, desktopErr := procedures[6].Call(tid)
	if originalStation == 0 || tid == 0 || originalDesktop == 0 {
		restored = true // No selection-changing operation has been attempted.
		t.Fatal("private desktop helper cannot retain its original USER objects", stationErr, tidErr, desktopErr)
	}
	defer func() {
		stationOK, _, stationErr := procedures[3].Call(originalStation)
		desktopOK, _, desktopErr := procedures[7].Call(originalDesktop)
		stationAfter, _, stationReadErr := procedures[2].Call()
		desktopAfter, _, desktopReadErr := procedures[6].Call(tid)
		restored = stationOK != 0 && desktopOK != 0 && stationAfter == originalStation && desktopAfter == originalDesktop
		if !restored {
			t.Error("isolated desktop helper did not independently restore its USER object selection", stationErr, desktopErr, stationReadErr, desktopReadErr)
		}
	}()
	station, _, callErr = procedures[0].Call(uintptr(unsafe.Pointer(stationText)), 1 /* CWF_CREATE_ONLY */, 0x000f037f /* WINSTA_ALL_ACCESS */, uintptr(unsafe.Pointer(&attributes)))
	runtime.KeepAlive(stationText)
	if station == 0 {
		t.Fatal(nativeError("create owned noninteractive Medium window station", callErr))
	}
	ok, _, callErr = procedures[3].Call(station)
	if ok == 0 {
		t.Fatal(nativeError("select only the private helper's window station", callErr))
	}
	desktop, _, callErr = procedures[4].Call(uintptr(unsafe.Pointer(desktopText)), 0, 0, 0, 0x000f01ff /* DESKTOP_ALL_ACCESS */, uintptr(unsafe.Pointer(&attributes)))
	runtime.KeepAlive(desktopText)
	runtime.KeepAlive(attributes)
	if desktop == 0 {
		t.Fatal(nativeError("create owned noninteractive Medium desktop", callErr))
	}
	fixtureVerifyMediumUserObject(t, procedures[8], station, identity.SID, 0x000f037f)
	fixtureVerifyMediumUserObject(t, procedures[8], desktop, identity.SID, 0x000f01ff)
	return stationName + `\default`
}

func fixtureVerifyMediumUserObject(t *testing.T, read *syscall.Proc, handle uintptr, owner string, all uint32) {
	t.Helper()
	information := uint32(1 | 4 | 0x10) // OWNER | DACL | LABEL_SECURITY_INFORMATION.
	var size uint32
	ok, _, callErr := read.Call(handle, uintptr(unsafe.Pointer(&information)), 0, 0, uintptr(unsafe.Pointer(&size)))
	if ok != 0 || !errors.Is(callErr, syscall.ERROR_INSUFFICIENT_BUFFER) || size < 20 || size > 65536 {
		t.Fatal("private USER object has no bounded security readback", callErr)
	}
	data := make([]byte, size)
	var returned uint32
	ok, _, callErr = read.Call(handle, uintptr(unsafe.Pointer(&information)), uintptr(unsafe.Pointer(&data[0])), uintptr(size), uintptr(unsafe.Pointer(&returned)))
	if ok == 0 || returned != size || data[0] != 1 || binary.LittleEndian.Uint16(data[2:4])&0x9014 != 0x9014 {
		t.Fatal("private USER object lost its explicit descriptor", callErr)
	}
	wanted, err := syscall.StringToSid(owner)
	if err != nil {
		t.Fatal(err)
	}
	wantedBytes := unsafe.Slice((*byte)(unsafe.Pointer(wanted)), wanted.Len())
	offset := int(binary.LittleEndian.Uint32(data[4:8]))
	_, length, err := systemImageSID(data, offset)
	if err != nil || !bytes.Equal(data[offset:offset+length], wantedBytes) {
		t.Fatal("private USER object changed its captured owner", err)
	}
	for _, section := range []struct {
		offset int
		label  bool
	}{{12, true}, {16, false}} {
		start := int(binary.LittleEndian.Uint32(data[section.offset : section.offset+4]))
		if start < 20 || start > len(data)-8 {
			t.Fatal("private USER ACL is outside its captured descriptor")
		}
		acl := data[start:]
		size, count := int(binary.LittleEndian.Uint16(acl[2:4])), int(binary.LittleEndian.Uint16(acl[4:6]))
		if acl[0] != 2 || size < 8 || size > len(acl) || section.label && count != 1 || !section.label && count != 2 {
			t.Fatal("private USER ACL has unexpected entries")
		}
		acl = acl[:size]
		seen := make(map[string]bool)
		position := 8
		for index := 0; index < count; index++ {
			if position > len(acl)-8 {
				t.Fatal("private USER ACL is truncated")
			}
			ace := acl[position:]
			length := int(binary.LittleEndian.Uint16(ace[2:4]))
			if length < 16 || length > len(ace) || ace[1] != 0 {
				t.Fatal("private USER ACE is malformed")
			}
			ace = ace[:length]
			sid, sidLength, err := systemImageSID(ace, 8)
			if err != nil || sidLength != length-8 {
				t.Fatal("private USER ACE has an invalid SID", err)
			}
			mask := binary.LittleEndian.Uint32(ace[4:8])
			if section.label {
				if ace[0] != 17 || mask != 1 || sid.authority != 16 || len(sid.parts) != 1 || sid.parts[0] != 8192 {
					t.Fatal("private USER object did not retain its Medium no-write-up label")
				}
			} else {
				principal := ""
				if sid.authority == 5 && len(sid.parts) == 1 && sid.parts[0] == 18 {
					principal = "system"
				}
				if bytes.Equal(ace[8:], wantedBytes) {
					principal = "owner"
				}
				if ace[0] != 0 || mask != all && mask != 0x10000000 || principal == "" || seen[principal] {
					t.Fatal("private USER object admitted an unexpected access principal")
				}
				seen[principal] = true
			}
			position += length
		}
		if position != len(acl) {
			t.Fatal("private USER ACL has trailing data")
		}
	}
	runtime.KeepAlive(wanted)
}
