//go:build windows

package windowscontroller

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type protectedShellAPI struct {
	openDirectory, openLink, queryLink, compare, security *syscall.Proc
}

var protectedShellOnce struct {
	sync.Once
	api *protectedShellAPI
	err error
}

func protectedShellNative() (*protectedShellAPI, error) {
	protectedShellOnce.Do(func() {
		api, err := native()
		if err != nil {
			protectedShellOnce.err = err
			return
		}
		value := &protectedShellAPI{}
		var loaded []*syscall.DLL
		for _, library := range []struct {
			name  string
			procs map[string]**syscall.Proc
		}{
			{"ntdll.dll", map[string]**syscall.Proc{
				"NtOpenDirectoryObject": &value.openDirectory, "NtOpenSymbolicLinkObject": &value.openLink,
				"NtQuerySymbolicLinkObject": &value.queryLink,
			}},
			{"kernelbase.dll", map[string]**syscall.Proc{"CompareObjectHandles": &value.compare}},
			{"advapi32.dll", map[string]**syscall.Proc{"GetKernelObjectSecurity": &value.security}},
		} {
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
				protectedShellOnce.err = err
				return
			}
		}
		// Published functions retain these exact system modules for process
		// lifetime, matching the existing native API owner.
		protectedShellOnce.api = value
	})
	return protectedShellOnce.api, protectedShellOnce.err
}

type protectedShellUnicode struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

type protectedShellAttributes struct {
	Length                     uint32
	Root                       syscall.Handle
	Name                       *protectedShellUnicode
	Flags                      uint32
	Security, QualityOfService uintptr
}

func (api *protectedShellAPI) open(name string, directory bool) (syscall.Handle, error) {
	encoded, err := syscall.UTF16FromString(name)
	if err != nil || len(encoded) < 2 || len(encoded) > 32767 {
		return 0, errors.Join(err, errors.New("protected Shell namespace name is unbounded"))
	}
	value := protectedShellUnicode{uint16((len(encoded) - 1) * 2), uint16(len(encoded) * 2), &encoded[0]}
	attributes := protectedShellAttributes{Name: &value, Flags: 0x40 /* OBJ_CASE_INSENSITIVE */}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	if unsafe.Sizeof(value) != 16 || attributes.Length != 48 {
		return 0, errors.New("protected Shell namespace ABI changed")
	}
	procedure, access := api.openLink, uintptr(0x00020001) // READ_CONTROL | SYMBOLIC_LINK_QUERY.
	if directory {
		procedure, access = api.openDirectory, 0x00020003 // READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE.
	}
	var handle syscall.Handle
	status, _, _ := procedure.Call(uintptr(unsafe.Pointer(&handle)), access, uintptr(unsafe.Pointer(&attributes)))
	runtime.KeepAlive(encoded)
	runtime.KeepAlive(value)
	runtime.KeepAlive(attributes)
	if uint32(status) != 0 || handle == 0 || handle == syscall.InvalidHandle {
		if handle == syscall.InvalidHandle {
			handle = 0
		}
		return handle, fmt.Errorf("protected Shell namespace %q open failed (NTSTATUS=0x%08x)", name, uint32(status))
	}
	return handle, nil
}

func (api *protectedShellAPI) target(handle syscall.Handle) (string, error) {
	buffer := make([]uint16, 32767)
	value := protectedShellUnicode{MaximumLength: uint16(len(buffer) * 2), Buffer: &buffer[0]}
	var returned uint32
	status, _, _ := api.queryLink.Call(uintptr(handle), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&returned)))
	if uint32(status) != 0 || value.Length == 0 || value.Length%2 != 0 || value.Length > value.MaximumLength || returned > uint32(value.MaximumLength) {
		return "", fmt.Errorf("protected Shell mapping query failed (NTSTATUS=0x%08x)", uint32(status))
	}
	result := syscall.UTF16ToString(buffer[:value.Length/2])
	runtime.KeepAlive(buffer)
	return result, nil
}

func (api *protectedShellAPI) protect(handle syscall.Handle, directory bool) error {
	var length uint32
	ok, _, callErr := api.security.Call(uintptr(handle), 1|4 /* OWNER | DACL */, 0, 0, uintptr(unsafe.Pointer(&length)))
	if ok != 0 || !errors.Is(callErr, syscall.ERROR_INSUFFICIENT_BUFFER) || length < 20 || length > 1<<20 {
		return errors.Join(nativeError("protected Shell descriptor bound", callErr), errors.New("protected Shell namespace has no bounded security descriptor"))
	}
	data := make([]byte, length)
	var returned uint32
	ok, _, callErr = api.security.Call(uintptr(handle), 1|4, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&returned)))
	if ok == 0 || returned != length {
		return nativeError("protected Shell descriptor readback", callErr)
	}
	return validateProtectedShellDescriptor(data, directory)
}

func (api *protectedShellAPI) sameMapping(global, effective syscall.Handle) error {
	same, _, callErr := api.compare.Call(uintptr(global), uintptr(effective))
	if same == 0 {
		return errors.Join(callErr, errors.New("effective Shell drive is not the captured global mapping object"))
	}
	return nil
}

// ProtectedShellImage retains both the actual executable ancestry and its
// protected global drive mapping. It is a captured name capability, not a
// launch operation or evidence of interactive/cross-account UAC acceptance.
type ProtectedShellImage struct {
	mu       sync.Mutex
	image    *Image
	path     string
	volume   string
	identity TokenIdentity
	handles  []syscall.Handle // Object Manager root, global directory, global link, effective link, global file.
	closed   bool
}

func protectedShellIdentity(api *nativeAPI) (TokenIdentity, error) {
	var token syscall.Token
	ok, _, callErr := api.threadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&token)))
	if token != 0 {
		_ = token.Close()
	}
	if ok != 0 || token != 0 || !errors.Is(callErr, syscall.Errno(1008) /* ERROR_NO_TOKEN */) {
		return TokenIdentity{}, errors.New("protected Shell capture requires the original process namespace, without impersonation")
	}
	return CurrentIdentity()
}

// PinProtectedShellImage derives its DOS spelling from the held image and
// proves that spelling through the protected global namespace. Per-logon DOS
// aliases do not acquire this capability, even if they reach identical bytes.
// A non-nil result accompanying an error retains cleanup ownership.
func PinProtectedShellImage(image *Image) (*ProtectedShellImage, error) {
	api, err := native()
	if err != nil || image == nil {
		return nil, errors.Join(err, errors.New("protected Shell capture has no retained image"))
	}
	image.mu.Lock()
	defer image.mu.Unlock()
	if image.closed || len(image.handles) == 0 {
		return nil, ErrClosed
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := api.finalPath.Call(uintptr(image.handles[len(image.handles)-1]), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0 /* VOLUME_NAME_DOS */)
	if length == 0 || length >= uintptr(len(buffer)) {
		return nil, nativeError("protected Shell image spelling", callErr)
	}
	path := strings.TrimPrefix(syscall.UTF16ToString(buffer[:length]), `\\?\`)
	return pinProtectedShellImageLocked(api, image, path)
}

func pinProtectedShellImageLocked(api *nativeAPI, image *Image, path string) (*ProtectedShellImage, error) {
	if api == nil || image == nil || image.closed || len(image.handles) == 0 {
		return nil, ErrClosed
	}
	checked, err := localExecutablePath(path)
	if err != nil || len(checked) < 4 || checked[1:3] != `:\` {
		return nil, errors.Join(err, errors.New("protected Shell capture requires a local drive spelling"))
	}
	identity, err := protectedShellIdentity(api)
	if err != nil {
		return nil, err
	}
	namespace, err := protectedShellNative()
	if err != nil {
		return nil, err
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	capture := &ProtectedShellImage{path: checked, identity: identity,
		image: &Image{path: image.path, identity: image.identity, systemPowerShell: image.systemPowerShell}}
	reject := func(cause error) (*ProtectedShellImage, error) {
		if err := capture.Close(); err != nil {
			return capture, errors.Join(cause, err)
		}
		return nil, cause
	}
	for _, handle := range image.handles {
		var duplicate syscall.Handle
		if err := syscall.DuplicateHandle(current, handle, current, &duplicate, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			return reject(err)
		}
		capture.image.handles = append(capture.image.handles, duplicate)
	}
	for index, name := range []string{`\`, `\GLOBAL??`, `\GLOBAL??\` + checked[:2], `\??\` + checked[:2]} {
		directory := index < 2
		handle, err := namespace.open(name, directory)
		if handle != 0 {
			capture.handles = append(capture.handles, handle)
		}
		if err != nil {
			return reject(err)
		}
		if index < 3 {
			if err := namespace.protect(handle, directory); err != nil {
				return reject(fmt.Errorf("protected Shell namespace %q: %w", name, err))
			}
		}
	}
	if err := namespace.sameMapping(capture.handles[2], capture.handles[3]); err != nil {
		return reject(err)
	}
	volume, err := namespace.target(capture.handles[2])
	device, local := strings.CutPrefix(volume, `\Device\`)
	if err != nil || !local || device == "" || strings.ContainsAny(device, `\/:`+"\x00") || strings.TrimRight(device, ". ") != device {
		return reject(errors.Join(err, errors.New("protected Shell mapping is not a direct local volume")))
	}
	capture.volume = volume
	globalName, _ := syscall.UTF16PtrFromString(`\\?\GLOBALROOT\GLOBAL??\` + checked)
	handle, err := syscall.CreateFile(globalName, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000, 0)
	if err != nil {
		return reject(nativeError("protected global Shell file", err))
	}
	capture.handles = append(capture.handles, handle)
	if err := capture.verifyLocked(api, namespace); err != nil {
		return reject(err)
	}
	return capture, nil
}

func (capture *ProtectedShellImage) verifyLocked(api *nativeAPI, namespace *protectedShellAPI) error {
	if capture.closed || capture.image == nil || len(capture.handles) != 5 || len(capture.image.handles) == 0 {
		return ErrClosed
	}
	identity, err := protectedShellIdentity(api)
	if err != nil || identity != capture.identity {
		return errors.Join(err, errors.New("protected Shell capture changed its original process identity"))
	}
	for index := 0; index < 3; index++ {
		if err := namespace.protect(capture.handles[index], index < 2); err != nil {
			return err
		}
	}
	for _, name := range []string{`\GLOBAL??\` + capture.path[:2], `\??\` + capture.path[:2]} {
		handle, err := namespace.open(name, false)
		if err != nil {
			if handle != 0 {
				capture.handles = append(capture.handles, handle)
			}
			return err
		}
		proofErr := namespace.sameMapping(capture.handles[2], handle)
		closeErr := syscall.CloseHandle(handle)
		if closeErr != nil {
			capture.handles = append(capture.handles, handle)
		}
		if proofErr != nil || closeErr != nil {
			return errors.Join(proofErr, closeErr)
		}
	}
	volume, err := namespace.target(capture.handles[2])
	if err != nil || !strings.EqualFold(volume, capture.volume) {
		return errors.Join(err, errors.New("protected global Shell volume changed"))
	}
	buffer := make([]uint16, 32768)
	for _, handle := range []syscall.Handle{capture.handles[4], capture.image.handles[len(capture.image.handles)-1]} {
		var actual syscall.ByHandleFileInformation
		if err := syscall.GetFileInformationByHandle(handle, &actual); err != nil {
			return err
		}
		want := capture.image.identity
		if actual.FileAttributes&(0x400|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 || want.NumberOfLinks == 0 || actual.NumberOfLinks != want.NumberOfLinks ||
			actual.VolumeSerialNumber != want.VolumeSerialNumber || actual.FileIndexHigh != want.FileIndexHigh || actual.FileIndexLow != want.FileIndexLow {
			return errors.New("protected global Shell path selected another retained executable")
		}
		length, _, callErr := api.finalPath.Call(uintptr(handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 2 /* VOLUME_NAME_NT */)
		if length == 0 || length >= uintptr(len(buffer)) || !strings.EqualFold(syscall.UTF16ToString(buffer[:length]), capture.volume+capture.path[2:]) {
			return errors.Join(callErr, errors.New("protected Shell native image path differs from its global mapping"))
		}
		length, _, callErr = api.finalPath.Call(uintptr(handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 1 /* VOLUME_NAME_GUID */)
		if length == 0 || length >= uintptr(len(buffer)) || !strings.EqualFold(syscall.UTF16ToString(buffer[:length]), capture.image.path) {
			return errors.Join(callErr, errors.New("protected Shell native image lost its captured volume identity"))
		}
	}
	runtime.KeepAlive(buffer)
	return nil
}

// Verify independently rereads the still-retained mapping, protection, original
// process namespace and file identity. A stale capture is never refreshed by
// choosing a different mapping or opening a replacement executable.
func (capture *ProtectedShellImage) Verify() error {
	if capture == nil {
		return ErrClosed
	}
	api, err := native()
	if err != nil {
		return err
	}
	namespace, err := protectedShellNative()
	if err != nil {
		return err
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.verifyLocked(api, namespace)
}

func (capture *ProtectedShellImage) Close() error {
	if capture == nil {
		return nil
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.closed = true
	var result error
	for index := len(capture.handles) - 1; index >= 0; index-- {
		if capture.handles[index] != 0 {
			err := syscall.CloseHandle(capture.handles[index])
			result = errors.Join(result, err)
			if err == nil {
				capture.handles[index] = 0
			}
		}
	}
	return errors.Join(result, capture.image.Close())
}
