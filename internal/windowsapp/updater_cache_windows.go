//go:build windows

package windowsapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"router-vpn/internal/updatepolicy"
)

// capturedUpdateCache retains the actual local-volume ancestry while the
// original-user updater Job can write here. Directory handles request metadata
// plus FILE_LIST_DIRECTORY, which makes Windows enforce the non-delete share.
// They never request DELETE, and allow normal Go/.NET readers and atomic file
// replacement inside the captured directory.
type capturedUpdateCache struct {
	mu      sync.Mutex
	path    string
	desktop string
	api     *portableNativeAPI
	handles []syscall.Handle
	root    syscall.Handle
	closed  bool
}

func captureUpdateCache(ctx context.Context, base string, components []string, desktop string) (_ *capturedUpdateCache, failure error) {
	cache := &capturedUpdateCache{desktop: desktop}
	if ctx == nil || ctx.Err() != nil || desktop == "" || len(components) == 0 || len(components) > 2 {
		return cache, errors.New("the updater cache has no captured original-user operation")
	}
	var err error
	cache.api, err = portableNative()
	if err != nil {
		return cache, err
	}
	last, err := cache.pinDirectories(base)
	if err != nil {
		return cache, err
	}
	before, err := updateObjectIdentity(last, true)
	if err != nil {
		return cache, err
	}
	canonical, err := cache.finalDirectory(last)
	if err != nil {
		return cache, err
	}
	if !strings.EqualFold(base, canonical) {
		last, err = cache.pinDirectories(canonical)
		if err != nil {
			return cache, err
		}
	}
	after, err := updateObjectIdentity(last, true)
	if err != nil || !updateSameIdentity(before, after) {
		return cache, errors.Join(err, errors.New("the updater base changed while capturing its local volume ancestry"))
	}
	if err := cache.validateSecurity(last, false); err != nil {
		return cache, fmt.Errorf("the updater base has an untrusted writer: %w", err)
	}
	cache.path = canonical
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.ContainsAny(component, `\/:`+"\x00\r\n") || strings.TrimRight(component, ". ") != component {
			return cache, errors.New("the updater cache component is not fixed local data")
		}
		if err := ctx.Err(); err != nil {
			return cache, err
		}
		cache.path = filepath.Join(cache.path, component)
		if err := cache.createPrivateDirectory(cache.path); err != nil {
			return cache, err
		}
		last, err = updateOpenMetadata(cache.path, true, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)
		if err != nil {
			return cache, err
		}
		cache.handles = append(cache.handles, last)
		if _, err := updateObjectIdentity(last, true); err != nil {
			return cache, err
		}
		if err := cache.validateSecurity(last, true); err != nil {
			return cache, fmt.Errorf("the updater cache is not private; existing permissions were preserved: %w", err)
		}
		actual, err := cache.finalDirectory(last)
		if err != nil || !strings.EqualFold(actual, cache.path) {
			return cache, errors.Join(err, errors.New("the updater cache differs from its retained local parent"))
		}
	}
	cache.root = last
	if err := cache.validateContents(); err != nil {
		return cache, err
	}
	return cache, ctx.Err()
}

func (cache *capturedUpdateCache) createPrivateDirectory(path string) (failure error) {
	security, err := portableDescriptor(cache.api, cache.desktop, true)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, security.close()) }()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(security.descriptor)}
	ok, _, callErr := cache.api.createDirectory.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&attributes)))
	runtime.KeepAlive(security)
	runtime.KeepAlive(name)
	if ok == 0 && !errors.Is(callErr, syscall.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create original-user update cache: %w", callErr)
	}
	// An existing object is inspected through a retained handle. Never apply a
	// replacement DACL or recurse through an existing caller's contents.
	return nil
}

func (cache *capturedUpdateCache) validateSecurity(handle syscall.Handle, private bool) (failure error) {
	security := &portableSecurity{api: cache.api}
	status, _, _ := cache.api.get.Call(uintptr(handle), 1, 1|4, 0, 0, 0, 0, uintptr(unsafe.Pointer(&security.descriptor)))
	defer func() { failure = errors.Join(failure, security.close()) }()
	if status != 0 || security.descriptor == nil {
		return fmt.Errorf("read retained update-cache security: %w", syscall.Errno(status))
	}
	owner, _, grants, err := security.inspect()
	if err != nil {
		return err
	}
	if private {
		return validatePortablePrivateGrants(owner, cache.desktop, grants)
	}
	return validatePortablePackageGrants(owner, cache.desktop, grants)
}

func (cache *capturedUpdateCache) pinDirectories(path string) (syscall.Handle, error) {
	parts, err := updateDirectoryPrefixes(path)
	if err != nil {
		return 0, err
	}
	var last syscall.Handle
	for _, part := range parts {
		last, err = updateOpenMetadata(part, true, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)
		if err != nil {
			return 0, err
		}
		cache.handles = append(cache.handles, last)
		if _, err := updateObjectIdentity(last, true); err != nil {
			return 0, err
		}
	}
	return last, nil
}

func updateDirectoryPrefixes(path string) ([]string, error) {
	if path == "" || len(path) > 32760 || strings.ContainsAny(path, "\x00\r\n/") || filepath.Clean(path) != path {
		return nil, errors.New("the updater cache path is not bounded and unambiguous")
	}
	var root string
	const prefix = `\\?\Volume{`
	if len(path) >= len(prefix)+38 && strings.EqualFold(path[:len(prefix)], prefix) && path[len(prefix)+36:len(prefix)+38] == `}\` {
		for index, value := range path[len(prefix) : len(prefix)+36] {
			if index == 8 || index == 13 || index == 18 || index == 23 {
				if value != '-' {
					return nil, errors.New("the updater volume identity is invalid")
				}
			} else if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F') {
				return nil, errors.New("the updater volume identity is invalid")
			}
		}
		root = path[:len(prefix)+38]
	} else if len(path) >= 3 && path[1:3] == `:\` && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z') {
		root = path[:3]
	} else {
		return nil, errors.New("the updater cache requires a captured local volume")
	}
	if len(path) == len(root) {
		return []string{root}, nil
	}
	parts := []string{root}
	current := root
	for _, part := range strings.Split(path[len(root):], `\`) {
		if part == "" || strings.TrimRight(part, ". ") != part || strings.ContainsAny(part, ":*?<>|\"") {
			return nil, errors.New("the updater cache path contains an ambiguous component")
		}
		current = filepath.Join(current, part)
		parts = append(parts, current)
	}
	return parts, nil
}

func updateOpenMetadata(path string, directory bool, share uint32) (syscall.Handle, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	access := uint32(0x00020000 | 0x80) // READ_CONTROL | FILE_READ_ATTRIBUTES
	if directory {
		access |= 1 // FILE_LIST_DIRECTORY: metadata-only access does not deny rename.
	}
	handle, err := syscall.CreateFile(name, access,
		share, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

func updateObjectIdentity(handle syscall.Handle, directory bool) (syscall.ByHandleFileInformation, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return info, err
	}
	kind, err := syscall.GetFileType(handle)
	if err != nil || kind != syscall.FILE_TYPE_DISK || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) != directory ||
		!directory && info.NumberOfLinks != 1 || info.FileIndexHigh == 0 && info.FileIndexLow == 0 {
		return info, errors.Join(err, errors.New("the updater cache contains a link or nonregular filesystem object"))
	}
	return info, nil
}

func updateSameIdentity(a, b syscall.ByHandleFileInformation) bool {
	return a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow
}

func (cache *capturedUpdateCache) finalDirectory(handle syscall.Handle) (string, error) {
	procedure, err := cache.api.createDirectory.Dll.FindProc("GetFinalPathNameByHandleW")
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := procedure.Call(uintptr(handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 1 /* VOLUME_NAME_GUID */)
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", fmt.Errorf("the updater cache has no stable local volume path: %w", callErr)
	}
	path := syscall.UTF16ToString(buffer[:length])
	runtime.KeepAlive(buffer)
	if !strings.HasPrefix(strings.ToLower(path), `\\?\volume{`) {
		return "", errors.New("the updater cache resolved outside a local volume")
	}
	if _, err := updateDirectoryPrefixes(path); err != nil {
		return "", err
	}
	return path, nil
}

func (cache *capturedUpdateCache) validateContents() (failure error) {
	directory, err := os.Open(cache.path)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, directory.Close()) }()
	actual, err := updateObjectIdentity(syscall.Handle(directory.Fd()), true)
	expected, identityErr := updateObjectIdentity(cache.root, true)
	if err != nil || identityErr != nil || !updateSameIdentity(actual, expected) {
		return errors.Join(err, identityErr, errors.New("the update cache changed before inspecting its contents"))
	}
	entries, err := directory.Readdir(4097)
	if err != nil && err != io.EOF || len(entries) > 4096 {
		return errors.Join(err, errors.New("the update cache content count is unbounded"))
	}
	for _, entry := range entries {
		if !updateCacheFilename(entry.Name()) || !entry.Mode().IsRegular() || entry.Size() < 0 || entry.Size() > updatepolicy.MaxArtifactBytes {
			return errors.New("the updater cache contains a foreign or unsupported existing object")
		}
		handle, err := updateOpenMetadata(filepath.Join(cache.path, entry.Name()), false,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
		if err != nil {
			return err
		}
		_, identityErr := updateObjectIdentity(handle, false)
		securityErr := cache.validateSecurity(handle, true)
		closeErr := syscall.CloseHandle(handle)
		if closeErr != nil {
			cache.handles = append(cache.handles, handle)
		}
		if err := errors.Join(identityErr, securityErr, closeErr); err != nil {
			return fmt.Errorf("the updater cache contains foreign private state; it was preserved: %w", err)
		}
	}
	return nil
}

func (cache *capturedUpdateCache) Verify() error {
	if cache == nil {
		return errors.New("the updater cache owner is absent")
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.closed || cache.root == 0 {
		return errors.New("the updater cache owner is closed or incomplete")
	}
	if _, err := updateObjectIdentity(cache.root, true); err != nil {
		return err
	}
	if err := cache.validateSecurity(cache.root, true); err != nil {
		return err
	}
	return cache.validateContents()
}

func (cache *capturedUpdateCache) Path() string {
	if cache == nil {
		return ""
	}
	return cache.path
}

func (cache *capturedUpdateCache) Close() error {
	if cache == nil {
		return nil
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.closed = true
	var result error
	for index := len(cache.handles) - 1; index >= 0; index-- {
		if cache.handles[index] != 0 {
			err := syscall.CloseHandle(cache.handles[index])
			result = errors.Join(result, err)
			if err == nil {
				cache.handles[index] = 0
			}
		}
	}
	return result
}
