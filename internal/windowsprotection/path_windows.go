//go:build windows

package windowsprotection

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const protectionVolumePrefix = `\\?\Volume{`

type protectionObject struct {
	handle    syscall.Handle
	identity  syscall.ByHandleFileInformation
	path      string
	directory bool
}

func protectionLocalPath(path string) (string, string, error) {
	if !filepath.IsAbs(path) || len(path) > 32760 || strings.ContainsAny(path, "\x00\r\n/") || filepath.Clean(path) != path {
		return "", "", errors.New("protection path is not a canonical local path")
	}
	var root string
	if len(path) >= len(protectionVolumePrefix)+38 && strings.EqualFold(path[:len(protectionVolumePrefix)], protectionVolumePrefix) {
		identifier := path[len(protectionVolumePrefix) : len(protectionVolumePrefix)+36]
		for index, digit := range identifier {
			if index == 8 || index == 13 || index == 18 || index == 23 {
				if digit != '-' {
					return "", "", errors.New("protection volume identity is malformed")
				}
			} else if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f' || digit >= 'A' && digit <= 'F') {
				return "", "", errors.New("protection volume identity is malformed")
			}
		}
		if path[len(protectionVolumePrefix)+36:len(protectionVolumePrefix)+38] != `}\` {
			return "", "", errors.New("protection volume root is malformed")
		}
		root = path[:len(protectionVolumePrefix)+38]
	} else {
		volume := filepath.VolumeName(path)
		if len(volume) != 2 || volume[1] != ':' || !(volume[0] >= 'a' && volume[0] <= 'z' || volume[0] >= 'A' && volume[0] <= 'Z') ||
			len(path) < 3 || path[2] != '\\' {
			return "", "", errors.New("protection path is not on a local Windows volume")
		}
		root = volume + `\`
	}
	if len(path) > len(root) {
		for _, part := range strings.Split(path[len(root):], `\`) {
			if part == "" || part == "." || part == ".." || strings.TrimRight(part, ". ") != part || strings.ContainsAny(part, `:<>"|?*`) {
				return "", "", errors.New("protection path contains an ambiguous component")
			}
		}
	}
	return path, root, nil
}

func protectionObjectIdentity(handle syscall.Handle, directory bool) (syscall.ByHandleFileInformation, error) {
	var actual syscall.ByHandleFileInformation
	if handle == 0 || handle == syscall.InvalidHandle {
		return actual, errors.New("protection object has no retained handle")
	}
	if err := syscall.GetFileInformationByHandle(handle, &actual); err != nil {
		return actual, err
	}
	kind, err := syscall.GetFileType(handle)
	if err != nil || kind != syscall.FILE_TYPE_DISK || actual.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(actual.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) != directory ||
		actual.FileIndexHigh == 0 && actual.FileIndexLow == 0 || !directory && actual.NumberOfLinks != 1 {
		return actual, errors.Join(err, errors.New("protection object is not its retained regular file or directory"))
	}
	return actual, nil
}

func sameProtectionObject(expected, actual syscall.ByHandleFileInformation) bool {
	return expected.VolumeSerialNumber == actual.VolumeSerialNumber && expected.FileIndexHigh == actual.FileIndexHigh &&
		expected.FileIndexLow == actual.FileIndexLow && expected.NumberOfLinks == actual.NumberOfLinks
}

func (file *protectionObject) verify() error {
	if file == nil {
		return errors.New("protection object has no captured lifetime")
	}
	actual, err := protectionObjectIdentity(file.handle, file.directory)
	if err != nil || !sameProtectionObject(file.identity, actual) {
		return errors.Join(err, errors.New("protection object changed its captured file identity"))
	}
	return nil
}

func (file *protectionObject) close() error {
	if file == nil || file.handle == 0 {
		return nil
	}
	if err := syscall.CloseHandle(file.handle); err != nil {
		return err
	}
	file.handle = 0
	return nil
}

func openProtectionObject(path string, directory bool, access, share uint32) (*protectionObject, error) {
	if _, _, err := protectionLocalPath(path); err != nil {
		return nil, err
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, access, share, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	file := &protectionObject{handle: handle, path: path, directory: directory}
	file.identity, err = protectionObjectIdentity(handle, directory)
	if err != nil {
		return file, err // caller retains the partially opened object for Close
	}
	return file, nil
}

func protectionFinalPath(api *protectionNativeAPI, file *protectionObject) (string, error) {
	if err := file.verify(); err != nil {
		return "", err
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := api.finalPath.Call(uintptr(file.handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 1 /* VOLUME_NAME_GUID */)
	runtime.KeepAlive(buffer)
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", fmt.Errorf("resolve protection local volume identity: %w", callErr)
	}
	path, _, err := protectionLocalPath(syscall.UTF16ToString(buffer[:length]))
	if err != nil || !strings.HasPrefix(strings.ToLower(path), strings.ToLower(protectionVolumePrefix)) {
		return "", errors.Join(err, errors.New("protection object has no independent local volume identity"))
	}
	return path, file.verify()
}

// Every ancestor is retained without FILE_SHARE_DELETE. The canonical volume
// ancestry is pinned too: a DOS alias cannot omit a parent or retarget creation.
// Failed opens remain in the returned list so their caller can join cleanup.
func pinProtectionDirectory(api *protectionNativeAPI, path string) ([]*protectionObject, string, error) {
	path, root, err := protectionLocalPath(path)
	if err != nil {
		return nil, "", err
	}
	var pins []*protectionObject
	pin := func(path, root string) error {
		var parts []string
		if len(path) > len(root) {
			parts = strings.Split(path[len(root):], `\`)
		}
		current := root
		for index := -1; index < len(parts); index++ {
			if index >= 0 {
				current = filepath.Join(current, parts[index])
			}
			file, err := openProtectionObject(current, true, protectionReadAttributes|protectionReadControl,
				syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)
			if file != nil {
				pins = append(pins, file)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := pin(path, root); err != nil {
		return pins, "", err
	}
	expected := pins[len(pins)-1].identity
	canonical, err := protectionFinalPath(api, pins[len(pins)-1])
	if err != nil {
		return pins, "", err
	}
	if !strings.EqualFold(path, canonical) {
		_, actualRoot, err := protectionLocalPath(canonical)
		if err != nil {
			return pins, "", err
		}
		if err := pin(canonical, actualRoot); err != nil {
			return pins, "", err
		}
	}
	if !sameProtectionObject(expected, pins[len(pins)-1].identity) {
		return pins, "", errors.New("protection directory changed while resolving its volume identity")
	}
	return pins, canonical, nil
}

func createProtectionDirectory(api *protectionNativeAPI, path string) (_ *protectionObject, failure error) {
	security, err := newProtectionSecurity(api, true)
	if err != nil {
		return nil, err
	}
	defer func() { failure = errors.Join(failure, security.close()) }()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(security.descriptor)}
	ok, _, callErr := api.createDirectory.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&attributes)))
	runtime.KeepAlive(security)
	runtime.KeepAlive(name)
	if ok == 0 && !errors.Is(callErr, syscall.ERROR_ALREADY_EXISTS) {
		return nil, fmt.Errorf("create protected administrative directory: %w", callErr)
	}
	file, err := openProtectionObject(path, true, protectionReadAttributes|protectionReadControl,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)
	if err != nil {
		return file, err
	}
	// Existing directories must already satisfy the exact trusted policy.
	// Hardening an untrusted object now would not authenticate its history.
	if err := verifyProtectionSecurity(api, file.handle, true); err != nil {
		return file, err
	}
	return file, file.verify()
}

func createProtectionFile(api *protectionNativeAPI, path string, deleteOnClose bool) (_ *protectionObject, failure error) {
	security, err := newProtectionSecurity(api, false)
	if err != nil {
		return nil, err
	}
	defer func() { failure = errors.Join(failure, security.close()) }()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if deleteOnClose {
		flags |= protectionDeleteOnClose
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(security.descriptor)}
	// CREATE_NEW never adopts a preexisting lock or recovery record. Share=0
	// denies other data writers/readers and every rename/deletion of this leaf.
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE|protectionReadControl|protectionDelete,
		0, &attributes, syscall.CREATE_NEW, flags, 0)
	runtime.KeepAlive(security)
	if err != nil {
		return nil, err
	}
	file := &protectionObject{handle: handle, path: path}
	file.identity, err = protectionObjectIdentity(handle, false)
	if err == nil {
		err = verifyProtectionSecurity(api, handle, false)
	}
	return file, err
}
