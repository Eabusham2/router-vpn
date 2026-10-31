//go:build windows

package windowscontroller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// The elevated Go compiler's TEMP image need not be readable by a restricted
// Medium primary token. Create a separate fixture with explicit read/execute
// access for that captured user. Never change the build image, its ancestors,
// the host's ACLs or the production PinCurrentImage/PinProtectedShellImage path.
type fixtureMediumImage struct {
	image         *Image
	file, dir     syscall.Handle
	native        *nativeAPI
	dispose       *syscall.Proc
	retiringWrite syscall.Handle
	removal       syscall.Handle
	removalTarget syscall.Handle
	deleteMarked  bool
}

func fixtureCaptureMediumImage(api *fixtureRestrictedAPI, source *Image, sid string) (_ *fixtureMediumImage, resultErr error) {
	owner := &fixtureMediumImage{native: api.native}
	var err error
	owner.dispose, err = api.native.event.Dll.FindProc("SetFileInformationByHandle")
	if err != nil {
		return owner, err
	}
	paths, err := MachineDirectories()
	if err != nil {
		return owner, err
	}
	parsed, err := syscall.StringToSid(sid)
	if err != nil {
		return owner, err
	}
	canonical, err := parsed.String()
	if err != nil || canonical != sid || sid == "S-1-5-18" {
		return owner, errors.New("private Medium image has no captured ordinary principal")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return owner, err
	}
	directory := filepath.Join(paths.ProgramData, "RouterVPN-Medium-Fixture-"+hex.EncodeToString(random[:]))
	path := filepath.Join(directory, "controller.test.exe")
	// Only new objects receive this descriptor. The worker can read/execute;
	// System and Administrators retain fixture creation and cleanup rights.
	sddl, _ := syscall.UTF16PtrFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;" + sid + ")S:(ML;;NW;;;ME)")
	var descriptor unsafe.Pointer
	var size uint32
	ok, _, callErr := api.native.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(sddl)
	if descriptor != nil {
		defer api.native.localFree.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil || size < 20 || size > 65536 {
		return owner, nativeError("new private Medium image descriptor", callErr)
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
	dirName, _ := syscall.UTF16PtrFromString(directory)
	if err := syscall.CreateDirectory(dirName, &attributes); err != nil {
		return owner, err // An existing directory is never adopted or removed.
	}
	owner.dir, err = syscall.CreateFile(dirName, 0x00020081, /* READ_CONTROL | READ_ATTRIBUTES | LIST_DIRECTORY */
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING,
		0x02200000 /* BACKUP_SEMANTICS | OPEN_REPARSE_POINT */, 0)
	if err != nil {
		owner.dir = 0
		return owner, errors.Join(err, errors.New("new Medium directory could not retain cleanup authority"))
	}
	fileName, _ := syscall.UTF16PtrFromString(path)
	owner.file, err = syscall.CreateFile(fileName, syscall.GENERIC_READ|syscall.GENERIC_WRITE|0x00010000, /* DELETE */
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, &attributes, syscall.CREATE_NEW,
		0x00200000 /* OPEN_REPARSE_POINT */, 0)
	runtime.KeepAlive(attributes)
	if err != nil {
		owner.file = 0
		return owner, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || len(source.handles) == 0 {
		return owner, errors.New("private Medium image lost its retained compiler output")
	}
	inputHandle, err := owner.open(source.handles[len(source.handles)-1], syscall.GENERIC_READ, 0x00200000)
	if err != nil {
		return owner, err
	}
	input := os.NewFile(uintptr(inputHandle), "captured-medium-source")
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	length := int64(source.identity.FileSizeHigh)<<32 | int64(source.identity.FileSizeLow)
	if length < 1 || length > 512<<20 {
		return owner, errors.New("private Medium fixture executable exceeds its copy bound")
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(fixtureMediumFileWriter(owner.file), digest), io.NewSectionReader(input, 0, length+1))
	if err != nil || written != length {
		return owner, errors.Join(err, errors.New("private Medium image did not copy its exact retained bytes"))
	}
	if err := syscall.FlushFileBuffers(owner.file); err != nil {
		return owner, err
	}
	// Retain the same native object with metadata-only access. A duplicate
	// of the writable file object would keep its write access and conflict with
	// the unchanged production pin's refusal to share image writes/deletion.
	metadata, err := owner.open(owner.file, 0x00020080 /* READ_CONTROL | READ_ATTRIBUTES */, 0x00200000)
	if err != nil {
		return owner, err
	}
	owner.retiringWrite = owner.file
	owner.file = metadata
	if err := syscall.CloseHandle(owner.retiringWrite); err != nil {
		return owner, err // Both original objects remain retained for cleanup.
	}
	owner.retiringWrite = 0
	owner.image, err = PinImage(path)
	if err != nil {
		return owner, err
	}
	var created syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(owner.file, &created); err != nil {
		return owner, err
	}
	actual := owner.image.identity
	if created.VolumeSerialNumber != actual.VolumeSerialNumber || created.FileIndexHigh != actual.FileIndexHigh ||
		created.FileIndexLow != actual.FileIndexLow || created.NumberOfLinks != 1 || actual.NumberOfLinks != 1 {
		return owner, errors.New("private Medium image changed its CREATE_NEW file identity")
	}
	readback, err := owner.open(owner.file, syscall.GENERIC_READ, 0x00200000)
	if err != nil {
		return owner, err
	}
	copyFile := os.NewFile(uintptr(readback), "captured-medium-copy")
	verified := sha256.New()
	count, readErr := io.Copy(verified, io.LimitReader(copyFile, length+1))
	closeErr := copyFile.Close()
	if readErr != nil || closeErr != nil || count != length || string(verified.Sum(nil)) != string(digest.Sum(nil)) {
		return owner, errors.Join(readErr, closeErr, errors.New("private Medium image failed retained byte readback"))
	}
	return owner, nil
}

type fixtureMediumFileWriter syscall.Handle

func (handle fixtureMediumFileWriter) Write(data []byte) (int, error) {
	var written uint32
	err := syscall.WriteFile(syscall.Handle(handle), data, &written, nil)
	return int(written), err
}

// The actual hosted fixture rejects ReOpenFile for retained directory/security
// and disposal access. Resolve the held object's kernel volume-GUID spelling,
// open with the exact requested rights, and independently compare native file
// identity before using it. A successful pathname open alone is never proof.
// The original handle remains retained throughout capture and later cleanup.
func fixtureOpenSameMediumObject(api *nativeAPI, handle syscall.Handle, access, flags uint32) (syscall.Handle, error) {
	var before syscall.ByHandleFileInformation
	if api == nil || handle == 0 || handle == syscall.InvalidHandle {
		return 0, errors.New("private Medium object has no retained native owner")
	}
	if err := syscall.GetFileInformationByHandle(handle, &before); err != nil {
		return 0, err
	}
	if before.VolumeSerialNumber == 0 || before.FileIndexHigh == 0 && before.FileIndexLow == 0 || before.FileAttributes&0x400 != 0 {
		return 0, errors.New("private Medium object has no stable non-reparse identity")
	}
	name := make([]uint16, 32768)
	length, _, callErr := api.finalPath.Call(uintptr(handle), uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)),
		1 /* FILE_NAME_NORMALIZED | VOLUME_NAME_GUID */)
	runtime.KeepAlive(name)
	if length == 0 || length >= uintptr(len(name)) {
		return 0, nativeError("private Medium retained object spelling", callErr)
	}
	path := syscall.UTF16ToString(name[:length])
	root, err := executableRoot(path)
	if err != nil || len(root) < len(volumeGUIDPrefix) || !strings.EqualFold(root[:len(volumeGUIDPrefix)], volumeGUIDPrefix) {
		return 0, errors.Join(err, errors.New("private Medium retained object lost its local volume identity"))
	}
	actual, err := syscall.CreateFile(&name[0], access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, flags, 0)
	runtime.KeepAlive(name)
	if err != nil {
		return 0, nativeError("private Medium identity-checked open", err)
	}
	var after syscall.ByHandleFileInformation
	readErr := syscall.GetFileInformationByHandle(actual, &after)
	if readErr != nil || after.VolumeSerialNumber != before.VolumeSerialNumber || after.FileIndexHigh != before.FileIndexHigh ||
		after.FileIndexLow != before.FileIndexLow || after.FileAttributes != before.FileAttributes {
		return 0, errors.Join(readErr, syscall.CloseHandle(actual), errors.New("private Medium open substituted its retained native object"))
	}
	return actual, nil
}

func (owner *fixtureMediumImage) open(handle syscall.Handle, access uint32, flags uint32) (syscall.Handle, error) {
	return fixtureOpenSameMediumObject(owner.native, handle, access, flags)
}

func (owner *fixtureMediumImage) close() error {
	if owner == nil {
		return nil
	}
	if err := owner.image.Close(); err != nil {
		return err
	}
	if owner.retiringWrite != 0 {
		if err := syscall.CloseHandle(owner.retiringWrite); err != nil {
			return err
		}
		owner.retiringWrite = 0
	}
	// The caller has joined the exact worker Job first. Delete only the
	// CREATE_NEW image and newly created directory through retained handles.
	for _, target := range []struct {
		handle *syscall.Handle
		flags  uint32
	}{{&owner.file, 0x00200000}, {&owner.dir, 0x02200000}} {
		if *target.handle == 0 {
			continue
		}
		if owner.removalTarget != 0 && owner.removalTarget != *target.handle {
			return errors.New("private Medium cleanup changed its retained target")
		}
		if !owner.deleteMarked {
			if owner.removal == 0 {
				var err error
				owner.removal, err = owner.open(*target.handle, 0x00010000 /* DELETE */, target.flags)
				if err != nil {
					return err
				}
				owner.removalTarget = *target.handle
			}
			pending := byte(1) // FILE_DISPOSITION_INFO uses one BOOLEAN.
			ok, _, callErr := owner.dispose.Call(uintptr(owner.removal), 4, uintptr(unsafe.Pointer(&pending)), 1)
			runtime.KeepAlive(&pending)
			if ok == 0 {
				return fmt.Errorf("private Medium object disposal failed: %w", callErr)
			}
			owner.deleteMarked = true
		}
		// Once marked, keep the exact deletion handle across a failed close.
		// Reopening a delete-pending pathname or dropping its owner is invalid.
		if owner.removal != 0 {
			if err := syscall.CloseHandle(owner.removal); err != nil {
				return err
			}
			owner.removal = 0
		}
		if err := syscall.CloseHandle(*target.handle); err != nil {
			return err
		}
		*target.handle = 0
		owner.removalTarget, owner.deleteMarked = 0, false
	}
	return nil
}
