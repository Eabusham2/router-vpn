//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var ErrClosed = errors.New("the captured Windows controller owner is closed")

// Process retains the actual kernel process object. PID reuse or a request's
// claimed process ID cannot retarget it. Closing a reference does not terminate
// a process and is never a substitute for acknowledged controller cleanup.
type Process struct {
	mu     sync.Mutex
	handle syscall.Handle
	// Only the owner returned by suspended Shell creation retains this exact
	// initial thread. Ordinary borrowed process references never acquire it.
	launchThread syscall.Handle
	pid          uint32
	closing      bool
	closed       chan struct{}
	operations   sync.WaitGroup
	closeOnce    sync.Once
	closeErr     error
}

func adoptProcess(handle syscall.Handle) (*Process, error) {
	api, err := native()
	if err != nil {
		_ = syscall.CloseHandle(handle)
		return nil, err
	}
	pid, _, callErr := api.processID.Call(uintptr(handle))
	if handle == 0 || handle == syscall.InvalidHandle || pid == 0 || pid > 0xffffffff {
		if handle != 0 && handle != syscall.InvalidHandle {
			_ = syscall.CloseHandle(handle)
		}
		return nil, nativeError("captured process identity", callErr)
	}
	return &Process{handle: handle, pid: uint32(pid), closed: make(chan struct{})}, nil
}

// OpenProcess retains a process for independent executable/token readback. A
// caller must then compare it with the PID supplied by the kernel pipe API or
// the exact retained ShellExecuteEx result before sending any private material.
func OpenProcess(pid uint32) (*Process, error) {
	if pid == 0 {
		return nil, errors.New("Windows controller process ID is missing")
	}
	handle, err := syscall.OpenProcess(0x00100000|0x1000 /* SYNCHRONIZE | QUERY_LIMITED_INFORMATION */, false, pid)
	if err != nil {
		return nil, err
	}
	return adoptProcess(handle)
}

func (p *Process) PID() uint32 {
	if p == nil {
		return 0
	}
	return p.pid
}

// retain duplicates only the already granted kernel handle in this process.
// It never reopens the elevated process by PID, which would apply a fresh DACL
// check to a standard user who explicitly consented using another admin account.
func (p *Process) retain() (*Process, error) {
	handle, release, err := p.borrow()
	if err != nil {
		return nil, err
	}
	defer release()
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	var duplicate syscall.Handle
	if err := syscall.DuplicateHandle(current, handle, current, &duplicate, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	retained, err := adoptProcess(duplicate)
	if err != nil {
		return nil, err
	}
	if retained.PID() != p.PID() {
		return nil, errors.Join(errors.New("retained Windows process handle changed identity"), retained.Close())
	}
	return retained, nil
}

func (p *Process) borrow() (syscall.Handle, func(), error) {
	if p == nil {
		return 0, nil, ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.handle == 0 {
		return 0, nil, ErrClosed
	}
	p.operations.Add(1)
	return p.handle, p.operations.Done, nil
}

func (p *Process) Alive() error {
	handle, release, err := p.borrow()
	if err != nil {
		return err
	}
	defer release()
	status, err := syscall.WaitForSingleObject(handle, 0)
	if err != nil {
		return err
	}
	if status != syscall.WAIT_TIMEOUT {
		return errors.New("the captured Windows controller process is no longer live")
	}
	return nil
}

func (p *Process) Wait(ctx context.Context) (uint32, error) {
	if ctx == nil {
		return 0, errors.New("Windows process wait requires a bounded caller")
	}
	handle, release, err := p.borrow()
	if err != nil {
		return 0, err
	}
	defer release()
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		select {
		case <-p.closed:
			return 0, ErrClosed
		default:
		}
		status, err := syscall.WaitForSingleObject(handle, 25)
		if err != nil {
			return 0, err
		}
		if status == syscall.WAIT_OBJECT_0 {
			var code uint32
			if err := syscall.GetExitCodeProcess(handle, &code); err != nil {
				return 0, err
			}
			return code, nil
		}
		if status != syscall.WAIT_TIMEOUT {
			return 0, errors.New("Windows process wait returned an unknown state")
		}
	}
}

func (p *Process) Identity() (TokenIdentity, error) {
	handle, release, err := p.borrow()
	if err != nil {
		return TokenIdentity{}, err
	}
	defer release()
	var token syscall.Token
	if err := syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token); err != nil {
		return TokenIdentity{}, err
	}
	identity, _, readErr := readTokenIdentity(token)
	err = errors.Join(readErr, token.Close())
	if err != nil || !identity.Primary {
		return TokenIdentity{}, errors.Join(err, errors.New("captured Windows process primary token is unproved"))
	}
	return identity, nil
}

// StartTimeUTCTicks reads the creation identity from this retained process
// handle. The representation matches DateTime.UtcTicks used by the native
// Tray; a recycled PID cannot choose the captured value.
func (p *Process) StartTimeUTCTicks() (int64, error) {
	handle, release, err := p.borrow()
	if err != nil {
		return 0, err
	}
	defer release()
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	const epoch = uint64(504911232000000000)
	ticks := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if ticks == 0 || ticks > uint64(3155378975999999999)-epoch {
		return 0, errors.New("the retained Windows process has an invalid creation identity")
	}
	return int64(ticks + epoch), nil
}

func (p *Process) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closing = true
		close(p.closed)
		p.mu.Unlock()
		p.operations.Wait()
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.launchThread != 0 {
			p.closeErr = syscall.CloseHandle(p.launchThread)
			if p.closeErr == nil {
				p.launchThread = 0
			}
		}
		processErr := syscall.CloseHandle(p.handle)
		p.closeErr = errors.Join(p.closeErr, processErr)
		if processErr == nil {
			p.handle = 0
		}
	})
	return p.closeErr
}

// Image pins a local executable and every ancestor against deletion/rename
// while launch and peer verification occur. The executable also denies writes.
// Different files with identical bytes do not acquire the same identity.
type Image struct {
	mu               sync.Mutex
	path             string
	handles          []syscall.Handle
	identity         syscall.ByHandleFileInformation
	systemPowerShell bool
	closed           bool
}

const volumeGUIDPrefix = `\\?\Volume{`

func executableRoot(path string) (string, error) {
	if len(path) >= len(volumeGUIDPrefix)+38 && strings.EqualFold(path[:len(volumeGUIDPrefix)], volumeGUIDPrefix) {
		identifier := path[len(volumeGUIDPrefix) : len(volumeGUIDPrefix)+36]
		for index, value := range identifier {
			if index == 8 || index == 13 || index == 18 || index == 23 {
				if value != '-' {
					return "", errors.New("Windows executable volume identity is invalid")
				}
			} else if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F') {
				return "", errors.New("Windows executable volume identity is invalid")
			}
		}
		if path[len(volumeGUIDPrefix)+36:len(volumeGUIDPrefix)+38] != `}\` {
			return "", errors.New("Windows executable volume root is invalid")
		}
		return path[:len(volumeGUIDPrefix)+38], nil
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || len(path) <= len(volume) || path[len(volume)] != '\\' {
		return "", errors.New("Windows controller executable must use a local volume path")
	}
	return volume + `\`, nil
}

func localPackageFilePath(path string) (string, error) {
	if !filepath.IsAbs(path) || len(path) > 32760 || strings.ContainsRune(path, 0) {
		return "", errors.New("Windows controller requires an absolute local executable")
	}
	clean := filepath.Clean(path)
	root, err := executableRoot(clean)
	if err != nil {
		return "", errors.New("Windows captured package file must be on a local drive")
	}
	for _, part := range strings.Split(clean[len(root):], `\`) {
		if part == "" || strings.TrimRight(part, ". ") != part || strings.ContainsAny(part, ":") {
			return "", errors.New("Windows controller executable path is ambiguous")
		}
	}
	return clean, nil
}

func localExecutablePath(path string) (string, error) {
	clean, err := localPackageFilePath(path)
	if err != nil || !strings.EqualFold(filepath.Ext(clean), ".exe") {
		return "", errors.Join(err, errors.New("Windows controller executable must be on a local drive"))
	}
	return clean, nil
}

func PinImage(path string) (_ *Image, resultErr error) {
	return pinImage(path, false)
}

// PinCurrentImage captures the current process's kernel-reported image. The
// module loader's spelling (and therefore os.Executable) preserves the launch
// namespace, including the normalized \\.\Volume form required by managed
// native children. It is not a caller-selected package path. Query the actual
// process instead, then retain its same local volume/file through PinImage's
// unchanged strict path, reparse and hardlink checks.
func PinCurrentImage() (*Image, error) {
	api, err := native()
	if err != nil {
		return nil, err
	}
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	ok, _, callErr := api.processImage.Call(uintptr(self), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if ok == 0 || length == 0 || length >= uint32(len(buffer)) {
		return nil, nativeError("current process executable", callErr)
	}
	image, err := PinImage(syscall.UTF16ToString(buffer[:length]))
	runtime.KeepAlive(buffer)
	return image, err
}

// The protected-system policy is private to the pathless OS factory and the
// readback of its already captured child. A caller-selected executable always
// uses PinImage's single-link policy.
func pinImage(path string, systemPowerShell bool) (_ *Image, resultErr error) {
	return pinPackageObject(path, systemPowerShell, localExecutablePath)
}

// The validator is private: only executable pins reach launch APIs. CodeFile
// wraps a non-executable package capture without exposing an Image capability.
func pinPackageObject(path string, systemPowerShell bool, validate func(string) (string, error)) (_ *Image, resultErr error) {
	path, err := validate(path)
	if err != nil {
		return nil, err
	}
	image := &Image{systemPowerShell: systemPowerShell}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, image.Close())
		}
	}()
	if err := image.pinComponents(path); err != nil {
		return nil, err
	}
	api, err := native()
	if err != nil {
		return nil, err
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := api.finalPath.Call(uintptr(image.handles[len(image.handles)-1]), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 1 /* FILE_NAME_NORMALIZED | VOLUME_NAME_GUID */)
	if length == 0 || length >= uintptr(len(buffer)) {
		// Network shares have no volume GUID. Never fall back to the original
		// DOS drive name, which can be rebound independently of held handles.
		return nil, nativeError("captured local volume image path", callErr)
	}
	canonical, err := validate(syscall.UTF16ToString(buffer[:length]))
	if err != nil || !strings.HasPrefix(strings.ToLower(canonical), strings.ToLower(volumeGUIDPrefix)) {
		return nil, errors.Join(err, errors.New("Windows image has no independently proved local volume identity"))
	}
	retained := image.identity
	// A DOS device may point directly at a subdirectory. Pin the full resolved
	// ancestry too, so renaming an omitted parent cannot retarget ShellExecute.
	if !strings.EqualFold(path, canonical) {
		if err := image.pinComponents(canonical); err != nil {
			return nil, err
		}
	}
	actual := image.identity
	if retained.VolumeSerialNumber != actual.VolumeSerialNumber || retained.FileIndexHigh != actual.FileIndexHigh || retained.FileIndexLow != actual.FileIndexLow || retained.NumberOfLinks != actual.NumberOfLinks {
		return nil, errors.New("Windows image changed while pinning its resolved volume path")
	}
	image.path = canonical
	runtime.KeepAlive(buffer)
	return image, nil
}

func (image *Image) pinComponents(path string) error {
	root, err := executableRoot(path)
	if err != nil {
		return err
	}
	parts := strings.Split(path[len(root):], `\`)
	current := root
	for index := -1; index < len(parts); index++ {
		if index >= 0 {
			current = filepath.Join(current, parts[index])
		}
		last := index == len(parts)-1
		access, share, flags := uint32(0x80), uint32(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE), uint32(0x00200000|0x02000000)
		if last {
			access, share, flags = syscall.GENERIC_READ, syscall.FILE_SHARE_READ, 0x00200000
		}
		if image.systemPowerShell && !last {
			access |= 0x00020000 // READ_CONTROL for the retained directory DACL.
		}
		name, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		handle, err := syscall.CreateFile(name, access, share, nil, syscall.OPEN_EXISTING, flags, 0)
		if err != nil {
			return nativeError("pin executable path", err)
		}
		image.handles = append(image.handles, handle)
		var info syscall.ByHandleFileInformation
		if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
			return err
		}
		if info.FileAttributes&0x400 != 0 || (!last && info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0) ||
			(last && (info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1 && !image.systemPowerShell)) {
			return errors.New("Windows controller image has a reparse, hardlink or unexpected path component")
		}
		if image.systemPowerShell && index >= 0 {
			// The actual volume root may permit creating new ordinary folders.
			// Every existing non-root ancestor of the system executable must be
			// protected, including any ancestry exposed by a DOS alias.
			if err := verifySystemImageProtection(handle); err != nil {
				return fmt.Errorf("Windows system image component %q: %w", current, err)
			}
		}
		if last {
			kind, err := syscall.GetFileType(handle)
			if err != nil || kind != syscall.FILE_TYPE_DISK || info.FileIndexHigh == 0 && info.FileIndexLow == 0 {
				return errors.Join(err, errors.New("Windows controller image has no stable disk identity"))
			}
			if image.systemPowerShell && (info.NumberOfLinks == 0 || image.identity.NumberOfLinks != 0 && info.NumberOfLinks != image.identity.NumberOfLinks) {
				return errors.New("Windows system image changed its captured hardlink count")
			}
			image.identity = info
		}
	}
	return nil
}

// normalizedLaunchNameLocked retains the same captured volume/file identity
// using the Win32 spelling that supports native managed process creation. The
// canonical no-normalization path stays the Image's public identity. There are
// no relative or ambiguous components to normalize: PinImage rejected them.
// Never replace this with a DOS drive path or a post-execution-only check.
// The caller holds image.mu and retains the returned file through CreateProcess.
func (image *Image) normalizedLaunchNameLocked() (string, syscall.Handle, error) {
	if image.closed || len(image.handles) == 0 || len(image.path) <= len(volumeGUIDPrefix) ||
		!strings.EqualFold(image.path[:len(volumeGUIDPrefix)], volumeGUIDPrefix) {
		return "", 0, ErrClosed
	}
	path := `\\.\` + image.path[len(`\\?\`):]
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", 0, err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000, 0)
	if err != nil {
		return "", 0, nativeError("normalized launch image capture", err)
	}
	reject := func(cause error) (string, syscall.Handle, error) {
		closeErr := syscall.CloseHandle(handle)
		if closeErr != nil {
			// An ambiguous close never loses its owned native handle.
			image.handles = append(image.handles, handle)
		}
		return "", 0, errors.Join(cause, closeErr)
	}
	var actual syscall.ByHandleFileInformation
	err = syscall.GetFileInformationByHandle(handle, &actual)
	if err != nil || actual.FileAttributes&(0x400|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 || image.identity.NumberOfLinks == 0 || actual.NumberOfLinks != image.identity.NumberOfLinks ||
		actual.VolumeSerialNumber != image.identity.VolumeSerialNumber || actual.FileIndexHigh != image.identity.FileIndexHigh || actual.FileIndexLow != image.identity.FileIndexLow {
		return reject(errors.Join(err, errors.New("normalized launch image differs from its retained executable")))
	}
	if image.systemPowerShell {
		if err := verifySystemImageProtection(handle); err != nil {
			return reject(err)
		}
	}
	api, err := native()
	if err != nil {
		return reject(err)
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := api.finalPath.Call(uintptr(handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 1 /* VOLUME_NAME_GUID */)
	if length == 0 || length >= uintptr(len(buffer)) || !strings.EqualFold(syscall.UTF16ToString(buffer[:length]), image.path) {
		return reject(nativeError("normalized launch image volume readback", callErr))
	}
	runtime.KeepAlive(buffer)
	return path, handle, nil
}

func (i *Image) Path() string {
	if i == nil {
		return ""
	}
	return i.path
}

func (i *Image) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closed = true
	var result error
	for index := len(i.handles) - 1; index >= 0; index-- {
		if i.handles[index] != 0 {
			err := syscall.CloseHandle(i.handles[index])
			result = errors.Join(result, err)
			if err == nil {
				i.handles[index] = 0
			}
		}
	}
	return result
}

func (p *Process) VerifyImage(expected *Image) (resultErr error) {
	if expected == nil {
		return errors.New("Windows controller has no captured executable")
	}
	api, err := native()
	if err != nil {
		return err
	}
	handle, release, err := p.borrow()
	if err != nil {
		return err
	}
	defer release()
	expected.mu.Lock()
	defer expected.mu.Unlock()
	if expected.closed || len(expected.handles) == 0 {
		return ErrClosed
	}
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	ok, _, callErr := api.processImage.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if ok == 0 || length == 0 || length >= uint32(len(buffer)) {
		return nativeError("actual process executable", callErr)
	}
	actual, err := pinImage(syscall.UTF16ToString(buffer[:length]), expected.systemPowerShell)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, actual.Close()) }()
	var retained syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(expected.handles[len(expected.handles)-1], &retained); err != nil {
		return err
	}
	want := expected.identity
	got := actual.identity
	if want.VolumeSerialNumber != retained.VolumeSerialNumber || want.FileIndexHigh != retained.FileIndexHigh || want.FileIndexLow != retained.FileIndexLow || want.NumberOfLinks == 0 || retained.NumberOfLinks != want.NumberOfLinks ||
		want.VolumeSerialNumber != got.VolumeSerialNumber || want.FileIndexHigh != got.FileIndexHigh || want.FileIndexLow != got.FileIndexLow || want.NumberOfLinks != got.NumberOfLinks {
		return errors.New("Windows controller process executes a different captured file")
	}
	status, err := syscall.WaitForSingleObject(handle, 0)
	if err != nil || status != syscall.WAIT_TIMEOUT {
		return errors.Join(err, errors.New("Windows controller process exited during executable verification"))
	}
	runtime.KeepAlive(buffer)
	return nil
}
