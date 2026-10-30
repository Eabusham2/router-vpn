//go:build windows

package windowsapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"router-vpn/internal/common"
	"router-vpn/internal/windowscontroller"
)

// PreparePortableData is an original-desktop operation before elevation. Its
// roots come only from this retained running Portable Core, not argv, a current
// directory, environment variables or a caller-selected configuration path.
// It does not launch a shell, acquire UAC, execute a generated catalog or copy
// data from another Windows user's profile.
func PreparePortableData(ctx context.Context, launcher *windowscontroller.Image, self *windowscontroller.Process) error {
	if ctx == nil || ctx.Err() != nil || launcher == nil || self == nil || self.PID() != uint32(os.Getpid()) ||
		!strings.EqualFold(filepath.Base(launcher.Path()), "RouterVPNPortableCore.exe") {
		return errors.New("Portable preparation requires its live captured Core process")
	}
	if err := self.VerifyImage(launcher); err != nil {
		return err
	}
	identity, err := self.Identity()
	if err != nil || !identity.Primary || identity.SID == "" || identity.AuthenticationID == 0 {
		return errors.Join(err, errors.New("Portable preparation has no original desktop identity"))
	}
	root := filepath.Dir(launcher.Path())
	return preparePortableCaptured(ctx, filepath.Join(root, "App", "RouterVPN"), filepath.Join(root, "Data"), identity.SID, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := self.VerifyImage(launcher); err != nil {
			return err
		}
		current, err := self.Identity()
		if err != nil || current != identity {
			return errors.Join(err, errors.New("Portable preparation lost its original desktop token"))
		}
		return self.Alive()
	})
}

type portablePreparedFile struct {
	info os.FileInfo
	body []byte
}

func preparePortableCaptured(ctx context.Context, packageRoot, dataRoot, desktop string, stillOwned func() error) (failure error) {
	if ctx == nil || ctx.Err() != nil || stillOwned == nil {
		return errors.New("Portable preparation has no live operation")
	}
	api, err := portableNative()
	if err != nil {
		return err
	}
	var code []*windowscontroller.CodeFile
	defer func() {
		for index := len(code) - 1; index >= 0; index-- {
			failure = errors.Join(failure, code[index].Close())
		}
	}()
	readSource := func(name string) ([]byte, error) {
		captured, err := windowscontroller.PinFile(filepath.Join(packageRoot, name))
		if err != nil {
			return nil, err
		}
		code = append(code, captured)
		file, err := os.Open(captured.Path())
		if err != nil {
			return nil, err
		}
		security, securityErr := portableInspectSecurity(api, file)
		if securityErr == nil {
			owner, _, grants, inspectErr := security.inspect()
			securityErr = errors.Join(inspectErr, validatePortablePackageGrants(owner, desktop, grants), security.close())
		}
		if securityErr != nil {
			return nil, errors.Join(securityErr, file.Close())
		}
		body, readErr := io.ReadAll(io.LimitReader(file, portablePrivateLimit+1))
		err = errors.Join(readErr, file.Close())
		if err != nil || len(body) == 0 || len(body) > portablePrivateLimit {
			return nil, errors.Join(err, errors.New("Portable package default is empty or unbounded"))
		}
		return body, nil
	}
	// Hold the immutable source catalog identities throughout preparation. The
	// elevated child independently validates and maps their actual commands.
	for _, name := range []string{"modes.json", "logical-modes.json"} {
		body, err := readSource(name)
		if err != nil || !json.Valid(body) {
			return errors.Join(err, fmt.Errorf("Portable source %s is invalid", name))
		}
	}
	if err := stillOwned(); err != nil {
		return err
	}
	data, err := portablePrivateDirectory(api, dataRoot, desktop)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, data.Close()) }()
	// A fixed exclusive, delete-on-close object serializes this preparation.
	// CREATE_NEW never adopts or removes an existing foreign lock. The kernel
	// removes precisely this newly created object if the preparer exits/crashes.
	lock, err := portableCreatePrivate(api, filepath.Join(dataRoot, ".routervpn-prepare.lock"), desktop,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE|0x00010000 /* DELETE */, 0, 0x04000000 /* DELETE_ON_CLOSE */)
	if err != nil {
		return fmt.Errorf("Portable data is already being prepared or its lock is unsafe: %w", err)
	}
	defer func() { failure = errors.Join(failure, lock.Close()) }()
	configPath, routersPath := filepath.Join(dataRoot, "client.json"), filepath.Join(dataRoot, "routers.json")
	config, err := portableReadPrivate(api, configPath, desktop)
	if err != nil {
		return err
	}
	var defaults []byte
	if config == nil {
		defaults, err = readSource("client.json")
		if err != nil {
			return err
		}
	}
	var existing []byte
	if config != nil {
		existing = config.body
	}
	nextConfig, err := portableConfiguration(existing, defaults, packageRoot, dataRoot)
	if err != nil {
		return err
	}
	routers, err := portableReadPrivate(api, routersPath, desktop)
	if err != nil {
		return err
	}
	var nextRouters []byte
	if routers == nil {
		nextRouters, err = readSource("routers.json")
		if err != nil {
			return err
		}
	} else {
		nextRouters = routers.body
	}
	if _, err := portableJSONObject(nextRouters); err != nil {
		return errors.New("Portable router store is invalid; refusing a reset")
	}
	var store common.RouterProfileStore
	if err := json.Unmarshal(nextRouters, &store); err != nil {
		return errors.New("Portable router store is unsupported or invalid; refusing a reset")
	}
	generated, err := portablePrivateDirectory(api, filepath.Join(dataRoot, "generated"), desktop)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, generated.Close()) }()
	if err := stillOwned(); err != nil {
		return err
	}
	if routers == nil {
		if err := portablePublishPrivate(api, routersPath, desktop, nil, nextRouters, stillOwned); err != nil {
			return err
		}
	}
	if config != nil && bytes.Equal(config.body, nextConfig) {
		return nil
	}
	return portablePublishPrivate(api, configPath, desktop, config, nextConfig, stillOwned)
}

func portablePrivateDirectory(api *portableNativeAPI, path, desktop string) (_ *os.File, failure error) {
	security, err := portableDescriptor(api, desktop, true)
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
	if ok == 0 && !errors.Is(callErr, syscall.ERROR_ALREADY_EXISTS) {
		return nil, fmt.Errorf("create captured Portable directory: %w", callErr)
	}
	file, err := portableOpenExisting(path, true, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)
	if err != nil {
		return nil, err
	}
	if err := portableHardenCaptured(api, file, desktop, true); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func portableCreatePrivate(api *portableNativeAPI, path, desktop string, access, share, flags uint32) (_ *os.File, failure error) {
	security, err := portableDescriptor(api, desktop, false)
	if err != nil {
		return nil, err
	}
	defer func() { failure = errors.Join(failure, security.close()) }()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(security.descriptor)}
	handle, err := syscall.CreateFile(name, access, share, &attributes, syscall.CREATE_NEW, flags|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(security)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if _, err := portableFileIdentity(file, false); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func portableReadPrivate(api *portableNativeAPI, path, desktop string) (_ *portablePreparedFile, failure error) {
	file, err := portableOpenExisting(path, false, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_DELETE)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { failure = errors.Join(failure, file.Close()) }()
	if err := portableHardenCaptured(api, file, desktop, false); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > portablePrivateLimit {
		return nil, errors.Join(err, errors.New("Portable private file is empty or unbounded"))
	}
	body, err := io.ReadAll(io.LimitReader(file, portablePrivateLimit+1))
	current, statErr := os.Lstat(path)
	after, afterErr := file.Stat()
	if err != nil || statErr != nil || afterErr != nil || !os.SameFile(info, current) ||
		len(body) != int(info.Size()) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.Join(err, statErr, afterErr, errors.New("Portable private file changed during its captured read"))
	}
	return &portablePreparedFile{info, body}, nil
}

func portablePublishPrivate(api *portableNativeAPI, path, desktop string, before *portablePreparedFile, body []byte, stillOwned func() error) (failure error) {
	if len(body) == 0 || len(body) > portablePrivateLimit || stillOwned == nil {
		return errors.New("Portable private publication has no bounded captured value")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), ".routervpn-prepare-"+hex.EncodeToString(nonce[:])+".tmp")
	file, err := portableCreatePrivate(api, temporary, desktop, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ, 0)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			current, err := os.Lstat(temporary)
			if err == nil && os.SameFile(current, info) {
				failure = errors.Join(failure, os.Remove(temporary))
			} else if !os.IsNotExist(err) {
				failure = errors.Join(failure, err, errors.New("Portable temporary owner changed before cleanup"))
			}
		}
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := stillOwned(); err != nil {
		return err
	}
	current, err := portableReadPrivate(api, path, desktop)
	if err != nil {
		return err
	}
	if (before == nil) != (current == nil) || before != nil && (!os.SameFile(before.info, current.info) || !bytes.Equal(before.body, current.body)) {
		return errors.New("Portable private target changed before captured publication")
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	committed = true
	return nil
}
