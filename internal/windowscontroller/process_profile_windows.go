//go:build windows

package windowscontroller

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type UserDirectories struct {
	Profile, RoamingAppData, LocalAppData string
}

var profileAPIOnce struct {
	sync.Once
	profile, knownFolder, free *syscall.Proc
	err                        error
}

// UserDirectories reads the original user's registered paths through the
// retained process token. Different-account UAC must not replace them with the
// administrator's environment or assume that AppData was not redirected.
// KF_FLAG_DONT_VERIFY prevents filesystem creation/probing of those folders.
func (p *Process) UserDirectories() (UserDirectories, error) {
	handle, release, err := p.borrow()
	if err != nil {
		return UserDirectories{}, err
	}
	defer release()
	api, err := native()
	if err != nil {
		return UserDirectories{}, err
	}
	profileAPIOnce.Do(func() {
		library, err := syscall.LoadDLL(filepath.Join(api.systemDirectory, "userenv.dll"))
		if err != nil {
			profileAPIOnce.err = err
			return
		}
		profileAPIOnce.profile, err = library.FindProc("GetUserProfileDirectoryW")
		if err == nil {
			profileAPIOnce.knownFolder, err = api.shellExecute.Dll.FindProc("SHGetKnownFolderPath")
		}
		if err == nil {
			profileAPIOnce.free, err = api.initializeCOM.Dll.FindProc("CoTaskMemFree")
		}
		if err != nil {
			_ = library.Release()
			profileAPIOnce.err = err
		}
	})
	if profileAPIOnce.err != nil {
		return UserDirectories{}, profileAPIOnce.err
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY|syscall.TOKEN_IMPERSONATE, &token); err != nil {
		return UserDirectories{}, err
	}
	defer token.Close()
	identity, _, err := readTokenIdentity(token)
	if err != nil || !identity.Primary {
		return UserDirectories{}, errors.Join(err, errors.New("the retained profile token is not primary"))
	}
	if err := p.Alive(); err != nil {
		return UserDirectories{}, err
	}
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	ok, _, callErr := profileAPIOnce.profile.Call(uintptr(token), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if ok == 0 || length == 0 || length > uint32(len(buffer)) || buffer[length-1] != 0 {
		return UserDirectories{}, nativeError("retained user profile", callErr)
	}
	profile, err := validateUserDirectory(syscall.UTF16ToString(buffer[:length]))
	if err != nil {
		return UserDirectories{}, err
	}
	readFolder := func(identifier syscall.GUID) (string, error) {
		var value *uint16
		status, _, _ := profileAPIOnce.knownFolder.Call(uintptr(unsafe.Pointer(&identifier)), 0x4000, uintptr(token), uintptr(unsafe.Pointer(&value)))
		if value != nil {
			defer profileAPIOnce.free.Call(uintptr(unsafe.Pointer(value)))
		}
		if uint32(status) != 0 || value == nil {
			return "", fmt.Errorf("retained user known folder failed (HRESULT 0x%08x)", uint32(status))
		}
		for length := 0; length < 32768; length++ {
			if *(*uint16)(unsafe.Add(unsafe.Pointer(value), length*2)) == 0 {
				return validateUserDirectory(syscall.UTF16ToString(unsafe.Slice(value, length)))
			}
		}
		return "", errors.New("retained user known folder is unbounded")
	}
	roaming, err := readFolder(syscall.GUID{Data1: 0x3eb685db, Data2: 0x65f9, Data3: 0x4cf6, Data4: [8]byte{0xa0, 0x3a, 0xe3, 0xef, 0x65, 0x72, 0x9f, 0x3d}})
	if err != nil {
		return UserDirectories{}, err
	}
	local, err := readFolder(syscall.GUID{Data1: 0xf1b32785, Data2: 0x6fba, Data3: 0x4fcf, Data4: [8]byte{0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91}})
	if err != nil {
		return UserDirectories{}, err
	}
	if err := p.Alive(); err != nil {
		return UserDirectories{}, err
	}
	return UserDirectories{profile, roaming, local}, nil
}

func (p *Process) UserProfileDirectory() (string, error) {
	directories, err := p.UserDirectories()
	return directories.Profile, err
}

func validateUserDirectory(value string) (string, error) {
	if value == "" || len(value) > 32760 || strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) ||
		strings.HasPrefix(value, `\\.\`) || strings.HasPrefix(strings.ToUpper(value), `\\?\GLOBALROOT`) {
		return "", errors.New("retained user folder is not a bounded absolute filesystem path")
	}
	return filepath.Clean(value), nil
}
