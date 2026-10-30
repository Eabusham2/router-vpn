//go:build windows

package windowscontroller

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// MachinePaths contains registered machine locations, independently of the
// launcher's inherited environment and of the account consenting to elevation.
// The paths are observations, not authority to adopt or change existing files.
type MachinePaths struct {
	System, Windows, SystemDrive, ProgramData, ProgramFiles string
}

// MachineDirectories deliberately requests a system-only environment without
// inheritance. SHGetKnownFolderPath in a minimally initialized child can leave
// registry environment strings unresolved; inherited strings are not an
// acceptable source of authority either. Userenv expands the actual registered
// machine locations without replacing a redirected folder with a default.
// This function neither changes the calling process environment nor creates a
// profile, folder, registry entry or filesystem object.
// https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createenvironmentblock
func MachineDirectories() (MachinePaths, error) {
	api, err := native()
	if err != nil {
		return MachinePaths{}, err
	}
	library, err := syscall.LoadDLL(filepath.Join(api.systemDirectory, "userenv.dll"))
	if err != nil {
		return MachinePaths{}, err
	}
	defer library.Release()
	create, err := library.FindProc("CreateEnvironmentBlock")
	if err != nil {
		return MachinePaths{}, err
	}
	destroy, err := library.FindProc("DestroyEnvironmentBlock")
	if err != nil {
		return MachinePaths{}, err
	}
	var block unsafe.Pointer
	ok, _, callErr := create.Call(uintptr(unsafe.Pointer(&block)), 0, 0)
	if block != nil {
		defer destroy.Call(uintptr(block))
	}
	if ok == 0 || block == nil {
		return MachinePaths{}, nativeError("system-only environment capture", callErr)
	}
	entries, err := readMachineEnvironment(block)
	if err != nil {
		return MachinePaths{}, err
	}
	values, err := parseMachineEnvironment(entries)
	if err != nil {
		return MachinePaths{}, err
	}
	paths := MachinePaths{System: filepath.Clean(api.systemDirectory), Windows: filepath.Dir(api.systemDirectory)}
	paths.SystemDrive = filepath.VolumeName(paths.Windows)
	if len(paths.SystemDrive) != 2 || paths.SystemDrive[1] != ':' ||
		!strings.EqualFold(values["SYSTEMDRIVE"], paths.SystemDrive) ||
		!strings.EqualFold(filepath.Clean(values["SYSTEMROOT"]), paths.Windows) ||
		!strings.EqualFold(filepath.Clean(values["WINDIR"]), paths.Windows) {
		return MachinePaths{}, errors.New("captured machine environment differs from the native Windows directory")
	}
	paths.ProgramData, err = validateMachineDirectory(values["PROGRAMDATA"])
	if err != nil {
		return MachinePaths{}, fmt.Errorf("captured ProgramData: %w", err)
	}
	paths.ProgramFiles, err = validateMachineDirectory(values["PROGRAMFILES"])
	if err != nil {
		return MachinePaths{}, fmt.Errorf("captured ProgramFiles: %w", err)
	}
	return paths, nil
}

func readMachineEnvironment(block unsafe.Pointer) ([]string, error) {
	const unitsLimit = 1 << 20
	entries := make([]string, 0, 64)
	start := 0
	for offset := 0; offset < unitsLimit; offset++ {
		if *(*uint16)(unsafe.Add(block, offset*2)) != 0 {
			if offset-start >= 32767 {
				return nil, errors.New("captured machine environment entry is unbounded")
			}
			continue
		}
		if offset == start {
			return entries, nil
		}
		if len(entries) >= 8192 {
			return nil, errors.New("captured machine environment contains too many entries")
		}
		entries = append(entries, syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Add(block, start*2)), offset-start)))
		start = offset + 1
	}
	return nil, errors.New("captured machine environment is unbounded")
}

func parseMachineEnvironment(entries []string) (map[string]string, error) {
	if len(entries) == 0 || len(entries) > 8192 {
		return nil, errors.New("captured machine environment has no bounded entries")
	}
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" || len(entry) > 32767 || strings.ContainsAny(entry, "\x00\r\n") {
			return nil, errors.New("captured machine environment has a malformed entry")
		}
		name = strings.ToUpper(name)
		if _, exists := values[name]; exists {
			return nil, errors.New("captured machine environment repeats a variable")
		}
		values[name] = value
	}
	for _, name := range []string{"SYSTEMDRIVE", "SYSTEMROOT", "WINDIR", "PROGRAMDATA", "PROGRAMFILES"} {
		if values[name] == "" {
			return nil, fmt.Errorf("captured machine environment has no %s", name)
		}
	}
	return values, nil
}

func validateMachineDirectory(value string) (string, error) {
	if strings.Contains(value, "%") {
		return "", errors.New("registered machine directory contains an unresolved environment string")
	}
	return validateUserDirectory(value)
}
