//go:build windows

package windowscontroller

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// MachinePaths contains registered machine locations, independently of the
// launcher's inherited environment and of the account consenting to elevation.
// The paths are observations, not authority to adopt or change existing files.
type MachinePaths struct {
	System, Windows, SystemDrive, ProgramData, ProgramFiles string
}

const (
	machineProfileListKey      = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	machineCurrentVersionKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion`
	machineUserShellFoldersKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
	machineDirectoryLimit      = 32760
)

// MachineDirectories reads only the fixed, 64-bit machine registrations for
// ProgramData and ProgramFilesDir. The optional common known-folder registration
// refines ProgramData. RegGetValueW must leave REG_EXPAND_SZ unexpanded: even a
// non-inheriting Userenv block expands these values using the caller's mutable
// SystemDrive/SystemRoot. Expansion here uses only the kernel Windows location
// and these captured registrations, never the process environment or a default.
// This function changes no environment, registry entry, profile or filesystem.
// https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-reggetvaluew
func MachineDirectories() (MachinePaths, error) {
	api, err := native()
	if err != nil {
		return MachinePaths{}, err
	}
	paths := MachinePaths{System: filepath.Clean(api.systemDirectory), Windows: filepath.Dir(api.systemDirectory)}
	paths.SystemDrive = filepath.VolumeName(paths.Windows)
	if len(paths.SystemDrive) != 2 || paths.SystemDrive[1] != ':' {
		return MachinePaths{}, errors.New("native Windows directory has no local system drive")
	}
	if _, err := validateMachineDirectory(paths.System); err != nil {
		return MachinePaths{}, err
	}
	if _, err := validateMachineDirectory(paths.Windows); err != nil {
		return MachinePaths{}, err
	}
	library, err := syscall.LoadDLL(filepath.Join(paths.System, "advapi32.dll"))
	if err != nil {
		return MachinePaths{}, err
	}
	defer library.Release()
	read, err := library.FindProc("RegGetValueW")
	if err != nil {
		return MachinePaths{}, err
	}
	data, _, err := readMachineRegistration(read, machineProfileListKey, "ProgramData", false)
	if err != nil {
		return MachinePaths{}, err
	}
	files, _, err := readMachineRegistration(read, machineCurrentVersionKey, "ProgramFilesDir", false)
	if err != nil {
		return MachinePaths{}, err
	}
	commonData, _, err := readMachineRegistration(read, machineUserShellFoldersKey, "Common AppData", true)
	if err != nil {
		return MachinePaths{}, err
	}
	return resolveMachineRegistrations(paths, data, files, commonData)
}

func resolveMachineRegistrations(paths MachinePaths, data, files, commonData string) (MachinePaths, error) {
	values := map[string]string{
		"SYSTEMDRIVE": paths.SystemDrive, "SYSTEMROOT": paths.Windows, "WINDIR": paths.Windows,
		"PROGRAMDATA": data, "ALLUSERSPROFILE": "%PROGRAMDATA%", "PROGRAMFILES": files,
	}
	programData, err := expandMachineVariables("%PROGRAMDATA%", values)
	if err != nil {
		return MachinePaths{}, fmt.Errorf("registered ProgramData expansion: %w", err)
	}
	programFiles, err := expandMachineVariables("%PROGRAMFILES%", values)
	if err != nil {
		return MachinePaths{}, fmt.Errorf("registered ProgramFilesDir expansion: %w", err)
	}
	if commonData != "" {
		// The common known-folder expression may refer to the already captured
		// ProfileList location. It does not become its own expansion authority.
		values["PROGRAMDATA"], values["ALLUSERSPROFILE"], values["PROGRAMFILES"] = programData, programData, programFiles
		programData, err = expandMachineVariables(commonData, values)
		if err != nil {
			return MachinePaths{}, fmt.Errorf("registered Common AppData expansion: %w", err)
		}
	}
	paths.ProgramData, err = validateMachineDirectory(programData)
	if err != nil {
		return MachinePaths{}, fmt.Errorf("captured ProgramData: %w", err)
	}
	paths.ProgramFiles, err = validateMachineDirectory(programFiles)
	if err != nil {
		return MachinePaths{}, fmt.Errorf("captured ProgramFiles: %w", err)
	}
	return paths, nil
}

func readMachineRegistration(read *syscall.Proc, key, name string, optional bool) (string, bool, error) {
	key16, err := syscall.UTF16PtrFromString(key)
	if err != nil {
		return "", false, err
	}
	name16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", false, err
	}
	buffer := make([]uint16, machineDirectoryLimit+1)
	size, kind := uint32(len(buffer)*2), uint32(0)
	const flags = 0x2 | 0x4 | 0x10000000 | 0x00010000 | 0x20000000 // SZ/EXPAND_SZ, NOEXPAND, WOW64_64, ZEROONFAILURE
	status, _, _ := read.Call(uintptr(syscall.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(key16)),
		uintptr(unsafe.Pointer(name16)), flags, uintptr(unsafe.Pointer(&kind)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(key16)
	runtime.KeepAlive(name16)
	runtime.KeepAlive(buffer)
	if status != 0 {
		if optional && (syscall.Errno(status) == syscall.ERROR_FILE_NOT_FOUND || syscall.Errno(status) == syscall.ERROR_PATH_NOT_FOUND) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("registered machine folder %s: %w", name, syscall.Errno(status))
	}
	value, err := decodeMachineRegistration(kind, buffer, size)
	if err != nil {
		return "", false, fmt.Errorf("registered machine folder %s: %w", name, err)
	}
	return value, true, nil
}

func decodeMachineRegistration(kind uint32, buffer []uint16, size uint32) (string, error) {
	if (kind != syscall.REG_SZ && kind != syscall.REG_EXPAND_SZ) || size < 4 || size%2 != 0 ||
		size > 2*(machineDirectoryLimit+1) || uint64(size) > uint64(len(buffer))*2 {
		return "", errors.New("machine registration has an invalid type or string bound")
	}
	units := buffer[:size/2]
	if units[len(units)-1] != 0 || slices.Contains(units[:len(units)-1], 0) {
		return "", errors.New("machine registration is not one terminated string")
	}
	units = units[:len(units)-1]
	runes := utf16.Decode(units)
	if !slices.Equal(utf16.Encode(runes), units) {
		return "", errors.New("machine registration has invalid UTF-16")
	}
	value := string(runes)
	if len(value) > machineDirectoryLimit || strings.ContainsAny(value, "\r\n") ||
		(kind == syscall.REG_SZ && strings.Contains(value, "%")) {
		return "", errors.New("machine registration is not a bounded unambiguous string")
	}
	return value, nil
}

func expandMachineVariables(value string, captured map[string]string) (string, error) {
	if len(captured) == 0 || len(captured) > 6 {
		return "", errors.New("machine expansion has no bounded captured namespace")
	}
	values := make(map[string]string, len(captured))
	for name, entry := range captured {
		name = strings.ToUpper(name)
		switch name {
		case "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR", "PROGRAMDATA", "ALLUSERSPROFILE", "PROGRAMFILES":
		default:
			return "", errors.New("machine expansion contains an uncaptured variable")
		}
		if _, exists := values[name]; exists || entry == "" || len(entry) > machineDirectoryLimit || strings.ContainsAny(entry, "\x00\r\n") {
			return "", errors.New("machine expansion has an ambiguous captured variable")
		}
		values[name] = entry
	}
	active, resolved := make(map[string]bool), make(map[string]string)
	var expand func(string) (string, error)
	expand = func(input string) (string, error) {
		if input == "" || len(input) > machineDirectoryLimit || strings.ContainsAny(input, "\x00\r\n") {
			return "", errors.New("machine expansion input is unbounded or malformed")
		}
		var result strings.Builder
		for input != "" {
			literal, remainder, found := strings.Cut(input, "%")
			if result.Len()+len(literal) > machineDirectoryLimit {
				return "", errors.New("expanded machine registration exceeds its bound")
			}
			result.WriteString(literal)
			if !found {
				break
			}
			name, rest, closed := strings.Cut(remainder, "%")
			name = strings.ToUpper(name)
			entry, exists := values[name]
			if !closed || !exists || active[name] {
				return "", errors.New("machine expansion has a missing, unknown or cyclic reference")
			}
			expanded, cached := resolved[name]
			if !cached {
				active[name] = true
				var err error
				expanded, err = expand(entry)
				delete(active, name)
				if err != nil {
					return "", err
				}
				resolved[name] = expanded
			}
			if result.Len()+len(expanded) > machineDirectoryLimit {
				return "", errors.New("expanded machine registration exceeds its bound")
			}
			result.WriteString(expanded)
			input = rest
		}
		return result.String(), nil
	}
	return expand(value)
}

func validateMachineDirectory(value string) (string, error) {
	if value == "" || len(value) > machineDirectoryLimit || strings.ContainsAny(value, "%\x00\r\n/") || !filepath.IsAbs(value) {
		return "", errors.New("machine folder is not a bounded absolute path")
	}
	clean := filepath.Clean(value)
	root, err := executableRoot(clean)
	if err != nil || (len(root) == 3 && !((root[0] >= 'A' && root[0] <= 'Z') || (root[0] >= 'a' && root[0] <= 'z'))) {
		return "", errors.New("machine folder is not on a local filesystem volume")
	}
	if clean != root {
		for _, component := range strings.Split(clean[len(root):], `\`) {
			if component == "" || strings.TrimRight(component, ". ") != component || strings.ContainsAny(component, `:<>"|?*`) {
				return "", errors.New("machine folder contains an ambiguous path component")
			}
			for _, character := range component {
				if character < 32 {
					return "", errors.New("machine folder contains a control character")
				}
			}
		}
	}
	return clean, nil
}
