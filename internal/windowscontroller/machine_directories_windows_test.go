//go:build windows

package windowscontroller

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestWindowsControllerMachineDirectories(t *testing.T) {
	// Capture an independent OS baseline before changing any environment. The
	// production implementation uses Userenv's system-only environment block;
	// this baseline uses ordinary Kernel32 and Shell known-folder APIs instead.
	want := machineDirectoriesIndependent(t)
	names := []string{"SystemDrive", "SystemRoot", "windir", "ProgramData", "ProgramFiles", "ProgramFiles(x86)",
		"ProgramW6432", "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432"}
	for _, scenario := range []string{"ordinary", "missing", "poisoned"} {
		t.Run(scenario, func(t *testing.T) {
			poison := t.TempDir()
			if scenario != "ordinary" {
				for _, name := range names {
					value := filepath.Join(poison, "unselected-"+strings.ReplaceAll(name, "(", "-"))
					t.Setenv(name, value)
					if scenario == "missing" {
						if err := os.Unsetenv(name); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			before := os.Environ()
			beforeNative := machineNativeEnvironmentSnapshot(t)
			defer func() {
				if t.Failed() {
					// Failure evidence never changes the assertion or repairs the
					// poisoned process environment. Log only fixed machine fields.
					machineDirectoriesFailureDiagnostic(t, want)
					if !reflect.DeepEqual(before, os.Environ()) || !reflect.DeepEqual(beforeNative, machineNativeEnvironmentSnapshot(t)) {
						t.Error("machine directory diagnostic changed its caller environment")
					}
				}
			}()
			for attempt := 0; attempt < 2; attempt++ {
				got, err := MachineDirectories()
				if !reflect.DeepEqual(before, os.Environ()) || !reflect.DeepEqual(beforeNative, machineNativeEnvironmentSnapshot(t)) {
					t.Fatal("machine directory capture changed its caller environment")
				}
				if err != nil {
					t.Fatal("machine directory capture used or required inherited environment", err)
				}
				for name, pair := range map[string][2]string{
					"system": {got.System, want.System}, "windows": {got.Windows, want.Windows},
					"program-data": {got.ProgramData, want.ProgramData}, "program-files": {got.ProgramFiles, want.ProgramFiles},
				} {
					left, leftErr := os.Stat(pair[0])
					right, rightErr := os.Stat(pair[1])
					if leftErr != nil || rightErr != nil || !left.IsDir() || !right.IsDir() || !os.SameFile(left, right) {
						t.Fatal("machine directory capture used or required inherited environment", name, leftErr, rightErr)
					}
				}
				if !strings.EqualFold(got.SystemDrive, want.SystemDrive) {
					t.Fatal("machine directory capture changed its independently observed system drive")
				}
			}
			entries, err := os.ReadDir(poison)
			if err != nil || len(entries) != 0 {
				t.Fatal("read-only machine capture created an unselected directory", err)
			}
		})
	}
	t.Run("bounded-records", func(t *testing.T) {
		valid := []string{"SystemDrive=" + want.SystemDrive, "SystemRoot=" + want.Windows, "windir=" + want.Windows,
			"ProgramData=" + want.ProgramData, "ProgramFiles=" + want.ProgramFiles, "PATH=machine-only"}
		parsed, err := parseMachineEnvironment(valid)
		if err != nil || parsed["PROGRAMDATA"] != want.ProgramData || parsed["PROGRAMFILES"] != want.ProgramFiles {
			t.Fatal("bounded independent machine environment was rejected", err)
		}
		invalid := [][]string{nil, {}, make([]string, 8193)}
		for _, value := range []string{"malformed", "=empty-name", "BAD=contains\x00nul", "BAD=contains\nnewline", "BAD=contains\rreturn", "LONG=" + strings.Repeat("a", 32768)} {
			invalid = append(invalid, append(append([]string(nil), valid...), value))
		}
		invalid = append(invalid, append(append([]string(nil), valid...), "programdata="+want.ProgramData))
		for index := 0; index < 5; index++ {
			missing := append([]string(nil), valid[:index]...)
			missing = append(missing, valid[index+1:]...)
			invalid = append(invalid, missing)
			empty := append([]string(nil), valid...)
			name, _, _ := strings.Cut(empty[index], "=")
			empty[index] = name + "="
			invalid = append(invalid, empty)
		}
		for index, entries := range invalid {
			if _, err := parseMachineEnvironment(entries); err == nil {
				t.Fatalf("malformed or incomplete machine environment was admitted at case %d", index)
			}
		}
		for _, value := range []string{"", `relative\machine`, `C:relative`, `%SystemDrive%\ProgramData`, `C:\%Unexpanded%`,
			`\\.\PhysicalDrive0`, `\\?\GLOBALROOT\Device\HarddiskVolume1`, "C:\\machine\n", strings.Repeat("a", 32761)} {
			if _, err := validateMachineDirectory(value); err == nil {
				t.Fatal("unsafe or unresolved registered machine path was admitted")
			}
		}
	})
}

// These read-only observations run only after the actual admission assertion
// fails. They distinguish native APIs and explicit-token behavior; none is a
// fallback or authority to admit the failed result. No complete environment,
// profile, credentials or registry contents are written to the test log.
func machineDirectoriesFailureDiagnostic(t *testing.T, baseline MachinePaths) {
	t.Helper()
	bounded := func(value string) string {
		if len(value) > 512 {
			return "<machine path exceeds diagnostic bound>"
		}
		return value
	}
	readPath := func(value *uint16) string {
		if value == nil {
			return "<absent>"
		}
		for size := 0; size < 32768; size++ {
			if *(*uint16)(unsafe.Add(unsafe.Pointer(value), size*2)) == 0 {
				return bounded(syscall.UTF16ToString(unsafe.Slice(value, size)))
			}
		}
		return "<unterminated native machine path>"
	}
	load := func(name string) *syscall.DLL {
		library, err := syscall.LoadDLL(filepath.Join(baseline.System, name))
		if err != nil {
			t.Logf("machine-directory diagnostic: load %s error=%v", name, err)
			return nil
		}
		t.Cleanup(func() {
			if err := library.Release(); err != nil {
				t.Error("machine-directory diagnostic library close failed", name, err)
			}
		})
		return library
	}
	tokens := []struct {
		name  string
		value uintptr
	}{{name: "NULL"}}
	process, processErr := syscall.GetCurrentProcess()
	var token syscall.Token
	if processErr == nil {
		processErr = syscall.OpenProcessToken(process, syscall.TOKEN_QUERY|syscall.TOKEN_IMPERSONATE|syscall.TOKEN_DUPLICATE, &token)
	}
	if processErr != nil {
		t.Logf("machine-directory diagnostic: explicit current token unavailable error=%v", processErr)
	} else {
		defer func() {
			if err := token.Close(); err != nil {
				t.Error("machine-directory diagnostic token close failed", err)
			}
		}()
		tokens = append(tokens, struct {
			name  string
			value uintptr
		}{"current-primary", uintptr(token)})
	}
	// SHGetKnownFolderPath requires QUERY|IMPERSONATE and sometimes DUPLICATE
	// for an explicit token; the ordinary baseline was captured before poisoning.
	shell, ole := load("shell32.dll"), load("ole32.dll")
	if shell != nil && ole != nil {
		known, knownErr := shell.FindProc("SHGetKnownFolderPath")
		free, freeErr := ole.FindProc("CoTaskMemFree")
		if knownErr != nil || freeErr != nil {
			t.Logf("machine-directory diagnostic: known-folder procedures unavailable known=%v free=%v", knownErr, freeErr)
		} else {
			identifier := syscall.GUID{Data1: 0x62ab5d82, Data2: 0xfdc1, Data3: 0x4dc3, Data4: [8]byte{0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97}}
			for _, choice := range tokens {
				var value *uint16
				status, _, _ := known.Call(uintptr(unsafe.Pointer(&identifier)), 0x4000 /* DONT_VERIFY */, choice.value, uintptr(unsafe.Pointer(&value)))
				runtime.KeepAlive(identifier)
				t.Logf("machine-directory diagnostic: SHGetKnownFolderPath ProgramData token=%s HRESULT=0x%08x value=%q", choice.name, uint32(status), readPath(value))
				if value != nil {
					free.Call(uintptr(unsafe.Pointer(value)))
				}
			}
		}
	}
	userenv := load("userenv.dll")
	if userenv == nil {
		return
	}
	// https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-getallusersprofiledirectoryw
	if allUsers, err := userenv.FindProc("GetAllUsersProfileDirectoryW"); err != nil {
		t.Logf("machine-directory diagnostic: GetAllUsersProfileDirectoryW unavailable error=%v", err)
	} else {
		buffer := make([]uint16, 32768)
		size := uint32(len(buffer))
		ok, _, callErr := allUsers.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
		runtime.KeepAlive(buffer)
		value := "<not returned>"
		if ok != 0 && size > 0 && size <= uint32(len(buffer)) {
			value = readPath(&buffer[0])
		}
		t.Logf("machine-directory diagnostic: GetAllUsersProfileDirectoryW success=%t size=%d value=%q error=%v", ok != 0, size, value, callErr)
	}
	create, createErr := userenv.FindProc("CreateEnvironmentBlock")
	destroy, destroyErr := userenv.FindProc("DestroyEnvironmentBlock")
	if createErr != nil || destroyErr != nil {
		t.Logf("machine-directory diagnostic: environment procedures unavailable create=%v destroy=%v", createErr, destroyErr)
		return
	}
	for _, choice := range tokens {
		var block unsafe.Pointer
		ok, _, callErr := create.Call(uintptr(unsafe.Pointer(&block)), choice.value, 0 /* no inheritance */)
		if ok == 0 || block == nil {
			t.Logf("machine-directory diagnostic: CreateEnvironmentBlock token=%s inherit=false success=%t error=%v", choice.name, ok != 0, callErr)
		} else {
			entries, err := readMachineEnvironment(block)
			if err != nil {
				t.Logf("machine-directory diagnostic: CreateEnvironmentBlock token=%s read error=%v", choice.name, err)
			} else {
				for _, name := range []string{"SYSTEMDRIVE", "SYSTEMROOT", "WINDIR", "PROGRAMDATA", "PROGRAMFILES"} {
					value, matches := "", 0
					for _, entry := range entries {
						key, candidate, found := strings.Cut(entry, "=")
						if found && strings.EqualFold(key, name) {
							value, matches = candidate, matches+1
						}
					}
					t.Logf("machine-directory diagnostic: CreateEnvironmentBlock token=%s inherit=false field=%s matches=%d value=%q", choice.name, name, matches, bounded(value))
				}
			}
		}
		if block != nil {
			if ok, _, callErr := destroy.Call(uintptr(block)); ok == 0 {
				t.Error("machine-directory diagnostic environment close failed", callErr)
			}
		}
	}
}

func machineNativeEnvironmentSnapshot(t *testing.T) []uint16 {
	t.Helper()
	block, err := syscall.GetEnvironmentStrings()
	if err != nil || block == nil {
		t.Fatal("independent native caller environment is unavailable", err)
	}
	defer func() {
		if err := syscall.FreeEnvironmentStrings(block); err != nil {
			t.Error("independent native environment snapshot did not close", err)
		}
	}()
	// Check the actual process block as well as Go's cached environment. Never
	// print its contents: unrelated caller values are outside this test's scope.
	values := make([]uint16, 0, 4096)
	for offset := 0; offset < 1<<20; offset++ {
		value := *(*uint16)(unsafe.Add(unsafe.Pointer(block), offset*2))
		values = append(values, value)
		if value == 0 && offset > 0 && values[offset-1] == 0 {
			return values
		}
	}
	t.Fatal("independent native caller environment is unbounded")
	return nil
}

func machineDirectoriesIndependent(t *testing.T) MachinePaths {
	t.Helper()
	kernel := syscall.NewLazyDLL("kernel32.dll") // OS KnownDLL, independent of the environment.
	read := func(name string) string {
		procedure := kernel.NewProc(name)
		if err := procedure.Find(); err != nil {
			t.Fatal(err)
		}
		buffer := make([]uint16, 32768)
		length, _, callErr := procedure.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		if length == 0 || length >= uintptr(len(buffer)) {
			t.Fatal("independent native directory baseline is unavailable", name, callErr)
		}
		return syscall.UTF16ToString(buffer[:length])
	}
	system, windows := read("GetSystemDirectoryW"), read("GetWindowsDirectoryW")
	shell, err := syscall.LoadDLL(filepath.Join(system, "shell32.dll"))
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Release()
	ole, err := syscall.LoadDLL(filepath.Join(system, "ole32.dll"))
	if err != nil {
		t.Fatal(err)
	}
	defer ole.Release()
	known, err := shell.FindProc("SHGetKnownFolderPath")
	if err != nil {
		t.Fatal(err)
	}
	free, err := ole.FindProc("CoTaskMemFree")
	if err != nil {
		t.Fatal(err)
	}
	folder := func(identifier syscall.GUID) string {
		var value *uint16
		status, _, _ := known.Call(uintptr(unsafe.Pointer(&identifier)), 0x4000, 0, uintptr(unsafe.Pointer(&value)))
		runtime.KeepAlive(identifier)
		if value != nil {
			defer free.Call(uintptr(unsafe.Pointer(value)))
		}
		if uint32(status) != 0 || value == nil {
			t.Fatalf("independent registered machine folder is unavailable (HRESULT 0x%08x)", uint32(status))
		}
		for size := 0; size < 32768; size++ {
			if *(*uint16)(unsafe.Add(unsafe.Pointer(value), size*2)) == 0 {
				path := syscall.UTF16ToString(unsafe.Slice(value, size))
				if path == "" || !filepath.IsAbs(path) || strings.Contains(path, "%") {
					t.Fatal("independent registered machine baseline is unresolved or nonabsolute")
				}
				return path
			}
		}
		t.Fatal("independent registered machine baseline is unbounded")
		return ""
	}
	// FOLDERID_ProgramData and architecture-appropriate FOLDERID_ProgramFiles;
	// no conventional C:\ locations are assumed for either registered folder.
	programData := folder(syscall.GUID{Data1: 0x62ab5d82, Data2: 0xfdc1, Data3: 0x4dc3, Data4: [8]byte{0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97}})
	programFiles := folder(syscall.GUID{Data1: 0x905e63b6, Data2: 0xc1bf, Data3: 0x494e, Data4: [8]byte{0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a}})
	return MachinePaths{System: system, Windows: windows, SystemDrive: filepath.VolumeName(windows), ProgramData: programData, ProgramFiles: programFiles}
}
