//go:build windows

package windowscontroller

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

func TestWindowsControllerMachineDirectories(t *testing.T) {
	// Capture an independent OS baseline before changing any environment. The
	// production implementation reads unexpanded machine registrations; this
	// baseline uses ordinary Kernel32 and Shell known-folder APIs instead.
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
		t.Run("registry-strings", machineRegistrationStrings)
		t.Run("captured-expansion", machineCapturedExpansion)
		t.Run("registered-locations", machineRegisteredLocations)
	})
}

func machineRegistrationStrings(t *testing.T) {
	terminated := func(value string) []uint16 { return append(utf16.Encode([]rune(value)), 0) }
	for _, value := range []string{`D:\Shared Data`, `R:\Registered\資料`, `E:\Apps\𠮷`} {
		for _, kind := range []uint32{syscall.REG_SZ, syscall.REG_EXPAND_SZ} {
			buffer := terminated(value)
			got, err := decodeMachineRegistration(kind, buffer, uint32(len(buffer)*2))
			if err != nil || got != value {
				t.Fatal("bounded literal machine registration was changed or rejected", err)
			}
		}
	}
	expression := terminated(`%SystemDrive%\Registered Data`)
	if got, err := decodeMachineRegistration(syscall.REG_EXPAND_SZ, expression, uint32(len(expression)*2)); err != nil || got != `%SystemDrive%\Registered Data` {
		t.Fatal("expandable machine registration was not preserved literally", err)
	}
	for _, fixture := range []struct {
		name   string
		kind   uint32
		buffer []uint16
		size   uint32
	}{
		{"wrong-type", syscall.REG_MULTI_SZ, terminated(`D:\Data`), 16},
		{"empty", syscall.REG_SZ, []uint16{0}, 2},
		{"odd-byte-count", syscall.REG_SZ, terminated(`D:\Data`), 15},
		{"short-buffer", syscall.REG_SZ, []uint16{'D', 0}, 8},
		{"unbounded-count", syscall.REG_SZ, nil, 0xfffffffe},
		{"unbounded-buffer", syscall.REG_SZ, make([]uint16, machineDirectoryLimit+2), 2 * (machineDirectoryLimit + 2)},
		{"unterminated", syscall.REG_SZ, []uint16{'D', ':', '\\', 'a'}, 8},
		{"embedded-nul", syscall.REG_SZ, []uint16{'D', ':', '\\', 0, 'a', 0}, 12},
		{"surrogate-high", syscall.REG_SZ, []uint16{'D', ':', '\\', 0xd800, 0}, 10},
		{"surrogate-low", syscall.REG_SZ, []uint16{'D', ':', '\\', 0xdc00, 0}, 10},
		{"literal-expansion", syscall.REG_SZ, expression, uint32(len(expression) * 2)},
		{"newline", syscall.REG_SZ, terminated("D:\\Data\n"), 18},
		{"return", syscall.REG_EXPAND_SZ, terminated("D:\\Data\r"), 18},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if _, err := decodeMachineRegistration(fixture.kind, fixture.buffer, fixture.size); err == nil {
				t.Fatal("malformed or ambiguous machine registration was admitted")
			}
		})
	}
}

func machineCapturedExpansion(t *testing.T) {
	values := map[string]string{"SYSTEMDRIVE": "R:", "SYSTEMROOT": `R:\Operating System`, "WINDIR": "%SystemRoot%",
		"PROGRAMDATA": `D:\Shared Data`, "ALLUSERSPROFILE": "%PROGRAMDATA%", "PROGRAMFILES": `%AllUsersProfile%\Apps`}
	for input, want := range map[string]string{
		`%SystemDrive%\Registered`: `R:\Registered`, `%windir%\Temp`: `R:\Operating System\Temp`,
		`%ProgramFiles%\Product`: `D:\Shared Data\Apps\Product`, `E:\Redirected Data`: `E:\Redirected Data`,
		`%PROGRAMDATA%\%SystemDrive%`: `D:\Shared Data\R:`,
	} {
		before := make(map[string]string, len(values))
		for name, value := range values {
			before[name] = value
		}
		got, err := expandMachineVariables(input, values)
		if err != nil || got != want || !reflect.DeepEqual(before, values) {
			t.Fatal("captured redirected machine expansion changed its value or inputs", err)
		}
	}
	for _, input := range []string{"", "%", "%%", "%SystemDrive", "%Unknown%", "%USERPROFILE%", "%PATH%",
		"value\x00", "value\n", "value\r", strings.Repeat("a", machineDirectoryLimit+1)} {
		if _, err := expandMachineVariables(input, values); err == nil {
			t.Fatal("unknown, incomplete or unbounded machine expression was admitted")
		}
	}
	for _, captured := range []map[string]string{
		nil, {}, {"PATH": "R:"}, {"SYSTEMDRIVE": ""}, {"SYSTEMDRIVE": "R:", "systemdrive": "S:"},
		{"SYSTEMDRIVE": "%SYSTEMDRIVE%"}, {"SYSTEMDRIVE": "%SYSTEMROOT%", "SYSTEMROOT": "%SYSTEMDRIVE%"},
		{"SYSTEMROOT": `R:\OS`}, {"SYSTEMDRIVE": "R:\x00"}, {"SYSTEMDRIVE": "R:\n"},
		{"SYSTEMDRIVE": strings.Repeat("x", machineDirectoryLimit+1)},
	} {
		if _, err := expandMachineVariables("%SYSTEMDRIVE%", captured); err == nil {
			t.Fatal("missing, cyclic or ambiguous machine expansion authority was admitted")
		}
	}
	if _, err := expandMachineVariables("%PROGRAMDATA%%PROGRAMDATA%", map[string]string{"PROGRAMDATA": strings.Repeat("a", machineDirectoryLimit/2+1)}); err == nil {
		t.Fatal("expanded machine registration exceeded its output bound")
	}
}

func machineRegisteredLocations(t *testing.T) {
	paths := MachinePaths{System: `R:\Operating System\System32`, Windows: `R:\Operating System`, SystemDrive: "R:"}
	for _, fixture := range []struct{ data, files, common, wantData, wantFiles string }{
		{`%SystemDrive%\Data`, `%SystemDrive%\Apps`, "", `R:\Data`, `R:\Apps`},
		{`D:\Shared Data`, `E:\Installed Apps`, `%ProgramData%`, `D:\Shared Data`, `E:\Installed Apps`},
		{`D:\Shared Data`, `%AllUsersProfile%\Apps`, `F:\Common Data`, `F:\Common Data`, `D:\Shared Data\Apps`},
		{`D:\Shared Data`, `E:\Apps`, `%ProgramData%\Common`, `D:\Shared Data\Common`, `E:\Apps`},
		{`%SystemRoot%\Data`, `%windir%\Apps`, "%AllUsersProfile%", `R:\Operating System\Data`, `R:\Operating System\Apps`},
	} {
		got, err := resolveMachineRegistrations(paths, fixture.data, fixture.files, fixture.common)
		if err != nil || got.ProgramData != fixture.wantData || got.ProgramFiles != fixture.wantFiles ||
			got.System != paths.System || got.Windows != paths.Windows || got.SystemDrive != paths.SystemDrive {
			t.Fatal("registered custom-drive or common-folder refinement was not preserved", err)
		}
	}
	for _, fixture := range [][3]string{
		{"", `E:\Apps`, ""}, {`D:\Data`, "", ""}, {`%ProgramFiles%`, `%ProgramData%`, ""},
		{`D:\Data`, `E:\Apps`, `%UNKNOWN%`}, {`D:\Data`, `E:\Apps`, `relative`},
		{`D:\Data`, `E:\Apps`, `\\server\share`}, {`%ProgramData%`, `E:\Apps`, ""},
	} {
		if _, err := resolveMachineRegistrations(paths, fixture[0], fixture[1], fixture[2]); err == nil {
			t.Fatal("invalid registered location was replaced with a default or other location")
		}
	}
	for _, value := range []string{`R:\`, `D:\Shared Data`, `E:\Apps\資料`, `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Data`} {
		if got, err := validateMachineDirectory(value); err != nil || got != value {
			t.Fatal("bounded local registered directory was rejected", err)
		}
	}
	for _, value := range []string{"", `relative\machine`, `C:relative`, `%SystemDrive%\ProgramData`, `C:\%Unexpanded%`,
		`\\.\PhysicalDrive0`, `\\?\GLOBALROOT\Device\HarddiskVolume1`, `\\server\share`, `1:\Data`,
		`C:\bad:stream`, `C:\bad.`, `C:\bad `, `C:\bad*`, `C:\bad?`, `C:\bad|`, `C:\bad<`, `C:\bad>`, `C:\bad"`,
		`C:/Data`, "C:\\machine\n", "C:\\machine\x00", "C:\\machine\t", strings.Repeat("a", machineDirectoryLimit+1)} {
		if _, err := validateMachineDirectory(value); err == nil {
			t.Fatal("unsafe or unresolved registered machine path was admitted")
		}
	}
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
			entries, err := machineDiagnosticEnvironmentEntries(block)
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

// The obsolete Userenv approach remains only as bounded failure evidence. It
// cannot supply production machine paths or repair a failed native assertion.
func machineDiagnosticEnvironmentEntries(block unsafe.Pointer) ([]string, error) {
	entries := make([]string, 0, 64)
	start := 0
	for offset := 0; offset < 1<<20; offset++ {
		if *(*uint16)(unsafe.Add(block, offset*2)) != 0 {
			if offset-start >= 32767 {
				return nil, errors.New("diagnostic environment entry is unbounded")
			}
			continue
		}
		if offset == start {
			return entries, nil
		}
		if len(entries) >= 8192 {
			return nil, errors.New("diagnostic environment contains too many entries")
		}
		entries = append(entries, syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Add(block, start*2)), offset-start)))
		start = offset + 1
	}
	return nil, errors.New("diagnostic environment is unbounded")
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
