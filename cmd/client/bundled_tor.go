package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const bundledTorVersion = "0.4.9.14"
const bundledTorRevision = "4a522a3ca491c6c04d4a44cb006b92101c42efc1"
const bundledTorSourceSHA = "ca52ffdbda44d1554c6ac0cadd7ce84bca2c1e1f46f5ca6c5aaab1d34bf0459f"
const bundledTorPaddingSHA = "011dc1e4c3e3b60fcc3b72ec180252cff3003c37b03fbed132f2fe58e2cf8be5"
const bundledTorMaxBytes = 64 << 20

var bundledTorRecords = []string{"TOR-RUNTIME.json", "TOR-SOURCE-LOCK.json", "TOR-PADDING-SOURCE-LOCK.json", "TOR-LICENSES.json"}
var bundledTorInputs = []string{
	"deploy/build-desktop-tor.py", "deploy/desktop_tor_package.py", "deploy/build-server-tor.py",
	"server/scripts/server_tor_package.py", "deploy/build-mobile-tor-package.py",
	"deploy/install-desktop-windows-toolchain.py", "mobile/torpack/sources.json",
	"deploy/apply-tor-padding.py", "mobile/tor/padding-source-lock.json", "mobile/tor/padding-integration.patch",
	"mobile/tor/routervpn_padding.c", "mobile/tor/routervpn_padding.h", "mobile/tor/test_routervpn_padding.c",
	"mobile/tor/routervpn_lastrelay.c", "mobile/tor/routervpn_lastrelay.h", "mobile/tor/test_routervpn_lastrelay.c",
}

type bundledTorIdentity struct {
	Format    string   `json:"format"`
	Machine   uint32   `json:"machine"`
	Libraries []string `json:"libraries"`
}

type bundledTorReceipt struct {
	Schema         int               `json:"schema_version"`
	Runtime        string            `json:"runtime"`
	Version        string            `json:"version"`
	Revision       string            `json:"upstream_revision"`
	Target         string            `json:"target"`
	Executable     string            `json:"executable_target"`
	Execution      string            `json:"execution"`
	SourceSHA      string            `json:"source_lock_sha256"`
	PaddingSHA     string            `json:"padding_lock_sha256"`
	PaddingVersion int               `json:"padding_version"`
	Inputs         map[string]string `json:"build_inputs"`
	InputsSHA      string            `json:"build_inputs_sha256"`
	Dependencies   map[string]string `json:"static_dependencies"`
	Process        map[string]string `json:"process_source_sha256"`
	NativeTests    struct {
		Passed    bool     `json:"passed"`
		Selectors []string `json:"selectors"`
		SHA256    string   `json:"executable_sha256"`
	} `json:"native_tests"`
	Offline  map[string]any               `json:"offline_self_test"`
	Identity bundledTorIdentity           `json:"executable_identity"`
	Files    map[string]bundledNativeFile `json:"files"`
	Compiler struct {
		Version string `json:"version"`
		Target  string `json:"target"`
	} `json:"compiler"`
}

func bundledTorBinaryName(target string) string {
	if strings.HasPrefix(target, "windows/") {
		return "tor-routervpn.exe"
	}
	return "tor-routervpn"
}

func bundledTorExecution(target string) (string, string, error) {
	switch target {
	case "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64":
		return target, "native", nil
	case "windows/arm64":
		return "windows/amd64", "windows11-amd64-emulation", nil
	default:
		return "", "", errors.New("unsupported bundled Tor target")
	}
}

func bundledTorPayloadBound(name, target string) int64 {
	if name == bundledTorBinaryName(target) {
		return bundledTorMaxBytes
	}
	for _, record := range bundledTorRecords {
		if name == record {
			if name == "TOR-LICENSES.json" {
				return 256 << 10
			}
			return 32 << 10
		}
	}
	return 0
}

func bundledTorDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func bundledTorOfflineReceipt() map[string]any {
	return map[string]any{"scope": "offline-disabled-network-loopback-control", "version": "tor " + bundledTorVersion,
		"safecookie": true, "incorrect_authentication_rejected": true, "process_and_listener_identity": true,
		"disabled_network_retained": true, "pt_socket_configuration": true, "owning_controller_exit": true,
		"owned_padding_capability": true, "padding_rejected_while_disabled": true, "padding_without_owner_rejected": true,
		"owned_lastrelay_capability": true, "lastrelay_rejected_while_disabled": true, "lastrelay_without_owner_rejected": true}
}

// debug/pe.ImportedLibraries is unimplemented in the pinned Go toolchain.
// Resolve bounded import RVAs ourselves, including delay imports, rather than
// accepting an empty dependency list or trusting a compiler PATH DLL.
func bundledTorPELibraries(raw []byte, f *pe.File, h *pe.OptionalHeader64) ([]string, error) {
	bad := errors.New("bundled Tor has malformed or incomplete PE dependency tables")
	if len(raw) < 64 || h.NumberOfRvaAndSizes < 14 || h.NumberOfRvaAndSizes > 16 || len(f.Sections) == 0 || len(f.Sections) > 96 {
		return nil, bad
	}
	peOffset := uint64(binary.LittleEndian.Uint32(raw[0x3c:]))
	if peOffset+24+uint64(f.SizeOfOptionalHeader)+40*uint64(len(f.Sections)) > uint64(h.SizeOfHeaders) || uint64(h.SizeOfHeaders) > uint64(len(raw)) || h.SizeOfHeaders >= h.SizeOfImage {
		return nil, bad
	}
	for index, section := range f.Sections {
		extent := uint64(max(section.VirtualSize, section.Size))
		if extent == 0 || section.VirtualAddress < h.SizeOfHeaders || uint64(section.VirtualAddress)+extent > uint64(h.SizeOfImage) || section.Size > 0 && (section.Offset < h.SizeOfHeaders || uint64(section.Offset)+uint64(section.Size) > uint64(len(raw))) {
			return nil, bad
		}
		for _, other := range f.Sections[:index] {
			if max(uint64(section.VirtualAddress), uint64(other.VirtualAddress)) < min(uint64(section.VirtualAddress)+extent, uint64(other.VirtualAddress)+uint64(max(other.VirtualSize, other.Size))) || section.Size > 0 && other.Size > 0 && max(uint64(section.Offset), uint64(other.Offset)) < min(uint64(section.Offset)+uint64(section.Size), uint64(other.Offset)+uint64(other.Size)) {
				return nil, bad
			}
		}
	}
	location := func(rva, size uint32) (uint64, uint64, bool) {
		if rva > 0 && rva < h.SizeOfHeaders && uint64(rva)+uint64(size) <= uint64(h.SizeOfHeaders) {
			return uint64(rva), uint64(h.SizeOfHeaders - rva), true
		}
		for _, section := range f.Sections {
			if rva >= section.VirtualAddress {
				delta := uint64(rva - section.VirtualAddress)
				if delta+uint64(size) <= uint64(section.Size) {
					return uint64(section.Offset) + delta, uint64(section.Size) - delta, true
				}
			}
		}
		return 0, 0, false
	}
	namePattern := regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9_-]*\.dll$`)
	libraries := []string{}
	for _, table := range [][2]uint32{{1, 20}, {13, 32}} {
		directory := h.DataDirectory[table[0]]
		if directory.VirtualAddress == 0 && directory.Size == 0 {
			continue
		}
		if directory.VirtualAddress == 0 || directory.Size < table[1] || directory.Size > 1<<20 {
			return nil, bad
		}
		offset, _, ok := location(directory.VirtualAddress, directory.Size)
		if !ok {
			return nil, bad
		}
		terminated := false
		for index := uint32(0); index < min(directory.Size/table[1], 257); index++ {
			start := offset + uint64(index*table[1])
			row := raw[start : start+uint64(table[1])]
			if bytes.Equal(row, make([]byte, table[1])) {
				terminated = true
				break
			}
			if index == 256 || table[0] == 13 && binary.LittleEndian.Uint32(row) != 1 {
				return nil, bad
			}
			nameOffset := 12
			if table[0] == 13 {
				nameOffset = 4
			}
			nameRVA := binary.LittleEndian.Uint32(row[nameOffset:])
			nameStart, available, ok := location(nameRVA, 1)
			if !ok {
				return nil, bad
			}
			span := raw[nameStart : nameStart+min(available, 256)]
			end := bytes.IndexByte(span, 0)
			if end < 0 || !namePattern.Match(span[:end]) {
				return nil, bad
			}
			libraries = append(libraries, strings.ToLower(string(span[:end])))
		}
		if !terminated {
			return nil, bad
		}
	}
	if len(libraries) == 0 {
		return nil, bad
	}
	return libraries, nil
}

func bundledTorExecutableIdentity(raw []byte, target string) (bundledTorIdentity, error) {
	var identity bundledTorIdentity
	executable, _, err := bundledTorExecution(target)
	if err != nil {
		return identity, err
	}
	bad := errors.New("bundled Tor executable target or static dependency identity differs")
	identity.Libraries = []string{}
	switch {
	case strings.HasPrefix(executable, "linux/"):
		f, err := elf.NewFile(bytes.NewReader(raw))
		if err != nil {
			return identity, bad
		}
		defer f.Close()
		wanted := elf.EM_X86_64
		if executable == "linux/arm64" {
			wanted = elf.EM_AARCH64
		}
		if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != wanted || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
			return identity, bad
		}
		loads, relro, stack := 0, false, false
		for _, p := range f.Progs {
			if p.Off > uint64(len(raw)) || p.Filesz > uint64(len(raw))-p.Off || p.Filesz > p.Memsz {
				return identity, bad
			}
			switch p.Type {
			case elf.PT_INTERP:
				return identity, bad
			case elf.PT_DYNAMIC:
				if p.Filesz%16 != 0 {
					return identity, bad
				}
				for offset := p.Off; offset < p.Off+p.Filesz; offset += 16 {
					if binary.LittleEndian.Uint64(raw[offset:]) == uint64(elf.DT_NEEDED) {
						return identity, bad
					}
				}
			case elf.PT_LOAD:
				loads++
				if p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
					return identity, bad
				}
			case elf.PT_GNU_RELRO:
				relro = true
			case elf.PT_GNU_STACK:
				stack = p.Flags&elf.PF_X == 0
			}
		}
		libraries, err := f.ImportedLibraries()
		if err != nil || len(libraries) != 0 || loads == 0 || !relro || !stack {
			return identity, bad
		}
		identity.Format, identity.Machine = "ELF64", uint32(wanted)
	case strings.HasPrefix(executable, "darwin/"):
		if len(raw) < 32 || binary.LittleEndian.Uint32(raw) != macho.Magic64 {
			return identity, bad
		}
		wanted := macho.CpuAmd64
		if executable == "darwin/arm64" {
			wanted = macho.CpuArm64
		}
		cpu, kind := binary.LittleEndian.Uint32(raw[4:]), binary.LittleEndian.Uint32(raw[12:])
		count, size, flags := binary.LittleEndian.Uint32(raw[16:]), uint64(binary.LittleEndian.Uint32(raw[20:])), binary.LittleEndian.Uint32(raw[24:])
		if cpu != uint32(wanted) || kind != uint32(macho.TypeExec) || flags&macho.FlagPIE == 0 || count == 0 || count > 256 || size == 0 || size > uint64(len(raw))-32 {
			return identity, bad
		}
		offset := uint64(32)
		libraries := []string{}
		for index := uint32(0); index < count; index++ {
			if offset+8 > 32+size {
				return identity, bad
			}
			command, length := binary.LittleEndian.Uint32(raw[offset:]), uint64(binary.LittleEndian.Uint32(raw[offset+4:]))
			if length < 8 || length%8 != 0 || offset+length > 32+size || command == 0x8000001c {
				return identity, bad
			}
			switch command {
			case 0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023:
				if length < 24 {
					return identity, bad
				}
				start := uint64(binary.LittleEndian.Uint32(raw[offset+8:]))
				if start < 24 || start >= length {
					return identity, bad
				}
				span := raw[offset+start : offset+length]
				end := bytes.IndexByte(span, 0)
				if end < 0 {
					return identity, bad
				}
				libraries = append(libraries, string(span[:end]))
			}
			offset += length
		}
		if offset != 32+size {
			return identity, bad
		}
		foundSystem := false
		for _, library := range libraries {
			if library == "/usr/lib/libSystem.B.dylib" {
				foundSystem = true
			} else if library != "/usr/lib/libresolv.9.dylib" {
				return identity, bad
			}
		}
		if !foundSystem {
			return identity, bad
		}
		identity.Format, identity.Machine, identity.Libraries = "Mach-O64", uint32(wanted), libraries
	default:
		f, err := pe.NewFile(bytes.NewReader(raw))
		if err != nil {
			return identity, bad
		}
		defer f.Close()
		header, ok := f.OptionalHeader.(*pe.OptionalHeader64)
		if !ok || f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || f.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
			return identity, bad
		}
		libraries, err := bundledTorPELibraries(raw, f, header)
		if err != nil || len(libraries) == 0 {
			return identity, bad
		}
		allowed := map[string]bool{"advapi32.dll": true, "bcrypt.dll": true, "crypt32.dll": true, "gdi32.dll": true,
			"iphlpapi.dll": true, "kernel32.dll": true, "msvcrt.dll": true, "ntdll.dll": true, "secur32.dll": true,
			"shell32.dll": true, "shlwapi.dll": true, "user32.dll": true, "userenv.dll": true, "ws2_32.dll": true}
		api := regexp.MustCompile(`^(?:api|ext)-ms-win-[a-z0-9-]+-l\d+-\d+-\d+\.dll$`)
		for index, library := range libraries {
			library = strings.ToLower(library)
			if !allowed[library] && !api.MatchString(library) {
				return identity, bad
			}
			libraries[index] = library
		}
		identity.Format, identity.Machine, identity.Libraries = "PE32+", uint32(pe.IMAGE_FILE_MACHINE_AMD64), libraries
	}
	sort.Strings(identity.Libraries)
	unique := identity.Libraries[:0]
	for _, library := range identity.Libraries {
		if len(unique) == 0 || unique[len(unique)-1] != library {
			unique = append(unique, library)
		}
	}
	identity.Libraries = unique
	return identity, nil
}

func verifyBundledTorPayload(directory, target string) (string, error) {
	executable, execution, err := bundledTorExecution(target)
	if err != nil {
		return "", err
	}
	bad := errors.New("bundled Tor receipt differs from its exact source, padding, execution or payload")
	data := map[string][]byte{}
	for _, name := range append(append([]string{}, bundledTorRecords...), bundledTorBinaryName(target)) {
		raw, err := bundledAmneziaRegular(filepath.Join(directory, name), bundledTorPayloadBound(name, target))
		if err != nil {
			return "", err
		}
		data[name] = raw
	}
	var receipt bundledTorReceipt
	if decodeRelayControlJSON(data["TOR-RUNTIME.json"], &receipt) != nil || receipt.Schema != 1 || receipt.Runtime != "tor-routervpn" || receipt.Version != bundledTorVersion || receipt.Revision != bundledTorRevision || receipt.Target != target || receipt.Executable != executable || receipt.Execution != execution || receipt.SourceSHA != bundledTorSourceSHA || receipt.PaddingSHA != bundledTorPaddingSHA || receipt.PaddingVersion != 1 || bundledTorDigest(data["TOR-SOURCE-LOCK.json"]) != bundledTorSourceSHA || bundledTorDigest(data["TOR-PADDING-SOURCE-LOCK.json"]) != bundledTorPaddingSHA || !receipt.NativeTests.Passed || !nativeDigest(receipt.NativeTests.SHA256) || !reflect.DeepEqual(receipt.NativeTests.Selectors, []string{"routervpn_padding/..", "routervpn_lastrelay/..", "relaycrypt/..", "cellqueue/.."}) || !reflect.DeepEqual(receipt.Offline, bundledTorOfflineReceipt()) {
		return "", bad
	}
	if len(receipt.Inputs) != len(bundledTorInputs) {
		return "", bad
	}
	inputs := append([]string{}, bundledTorInputs...)
	sort.Strings(inputs)
	combined := sha256.New()
	for _, name := range inputs {
		value := receipt.Inputs[name]
		if !nativeDigest(value) {
			return "", bad
		}
		_, _ = combined.Write([]byte(name + "\x00" + value + "\x00"))
	}
	if hex.EncodeToString(combined.Sum(nil)) != receipt.InputsSHA || receipt.Inputs["mobile/torpack/sources.json"] != bundledTorSourceSHA || receipt.Inputs["mobile/tor/padding-source-lock.json"] != bundledTorPaddingSHA || len(receipt.Dependencies) != 4 {
		return "", bad
	}
	for _, name := range []string{"libssl.a", "libcrypto.a", "libevent.a", "libz.a"} {
		if !nativeDigest(receipt.Dependencies[name]) {
			return "", bad
		}
	}
	for _, value := range []string{receipt.Compiler.Version, receipt.Compiler.Target} {
		if len(value) == 0 || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
			return "", bad
		}
	}
	// Both source records are already byte-bound to hard pins above. Their
	// relevant fields now bind the unchanged process, C patch and licenses.
	var source struct {
		Sources map[string]struct {
			Licenses map[string]string `json:"licenses"`
		} `json:"sources"`
		Process map[string]struct {
			Original string `json:"original"`
		} `json:"embedded_process_sha256"`
	}
	var padding struct {
		Patch  string `json:"patch_sha256"`
		Copies map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"copies"`
	}
	var licenses map[string]string
	if json.Unmarshal(data["TOR-SOURCE-LOCK.json"], &source) != nil || json.Unmarshal(data["TOR-PADDING-SOURCE-LOCK.json"], &padding) != nil || decodeRelayControlJSONBounded(data["TOR-LICENSES.json"], &licenses, 64<<10) != nil || len(source.Process) != len(receipt.Process) || len(licenses) != 4 || receipt.Inputs["mobile/tor/padding-integration.patch"] != padding.Patch {
		return "", bad
	}
	for name, record := range source.Process {
		if receipt.Process[name] != record.Original {
			return "", bad
		}
	}
	for name, record := range padding.Copies {
		if receipt.Inputs[name] != record.SHA256 {
			return "", bad
		}
	}
	for name, record := range source.Sources {
		for path, checksum := range record.Licenses {
			if bundledTorDigest([]byte(licenses[name+"/"+path])) != checksum {
				return "", bad
			}
		}
	}
	if len(receipt.Files) != 4 {
		return "", bad
	}
	for name, raw := range data {
		if name != "TOR-RUNTIME.json" && receipt.Files[name] != (bundledNativeFile{Size: int64(len(raw)), SHA256: bundledTorDigest(raw)}) {
			return "", bad
		}
	}
	identity, err := bundledTorExecutableIdentity(data[bundledTorBinaryName(target)], target)
	if err != nil || !reflect.DeepEqual(identity, receipt.Identity) {
		return "", bad
	}
	return filepath.Join(directory, bundledTorBinaryName(target)), nil
}

// verifyBundledTor is the sole fixed-path resolver for the complete desktop
// bundle. It never falls back to a PATH executable or an unrelated Tor tree.
func verifyBundledTor(root string) (string, error) {
	if _, err := verifyBundledNative(root); err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		if _, err := windowsTorHostCompatibility(); err != nil {
			return "", err
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, "runtime", "native")
	binary, err := verifyBundledTorPayload(directory, runtime.GOOS+"/"+runtime.GOARCH)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--version")
	command.Dir = directory
	command.Env = nativeLibraryEnvironment(os.Environ(), directory)
	output, err := command.Output()
	if err != nil || len(output) > 8192 || !regexp.MustCompile(`^Tor version 0\.4\.9\.14(?:[. (]|$)`).Match(output) {
		return "", fmt.Errorf("bundled Tor failed its exact executable version check")
	}
	return binary, nil
}
