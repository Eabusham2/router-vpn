package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

const bundledDNSSECLibrary = "libroutervpn_dnssec.so"
const bundledDNSSECReceiptName = "DNSSEC-VALIDATOR.json"
const bundledDNSSECShimSHA = "e23fa88ed8b52922a71dbfd0018d42e93b9f76420a21c6e6835dfd7652c1fc6e"
const bundledDNSSECHeaderSHA = "7182ea1e70b2b710cb6573d1d31ae4d19dbf8741a93bd952b9a293c1f5c7e930"
const bundledDNSSECBuilderSHA = "b6dbb564dec73d1e242a435831bc5e453dd2e2722dd96303765089f2ec8aa872"
const bundledDNSSECLockSHA = "e7a2ef2ccf5a71970e7118daf2fb6433149acfc7e4c2ed74f775fb235392ead9"

var bundledDNSSECNames = []string{bundledDNSSECLibrary, bundledDNSSECReceiptName, "DNSSEC-UNBOUND-LICENSE", "DNSSEC-OPENSSL-LICENSE"}
var bundledDNSSECExports = []string{"rvdns_abi", "rvdns_anchor", "rvdns_cancel", "rvdns_create", "rvdns_destroy", "rvdns_fd", "rvdns_insecure", "rvdns_process", "rvdns_result", "rvdns_start"}
var bundledDNSSECInputs = []string{
	"native/dnssec/README.md", "native/dnssec/sources.json", "native/dnssec/validator.c", "native/dnssec/validator.h", "native/dnssec/zone_fixture.go.tmpl", "native/dnssec/fixture.go.mod", "native/dnssec/fixture.go.sum",
	"deploy/build-dnssec-validator.py", "deploy/verify-dnssec-validator.py", "deploy/test_dnssec_validator.py", "deploy/test_dnssec_validator_build.py", "deploy/test_dnssec_validator_package.py", "deploy/desktop-dnssec-bundle.py", "deploy/test_desktop_dnssec_bundle.py",
	"cmd/client/bundled_dnssec.go", "cmd/client/bundled_dnssec_test.go", "cmd/client/bundled_native.go",
}
var bundledDNSSECLicenses = map[string]string{
	"DNSSEC-UNBOUND-LICENSE": "8eb9a16cbfb8703090bbfa3a2028fd46bb351509a2f90dc1001e51fbe6fd45db",
	"DNSSEC-OPENSSL-LICENSE": "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a",
}

type bundledDNSSECBuild struct {
	Schema       int               `json:"schema"`
	ABI          int               `json:"abi"`
	Platform     string            `json:"platform"`
	Architecture string            `json:"architecture"`
	Sources      json.RawMessage   `json:"sources"`
	SHA256       string            `json:"artifact_sha256"`
	Size         int64             `json:"artifact_size"`
	Machine      uint16            `json:"elf_machine"`
	Projection   map[string]string `json:"configure_projection"`
	Shim         string            `json:"shim_sha256"`
	Header       string            `json:"header_sha256"`
	Builder      string            `json:"builder_sha256"`
	Exports      []string          `json:"exports"`
	Needed       []string          `json:"needed"`
	Commands     [][]string        `json:"commands"`
	Compiler     string            `json:"compiler"`
}
type bundledDNSSECReceipt struct {
	Schema int                          `json:"schema"`
	ABI    int                          `json:"abi"`
	Target string                       `json:"target"`
	Inputs map[string]string            `json:"source_inputs"`
	Build  bundledDNSSECBuild           `json:"build"`
	Files  map[string]bundledNativeFile `json:"files"`
}

func bundledDNSSECPayloadBound(name, target string) int64 {
	if target != "linux/amd64" && target != "linux/arm64" {
		return 0
	}
	switch name {
	case bundledDNSSECLibrary:
		return 32 << 20
	case bundledDNSSECReceiptName:
		return 64 << 10
	case "DNSSEC-UNBOUND-LICENSE", "DNSSEC-OPENSSL-LICENSE":
		return 256 << 10
	}
	return 0
}

func bundledDNSSECIdentity(raw []byte, target string) (uint16, []string, []string, error) {
	bad := errors.New("DNSSEC library has another target, loader dependency or exported ABI")
	if len(raw) < 64 || len(raw) > 32<<20 || (target != "linux/amd64" && target != "linux/arm64") {
		return 0, nil, nil, bad
	}
	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return 0, nil, nil, bad
	}
	defer file.Close()
	machine := elf.EM_X86_64
	if target == "linux/arm64" {
		machine = elf.EM_AARCH64
	}
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Type != elf.ET_DYN || file.Machine != machine || len(file.Progs) > 128 || len(file.Sections) > 4096 {
		return 0, nil, nil, bad
	}
	stack, relro := false, false
	var loader *elf.Prog
	var dynamicSection, symbolSection *elf.Section
	for _, program := range file.Progs {
		if program.Off > uint64(len(raw)) || program.Filesz > uint64(len(raw))-program.Off {
			return 0, nil, nil, bad
		}
		if program.Type == elf.PT_LOAD && program.Flags&(elf.PF_W|elf.PF_X) == elf.PF_W|elf.PF_X {
			return 0, nil, nil, bad
		}
		if program.Type == elf.PT_GNU_RELRO {
			relro = true
		}
		if program.Type == elf.PT_DYNAMIC {
			if loader != nil {
				return 0, nil, nil, bad
			}
			loader = program
		}
		if program.Type == elf.PT_INTERP {
			return 0, nil, nil, bad
		}
		if program.Type == elf.PT_GNU_STACK {
			if stack || program.Flags&elf.PF_X != 0 {
				return 0, nil, nil, bad
			}
			stack = true
		}
	}
	if !stack || !relro {
		return 0, nil, nil, bad
	}
	dynamic, symbolTables := 0, 0
	for _, section := range file.Sections {
		if section.Flags&elf.SHF_COMPRESSED != 0 || section.Size > 64<<20 {
			return 0, nil, nil, bad
		}
		if section.Type != elf.SHT_NOBITS && (section.Offset > uint64(len(raw)) || section.Size > uint64(len(raw))-section.Offset) {
			return 0, nil, nil, bad
		}
		if section.Type == elf.SHT_DYNAMIC {
			dynamic++
			dynamicSection = section
		}
		if section.Type == elf.SHT_DYNSYM {
			symbolTables++
			symbolSection = section
		}
	}
	if dynamic != 1 || symbolTables != 1 {
		return 0, nil, nil, bad
	}
	if loader == nil || loader.Off != dynamicSection.Offset || loader.Vaddr != dynamicSection.Addr || loader.Filesz != dynamicSection.Size || int(dynamicSection.Link) >= len(file.Sections) || dynamicSection.Link != symbolSection.Link {
		return 0, nil, nil, bad
	}
	text := file.Sections[dynamicSection.Link]
	for _, section := range []*elf.Section{dynamicSection, symbolSection, text} {
		mapped := false
		for _, program := range file.Progs {
			if program.Type == elf.PT_LOAD && section.Addr >= program.Vaddr && section.Addr-program.Vaddr <= program.Filesz && section.Size <= program.Filesz-(section.Addr-program.Vaddr) && program.Off+section.Addr-program.Vaddr == section.Offset {
				mapped = true
			}
		}
		if !mapped {
			return 0, nil, nil, bad
		}
	}
	for tag, want := range map[elf.DynTag]uint64{elf.DT_STRTAB: text.Addr, elf.DT_STRSZ: text.Size, elf.DT_SYMTAB: symbolSection.Addr, elf.DT_SYMENT: 24} {
		values, e := file.DynValue(tag)
		if e != nil || len(values) != 1 || values[0] != want {
			return 0, nil, nil, bad
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH, elf.DynTag(0x7ffffffd), elf.DynTag(0x7fffffff), elf.DynTag(0x6ffffefa), elf.DynTag(0x6ffffefb), elf.DynTag(0x6ffffefc)} {
		values, e := file.DynValue(tag)
		if e != nil || len(values) != 0 {
			return 0, nil, nil, bad
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		values, e := file.DynString(tag)
		if e != nil || len(values) != 0 {
			return 0, nil, nil, bad
		}
	}
	needed, err := file.ImportedLibraries()
	if err != nil || len(needed) == 0 {
		return 0, nil, nil, bad
	}
	seen := map[string]bool{}
	for _, name := range needed {
		if seen[name] || (name != "libc.so.6" && name != "libpthread.so.0" && name != "libdl.so.2") {
			return 0, nil, nil, bad
		}
		seen[name] = true
	}
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return 0, nil, nil, bad
	}
	exports := []string{}
	for _, symbol := range symbols {
		bind, visibility := elf.ST_BIND(symbol.Info), elf.ST_VISIBILITY(symbol.Other)
		if symbol.Section != elf.SHN_UNDEF && (bind == elf.STB_GLOBAL || bind == elf.STB_WEAK) && (visibility == elf.STV_DEFAULT || visibility == elf.STV_PROTECTED) {
			exports = append(exports, symbol.Name)
		}
	}
	sort.Strings(exports)
	if !reflect.DeepEqual(exports, bundledDNSSECExports) {
		return 0, nil, nil, bad
	}
	return uint16(machine), needed, exports, nil
}

// Verification never loads this library. The authenticated native child's owner
// must independently open/hash/seal its original library descriptor before use.
func verifyBundledDNSSECPayload(directory, target string) (bundledDNSSECReceipt, error) {
	var receipt bundledDNSSECReceipt
	bad := errors.New("DNSSEC package differs from its exact native pins, source or payload")
	raw, err := bundledAmneziaRegular(filepath.Join(directory, bundledDNSSECReceiptName), 64<<10)
	if err != nil {
		return receipt, err
	}
	if decodeRelayControlJSONBounded(raw, &receipt, 64<<10) != nil {
		return receipt, bad
	}
	build := receipt.Build
	arch, machine := "x86_64", uint16(62)
	if target == "linux/arm64" {
		arch, machine = "aarch64", 183
	}
	if (target != "linux/amd64" && target != "linux/arm64") || receipt.Schema != 1 || receipt.ABI != 1 || receipt.Target != target || build.Schema != 1 || build.ABI != 1 || build.Platform != "linux" || build.Architecture != arch || build.Machine != machine || build.Shim != bundledDNSSECShimSHA || build.Header != bundledDNSSECHeaderSHA || build.Builder != bundledDNSSECBuilderSHA || !nativeDigest(build.SHA256) || build.Size <= 0 || build.Size > 32<<20 || len(build.Compiler) == 0 || len(build.Compiler) > 16384 || len(build.Commands) == 0 || len(build.Commands) > 32 {
		return receipt, bad
	}
	var actualSources, expectedSources any
	if json.Unmarshal(build.Sources, &actualSources) != nil || json.Unmarshal([]byte(bundledDNSSECSources), &expectedSources) != nil || !reflect.DeepEqual(actualSources, expectedSources) {
		return receipt, bad
	}
	if len(receipt.Inputs) != len(bundledDNSSECInputs) {
		return receipt, bad
	}
	for _, name := range bundledDNSSECInputs {
		if !nativeDigest(receipt.Inputs[name]) {
			return receipt, bad
		}
	}
	for name, want := range map[string]string{"native/dnssec/validator.c": bundledDNSSECShimSHA, "native/dnssec/validator.h": bundledDNSSECHeaderSHA, "deploy/build-dnssec-validator.py": bundledDNSSECBuilderSHA, "native/dnssec/sources.json": bundledDNSSECLockSHA} {
		if receipt.Inputs[name] != want {
			return receipt, bad
		}
	}
	projection := map[string]string{"original_sha256": "9b18d449c2aedb76816009caec44978c23ea58d34f26c7ad4cb1625ba824a329", "removed_block_sha256": "e36da3b8403ee6723434ad496633843b38655902f794f15d321bba4c29d85825", "projected_sha256": "f4b9df17aab6933befc8041f6c57c1dc7b869e52dfacbab6a4b0d80cd6500792"}
	if !reflect.DeepEqual(build.Projection, projection) || len(receipt.Files) != 3 || receipt.Files[bundledDNSSECLibrary] != (bundledNativeFile{Size: build.Size, SHA256: build.SHA256}) {
		return receipt, bad
	}
	for name, file := range receipt.Files {
		limit := bundledDNSSECPayloadBound(name, target)
		if limit == 0 || name == bundledDNSSECReceiptName || file.Size <= 0 || file.Size > limit || !nativeDigest(file.SHA256) {
			return receipt, bad
		}
		if err := verifyNativeFile(filepath.Join(directory, name), file); err != nil {
			return receipt, err
		}
	}
	for name, digest := range bundledDNSSECLicenses {
		if receipt.Files[name].SHA256 != digest {
			return receipt, bad
		}
	}
	library, err := bundledAmneziaRegular(filepath.Join(directory, bundledDNSSECLibrary), 32<<20)
	if err != nil {
		return receipt, err
	}
	sum := sha256.Sum256(library)
	if int64(len(library)) != build.Size || hex.EncodeToString(sum[:]) != build.SHA256 {
		return receipt, bad
	}
	gotMachine, needed, exports, err := bundledDNSSECIdentity(library, target)
	if err != nil || gotMachine != build.Machine || !reflect.DeepEqual(needed, build.Needed) || !reflect.DeepEqual(exports, build.Exports) {
		return receipt, bad
	}
	for _, command := range build.Commands {
		if len(command) == 0 || len(command) > 64 {
			return receipt, bad
		}
		for _, argument := range command {
			if len(argument) > 4096 || strings.ContainsRune(argument, 0) {
				return receipt, bad
			}
		}
	}
	return receipt, nil
}

const bundledDNSSECSources = `{"schema":1,"abi":1,"unbound":{"version":"1.26.2","url":"https://nlnetlabs.nl/downloads/unbound/unbound-1.26.2.tar.gz","archive_sha256":"d8ee7aa6bbb3ff1be7d9e57637d0d0ec2f18273a8efff1a0afe2c665858b96f7","licenses":{"LICENSE":"8eb9a16cbfb8703090bbfa3a2028fd46bb351509a2f90dc1001e51fbe6fd45db"}},"openssl":{"repository":"https://github.com/openssl/openssl","commit":"45e844fa2a14ec92d146bd8f5778ac130b6625fb","archive_sha256":"f54250b21795bb01240f3f9b42c384868d04460e339e39275aaaf93487f2d903","licenses":{"LICENSE.txt":"7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a"}},"source_date_epoch":1791478284}`
