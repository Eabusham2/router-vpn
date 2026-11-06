package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBundledDNSSECSourcePinsAndMandatoryReceipt(t *testing.T) {
	for name, want := range map[string]string{"native/dnssec/validator.c": bundledDNSSECShimSHA, "native/dnssec/validator.h": bundledDNSSECHeaderSHA, "native/dnssec/sources.json": bundledDNSSECLockSHA, "deploy/build-dnssec-validator.py": bundledDNSSECBuilderSHA} {
		raw, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("DNSSEC verifier source pin is stale", name)
		}
	}
	if runtime.GOOS != "linux" {
		return
	}
	for _, name := range bundledDNSSECNames {
		receipt := nativeReceiptFixture()
		delete(receipt.Files, name)
		raw, _ := json.Marshal(receipt)
		if _, err := validateNativeReceipt(raw); err == nil {
			t.Fatal("Linux native receipt omitted validator payload", name)
		}
	}
	if bundledDNSSECPayloadBound(bundledDNSSECLibrary, "darwin/arm64") != 0 {
		t.Fatal("validator widened another platform")
	}
}

// The native producer explicitly supplies the real pinned compiled package.
// Ordinary portable suites do not substitute a modeled ELF or fake crypto receipt.
func TestBundledDNSSECActualPackage(t *testing.T) {
	source := os.Getenv("ROUTERVPN_DNSSEC_BUNDLE")
	if source == "" {
		t.Skip("actual pinned validator package is supplied by the native producer")
	}
	target := runtime.GOOS + "/" + runtime.GOARCH
	original, err := verifyBundledDNSSECPayload(source, target)
	if err != nil {
		t.Fatal(err)
	}
	if original.Build.ABI != 1 {
		t.Fatal("actual private ABI changed")
	}
	cases := []string{"abi", "target", "builder", "duplicate-json", "artifact", "wrong-elf-machine", "ambient-dependency", "foreign-export", "loader-strtab", "inspection-dynamic", "license", "missing", "symlink"}
	for _, fault := range cases {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			for _, name := range bundledDNSSECNames {
				raw, err := os.ReadFile(filepath.Join(source, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := os.ReadFile(filepath.Join(directory, bundledDNSSECReceiptName))
			var receipt bundledDNSSECReceipt
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			reseal := false
			switch fault {
			case "abi":
				receipt.ABI++
			case "target":
				receipt.Target = "linux/foreign"
			case "builder":
				receipt.Build.Builder = receipt.Build.Shim
			case "duplicate-json":
				raw = append([]byte(`{"schema":1,`), raw[1:]...)
			case "artifact":
				file := filepath.Join(directory, bundledDNSSECLibrary)
				body, _ := os.ReadFile(file)
				body[len(body)-1] ^= 1
				os.WriteFile(file, body, 0600)
			case "wrong-elf-machine", "ambient-dependency", "foreign-export", "loader-strtab", "inspection-dynamic":
				file := filepath.Join(directory, bundledDNSSECLibrary)
				body, _ := os.ReadFile(file)
				if fault == "wrong-elf-machine" {
					body[18], body[19] = 0, 0
				} else if fault == "loader-strtab" || fault == "inspection-dynamic" {
					parsed, e := elf.NewFile(bytes.NewReader(body))
					if e != nil {
						t.Fatal(e)
					}
					found := false
					for index, section := range parsed.Sections {
						if section.Type == elf.SHT_DYNAMIC {
							if fault == "inspection-dynamic" {
								headers := binary.LittleEndian.Uint64(body[40:48])
								offset := headers + uint64(index)*64 + 24
								binary.LittleEndian.PutUint64(body[offset:offset+8], section.Offset+16)
								found = true
							} else {
								for offset := section.Offset; offset < section.Offset+section.Size; offset += 16 {
									if elf.DynTag(binary.LittleEndian.Uint64(body[offset:offset+8])) == elf.DT_STRTAB {
										value := binary.LittleEndian.Uint64(body[offset+8 : offset+16])
										binary.LittleEndian.PutUint64(body[offset+8:offset+16], value+1)
										found = true
										break
									}
								}
							}
						}
					}
					if !found {
						t.Fatal("actual loader mutation target absent")
					}
				} else {
					parsed, e := elf.NewFile(bytes.NewReader(body))
					if e != nil {
						t.Fatal(e)
					}
					section := parsed.Section(".dynstr")
					if section == nil {
						t.Fatal("actual library lost dynamic strings")
					}
					old, new := []byte("libc.so.6"), []byte("libx.so.6")
					if fault == "foreign-export" {
						old, new = []byte("rvdns_abi"), []byte("rvdns_bad")
					}
					start := bytes.Index(body[section.Offset:section.Offset+section.Size], append(old, 0))
					if start < 0 {
						t.Fatal("actual ELF mutation target absent", fault)
					}
					copy(body[int(section.Offset)+start:], new)
				}
				os.WriteFile(file, body, 0600)
				sum := sha256.Sum256(body)
				receipt.Build.SHA256 = hex.EncodeToString(sum[:])
				receipt.Files[bundledDNSSECLibrary] = bundledNativeFile{int64(len(body)), receipt.Build.SHA256}
				reseal = true
			case "license":
				name := "DNSSEC-UNBOUND-LICENSE"
				body := []byte("changed license")
				os.WriteFile(filepath.Join(directory, name), body, 0600)
				sum := sha256.Sum256(body)
				receipt.Files[name] = bundledNativeFile{int64(len(body)), hex.EncodeToString(sum[:])}
				reseal = true
			case "missing":
				os.Remove(filepath.Join(directory, bundledDNSSECLibrary))
			case "symlink":
				os.Remove(filepath.Join(directory, bundledDNSSECLibrary))
				if err := os.Symlink(filepath.Join(source, bundledDNSSECLibrary), filepath.Join(directory, bundledDNSSECLibrary)); err != nil {
					t.Fatal(err)
				}
			}
			if fault != "duplicate-json" {
				raw, err = json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(directory, bundledDNSSECReceiptName), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyBundledDNSSECPayload(directory, target); err == nil {
				t.Fatal("mutated actual DNSSEC package admitted", fault, reseal)
			}
		})
	}
}
