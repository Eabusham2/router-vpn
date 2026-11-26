package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
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
	// Change only a real producer's dynamic dependency string. The complete
	// native ELF parser must still reject ambient crypto and a foreign loader.
	raw, err := os.ReadFile(filepath.Join(source, bundledDNSSECLibrary))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Close()
	strings := parsed.Section(".dynstr")
	if strings == nil {
		t.Fatal("actual validator has no dynamic string table")
	}
	replaceDependency := func(from, to string) {
		t.Helper()
		data, err := strings.Data()
		if err != nil {
			t.Fatal(err)
		}
		needed, err := parsed.DynValue(elf.DT_NEEDED)
		if err != nil {
			t.Fatal(err)
		}
		index := -1
		for _, offset := range needed {
			if offset < uint64(len(data)) && bytes.HasPrefix(data[offset:], append([]byte(from), 0)) {
				index = int(offset)
				break
			}
		}
		if index < 0 || len(to) > len(from) {
			t.Fatal("actual validator is missing its captured dependency", from)
		}
		changed := bytes.Clone(raw)
		offset := int(strings.Offset) + index
		clear(changed[offset : offset+len(from)+1])
		copy(changed[offset:], to)
		if _, _, _, err := bundledDNSSECIdentity(changed, target); err == nil {
			t.Fatal("native validator accepted an unowned dependency", to)
		}
	}
	replaceDependency("libc.so.6", "libssl.so")
	for _, dependency := range original.Build.Needed {
		if dependency == "ld-linux-aarch64.so.1" {
			replaceDependency(dependency, "ld-linux-x86-64.so.2")
		}
	}
	t.Run("missing", func(t *testing.T) {
		directory := t.TempDir()
		for _, name := range bundledDNSSECNames {
			if name == bundledDNSSECReceiptName {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(source, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := verifyBundledDNSSECPayload(directory, target); err == nil {
			t.Fatal("package without receipt accepted")
		}
	})
}
