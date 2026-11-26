package main

import (
	"crypto/sha256"
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
    t.Run("missing", func(t *testing.T) {
        directory := t.TempDir()
        for _, name := range bundledDNSSECNames {
            if name == bundledDNSSECReceiptName { continue }
            raw, err := os.ReadFile(filepath.Join(source, name))
            if err != nil { t.Fatal(err) }
            if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil { t.Fatal(err) }
        }
        if _, err := verifyBundledDNSSECPayload(directory, target); err == nil { t.Fatal("package without receipt accepted") }
    })
}
