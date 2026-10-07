package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestWindowsTorArchitecturePolicy(t *testing.T) {
	calls := 0
	probe := func() (bool, error) { calls++; return true, nil }
	got, err := windowsTorArchitecture("amd64", probe)
	if err != nil || got != "x64 helpers" || calls != 0 {
		t.Fatalf("x64 must not require a Windows 11 API: %q %v calls=%d", got, err, calls)
	}
	got, err = windowsTorArchitecture("arm64", probe)
	if err != nil || !strings.Contains(got, "Windows emulation") || !strings.Contains(got, "ARM64 VPN engine and driver") || calls != 1 {
		t.Fatalf("ARM64 lost compatibility/native-driver distinction: %q %v", got, err)
	}
	for _, check := range []func() (bool, error){nil, func() (bool, error) { return false, nil }, func() (bool, error) { return false, errors.New("probe failed") }, func() (bool, error) { return true, errors.New("probe failed") }} {
		if mode, err := windowsTorArchitecture("arm64", check); err == nil || mode != "" {
			t.Fatal("unproved ARM64 helper execution accepted", mode, err)
		}
	}
	for _, arch := range []string{"", "386", "arm", "mips", "x64", "ARM64"} {
		if _, err := windowsTorArchitecture(arch, probe); err == nil {
			t.Fatal("unsupported architecture accepted", arch)
		}
	}
}

func TestWindowsTorHostCompatibilityNative(t *testing.T) {
	if runtime.GOOS != "windows" {
		if _, err := windowsTorHostCompatibility(); err == nil {
			t.Fatal("non-Windows host accepted")
		}
		if os.Getenv("ROUTER_VPN_REQUIRE_TOR_HELPERS") == "1" {
			t.Fatal("native Windows compatibility gate did not run on Windows")
		}
		return
	}
	mode, err := windowsTorHostCompatibility()
	if err != nil {
		if os.Getenv("ROUTER_VPN_REQUIRE_TOR_HELPERS") == "1" {
			t.Fatal(err)
		}
		t.Log("This Windows host does not offer x64 helper compatibility:", err)
		return
	}
	if runtime.GOARCH == "arm64" && !strings.Contains(mode, "Windows emulation") {
		t.Fatal("ARM64 helper execution was mislabelled", mode)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("unimplemented architecture accepted")
	}
	t.Log("Verified native host capability:", mode)
}
