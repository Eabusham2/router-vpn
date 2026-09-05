package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedWindowsTorRuntimeResolverRequiresOneRegularExecutable(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "Browser", "TorBrowser", "Tor")
	if err := os.MkdirAll(nested, 0o700); err != nil { t.Fatal(err) }
	tor := filepath.Join(nested, "tor.exe")
	if err := os.WriteFile(tor, []byte("fake-tor"), 0o600); err != nil { t.Fatal(err) }
	got, err := findUniquePinnedRuntimeExecutable(root, "tor.exe", "pinned Windows Tor")
	if err != nil { t.Fatal(err) }
	if got != tor { t.Fatalf("resolved Tor=%q want %q", got, tor) }

	second := filepath.Join(root, "second")
	if err := os.MkdirAll(second, 0o700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(second, "TOR.EXE"), []byte("duplicate"), 0o600); err != nil { t.Fatal(err) }
	if _, err := findUniquePinnedRuntimeExecutable(root, "tor.exe", "pinned Windows Tor"); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("duplicate Tor executable was not rejected: %v", err)
	}
}

func TestPinnedWindowsTorRuntimeResolverRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real.exe")
	if err := os.WriteFile(target, []byte("real"), 0o600); err != nil { t.Fatal(err) }
	link := filepath.Join(root, "tor.exe")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable on this test platform: %v", err)
	}
	if _, err := findUniquePinnedRuntimeExecutable(root, "tor.exe", "pinned Windows Tor"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("symlink Tor executable was not rejected: %v", err)
	}
}

func TestWindowsTorControllerUsesPinnedNativeLifecycle(t *testing.T) {
	runtimeBody, err := os.ReadFile("tor_bridge_runtime.go")
	if err != nil { t.Fatal(err) }
	source := string(runtimeBody)
	for _, marker := range []string{
		`case "windows":`,
		`runtime.GOARCH != "amd64"`,
		`windowsTorRuntimeExecutable(root, "tor.exe")`,
		`windowsTorRuntimeExecutable(root, "lyrebird.exe")`,
		`windowsTorRuntimeExecutable(root, "sing-box.exe")`,
		`native-tor-bridge-windows.ps1`,
		`safeExecutable("powershell.exe")`,
		`"-Action", "up"`,
		`"-TunnelAlias", "router-vpn-tor"`,
	} {
		if !strings.Contains(source, marker) { t.Fatalf("Windows Tor controller lost %q", marker) }
	}

	helperBody, err := os.ReadFile("../../client/native-tor-bridge-windows.ps1")
	if err != nil { t.Fatal(err) }
	helper := string(helperBody)
	for _, marker := range []string{
		"JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
		"AssignProcessToJobObject",
		"windows-kill-switch.ps1",
		"Bootstrapped 100%",
		"Tor SOCKS listener is unavailable after bootstrap",
		"Tor circumvention process exited; tearing down full-device path",
		"Tor PT binary changed after capability proof",
	} {
		if !strings.Contains(helper, marker) { t.Fatalf("Windows Tor lifecycle helper lost %q", marker) }
	}

	setupBody, err := os.ReadFile("../../client/Setup-Windows-Runtime.ps1")
	if err != nil { t.Fatal(err) }
	setup := string(setupBody)
	for _, marker := range []string{
		"TorExpertWindowsX64Sha256",
		"Install-PinnedTorExpertBundle",
		"tor.exe",
		"lyrebird.exe",
		"TorNativeAvailable = $true",
		"Tor unavailable on Windows ARM64",
	} {
		if !strings.Contains(setup, marker) { t.Fatalf("Windows Tor pinned installer lost %q", marker) }
	}
}
