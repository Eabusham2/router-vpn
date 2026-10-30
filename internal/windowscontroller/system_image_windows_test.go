//go:build windows

package windowscontroller

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

func TestWindowsControllerGUISystemImageCapturePolicy(t *testing.T) {
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	fake := filepath.Join(directory, "WindowsPowerShell", "v1.0")
	if err := os.MkdirAll(fake, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fake, "powershell.exe"), []byte("untrusted system-path replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"PATH", "SystemRoot", "WINDIR"} {
		t.Setenv(name, directory)
	}
	system, systemErr := SystemDirectory()
	if systemErr != nil || system != api.systemDirectory {
		t.Fatal("environment replacement retargeted the captured system directory", system, systemErr)
	}
	image, err := PinSystemPowerShell()
	if err != nil {
		guiObserveSystemPowerShellImage(t, filepath.Join(api.systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
		t.Fatal("environment replacement retargeted the pathless system PowerShell capture:", err)
	}
	defer image.Close()
	if !image.systemPowerShell || image.identity.NumberOfLinks == 0 {
		t.Fatal("actual system image has no captured protected link policy")
	}
	path := filepath.Join(api.systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	if image.identity.NumberOfLinks > 1 {
		ordinary, err := PinImage(path)
		if ordinary != nil {
			_ = ordinary.Close()
		}
		if err == nil || ordinary != nil {
			t.Fatal("protected system image broadened ordinary caller-selected hardlink admission")
		}
	}
	// Only this fixture's captured metadata changes. The actual system file,
	// links, permissions and contents remain untouched.
	image.mu.Lock()
	links := image.identity.NumberOfLinks
	image.identity.NumberOfLinks = links ^ 1
	if image.identity.NumberOfLinks == 0 {
		image.identity.NumberOfLinks = 2
	}
	_, handle, changedErr := image.normalizedLaunchNameLocked()
	image.identity.NumberOfLinks = links
	image.mu.Unlock()
	if handle != 0 {
		_ = syscall.CloseHandle(handle)
	}
	if changedErr == nil || handle != 0 {
		t.Fatal("system image admitted a changed captured hardlink count before creation")
	}
	if err := verifySystemImageProtection(syscall.InvalidHandle); err == nil {
		t.Fatal("invalid native handle acquired system image protection")
	}
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// Create only a new disposable fixture with deliberately unsafe access.
	// This independently exercises handle-based GetSecurityInfo; no existing
	// object's permissions or any Windows system resource is modified.
	sddl, err := syscall.UTF16PtrFromString("O:" + identity.SID + "D:P(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	var descriptor unsafe.Pointer
	var size uint32
	ok, _, callErr := api.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	if descriptor != nil {
		defer api.localFree.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil || size < 20 {
		t.Fatal(nativeError("owned unsafe image fixture descriptor", callErr))
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
	fixturePath, err := syscall.UTF16PtrFromString(filepath.Join(directory, "unsafe-owned-fixture.exe"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := syscall.CreateFile(fixturePath, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ, &attributes, syscall.CREATE_NEW, 0x00200000, 0)
	if err != nil {
		t.Fatal("owned unsafe image fixture could not be created:", err)
	}
	defer syscall.CloseHandle(fixture)
	if err := verifySystemImageProtection(fixture); err == nil {
		t.Fatal("actual untrusted writable file acquired system image protection")
	}
}
