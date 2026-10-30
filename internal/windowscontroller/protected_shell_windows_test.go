//go:build windows

package windowscontroller

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWindowsControllerFoundationProtectedShellGlobalCapture(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "captured.exe")
	fixtureCopy(t, fixtureExecutable(t), executable)
	image, err := PinImage(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	capture, err := PinProtectedShellImage(image)
	if capture != nil {
		defer capture.Close()
	}
	if err != nil || capture == nil {
		t.Fatal("actual protected global drive/image capture failed", err)
	}
	if err := image.Close(); err != nil {
		t.Fatal(err)
	}
	if err := capture.Verify(); err != nil {
		t.Fatal("protected Shell capture borrowed the caller's released image", err)
	}
	if writer, err := os.OpenFile(executable, os.O_WRONLY, 0); err == nil {
		_ = writer.Close()
		t.Fatal("protected Shell capture released its actual file before retirement")
	}
	if err := os.Rename(directory, directory+".moved"); err == nil {
		restoreErr := os.Rename(directory+".moved", directory)
		t.Fatal("protected Shell capture released its actual ancestry before retirement", restoreErr)
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	if err := capture.Verify(); !errors.Is(err, ErrClosed) {
		t.Fatal("retired protected Shell capture admitted another proof", err)
	}
	writer, err := os.OpenFile(executable, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal("protected Shell retirement retained an unowned file lock", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("Actual held global directory/link protection, effective/global kernel-object equality, explicit-global file identity and independent image retention passed; this does not establish interactive or cross-account UAC acceptance.")
}

func TestWindowsControllerFoundationProtectedShellWrongMapping(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil || identity.SID == "S-1-5-18" {
		t.Fatal("wrong-map fixture requires its actual non-System logon namespace", err)
	}
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	image, err := PinImage(fixtureExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	capture, err := PinProtectedShellImage(image)
	if capture != nil {
		defer capture.Close()
	}
	if err != nil || capture == nil {
		t.Fatal("wrong-map fixture did not establish its actual global owner", err)
	}
	namespace, err := protectedShellNative()
	if err != nil {
		t.Fatal(err)
	}
	// A separately owned local link deliberately reaches the very same
	// native volume. Text equality cannot replace actual object equality.
	drive := newFixtureDOSDriveTarget(t, capture.volume)
	handle, err := namespace.open(`\??\`+drive.name, false)
	if handle != 0 {
		defer syscall.CloseHandle(handle)
	}
	if err != nil {
		t.Fatal(err)
	}
	target, err := namespace.target(handle)
	if err != nil || !strings.EqualFold(target, capture.volume) {
		t.Fatal("wrong-map fixture did not reach the same captured volume", err)
	}
	if err := namespace.sameMapping(capture.handles[2], handle); err == nil {
		t.Fatal("same-target local alias acquired the retained global mapping identity")
	}
	alias := drive.name + capture.path[2:]
	image.mu.Lock()
	wrong, wrongErr := pinProtectedShellImageLocked(api, image, alias)
	image.mu.Unlock()
	if wrong != nil {
		defer wrong.Close()
	}
	if wrongErr == nil {
		t.Fatal("per-logon alias acquired a protected global Shell spelling")
	}
	// The real global mapping also cannot select a second equal-byte file.
	replacement := filepath.Join(t.TempDir(), "replacement.exe")
	fixtureCopy(t, fixtureExecutable(t), replacement)
	image.mu.Lock()
	wrongFile, wrongFileErr := pinProtectedShellImageLocked(api, image, replacement)
	image.mu.Unlock()
	if wrongFile != nil {
		defer wrongFile.Close()
	}
	if wrongFileErr == nil || !strings.Contains(wrongFileErr.Error(), "another retained executable") {
		t.Fatal("protected global spelling did not reject another equal-byte file at its identity boundary", wrongFileErr)
	}
	before := capture.identity
	capture.identity.AuthenticationID ^= 1
	if err := capture.Verify(); err == nil {
		t.Fatal("protected Shell capture admitted another original logon owner")
	}
	capture.identity = before
	if err := capture.Verify(); err != nil {
		t.Fatal("rejected fixture changed the original protected mapping", err)
	}
}
