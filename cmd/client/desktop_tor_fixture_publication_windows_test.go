//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"router-vpn/internal/mobiletor"
)

func TestDesktopTorFixturePublicationRetainsSnapshotAcrossWindowsRenameHandle(t *testing.T) {
	control := filepath.Join(t.TempDir(), "original-control")
	expected := mobiletor.DesktopBridgeMetadata{SessionID: strings.Repeat("a", 32), SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64)}
	identity := desktopTorFixturePauseIdentity(expected)
	for _, suffix := range []string{".pause", ".resume"} {
		if err := atomicWritePrivate(control+suffix, []byte(identity)); err != nil {
			t.Fatal(err)
		}
	}
	name, err := windowsPrivateStoreName(control + ".pause")
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the rename/read overlap deterministically: the captured
	// publisher still holds delete access while the reader opens its record.
	const deleteAccess uint32 = 0x00010000
	handle, err := syscall.CreateFile(name, deleteAccess,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal("capture actual Windows publication handle", err)
	}
	defer syscall.CloseHandle(handle)
	if _, err := os.ReadFile(control + ".pause"); !errors.Is(err, syscall.Errno(32)) {
		t.Fatal("ordinary pathname reader did not reproduce the native sharing boundary", err)
	}
	t.Setenv("ROUTERVPN_TOR_TEST_RELEASE", control)
	desktopTorFixturePublicationBarrier("proof-directory-retire", expected)
	receipt, err := os.ReadFile(control + ".paused")
	if err != nil || string(receipt) != identity {
		t.Fatal("captured root reader did not acknowledge the exact original publication", err)
	}
}
