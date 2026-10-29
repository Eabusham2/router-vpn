//go:build windows

package windowscontroller

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestWindowsControllerGUIOriginalUserDirectories(t *testing.T) {
	process, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	before, err := process.UserDirectories()
	if err != nil {
		t.Fatal("actual retained user's folders could not be captured:", err)
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	profile, profileErr := token.GetUserProfileDirectory()
	closeErr := token.Close()
	if profileErr != nil || closeErr != nil || !strings.EqualFold(before.Profile, profile) {
		t.Fatal("retained original profile differs from independent token readback", profileErr, closeErr)
	}
	for _, name := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA", "SystemRoot", "WINDIR", "PATH"} {
		t.Setenv(name, `C:\unselected-admin-profile`)
	}
	after, err := process.UserDirectories()
	if err != nil || before != after {
		t.Fatal("ambient environment replaced original-user known folders", err)
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := process.UserDirectories(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed retained process acquired user-profile authority", err)
	}
	for _, value := range []string{"", `relative\profile`, `\\.\PhysicalDrive0`, `\\?\GLOBALROOT\Device\HarddiskVolume1`, "C:\\profile\n", strings.Repeat("a", 32761)} {
		if _, err := validateUserDirectory(value); err == nil {
			t.Fatal("invalid native profile path was admitted")
		}
	}
}
