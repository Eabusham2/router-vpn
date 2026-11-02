//go:build linux

package installcap

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"syscall"
	"testing"
)

func TestInstallerForeignCredentialsCannotHideReceivedRights(t *testing.T) {
	channels := fixtureChannels(t)
	raw, err := channels[1].SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionError error
	if err := raw.Control(func(fd uintptr) {
		optionError = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
	}); err != nil || optionError != nil {
		t.Fatal(err, optionError)
	}
	lease, err := os.CreateTemp(t.TempDir(), "actual-credential-lease-")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(fixtureRecord())
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	if _, _, err := channels[0].WriteMsgUnix(frame, syscall.UnixRights(int(lease.Fd()), int(lease.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	lease.Close()
	if _, files, err := receive(channels[1], 2); err == nil || len(files) != 0 {
		t.Fatal("foreign credentials received authority instead of rejection", files, err)
	}
	probe, err := os.OpenFile(lease.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal("foreign earlier cmsg hid and leaked later SCM_RIGHTS descriptions", err)
	}
}
