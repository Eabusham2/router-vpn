//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsControllerFoundationRetainsGrantedLaunchHandle(t *testing.T) {
	if !fixtureInRestrictedDACLWorker(t) {
		return
	}
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	getSecurity, err := api.convertSD.Dll.FindProc("GetSecurityInfo")
	if err != nil {
		t.Fatal(err)
	}
	setSecurity, err := api.convertSD.Dll.FindProc("SetSecurityInfo")
	if err != nil {
		t.Fatal(err)
	}
	getDACL, err := api.convertSD.Dll.FindProc("GetSecurityDescriptorDacl")
	if err != nil {
		t.Fatal(err)
	}
	// This exact fixture child is already captured. Only its owned process
	// DACL changes; no account, parent, executable, token or existing object is
	// granted extra access. The original process handle retains its rights.
	handle, err := syscall.OpenProcess(0x00040000|0x00020000, false, child.process.PID())
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)
	var originalDACL, originalDescriptor unsafe.Pointer
	status, _, _ := getSecurity.Call(uintptr(handle), 6 /* SE_KERNEL_OBJECT */, 4, 0, 0, uintptr(unsafe.Pointer(&originalDACL)), 0, uintptr(unsafe.Pointer(&originalDescriptor)))
	if status != 0 || originalDescriptor == nil || originalDACL == nil {
		t.Fatalf("owned process DACL could not be captured: status=%d", status)
	}
	defer api.localFree.Call(uintptr(originalDescriptor))
	restored := false
	defer func() {
		if restored {
			return
		}
		status, _, _ := setSecurity.Call(uintptr(handle), 6, 4, 0, 0, uintptr(originalDACL), 0)
		if status != 0 {
			t.Errorf("owned process DACL restore failed: status=%d", status)
		}
	}()
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sddl, _ := syscall.UTF16PtrFromString("D:P(D;;0x00101000;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + identity.SID + ")")
	var descriptor unsafe.Pointer
	var size uint32
	ok, _, callErr := api.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	if descriptor != nil {
		defer api.localFree.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil {
		t.Fatal(nativeError("owned process denial descriptor", callErr))
	}
	var present, defaulted uint32
	var dacl unsafe.Pointer
	ok, _, callErr = getDACL.Call(uintptr(descriptor), uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present != 1 || defaulted != 0 || dacl == nil {
		t.Fatal(nativeError("owned process denial DACL", callErr))
	}
	status, _, _ = setSecurity.Call(uintptr(handle), 6, 4, 0, 0, uintptr(dacl), 0)
	if status != 0 {
		t.Fatalf("owned process denial DACL was not installed: status=%d", status)
	}
	if reopened, err := OpenProcess(child.process.PID()); !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal("negative control did not independently deny a fresh process reopen:", err)
	}
	peer, err := child.pipe.VerifyPeer(child.process, child.image)
	if err != nil {
		t.Fatal("retained launch handle was rejected by a fresh process DACL:", err)
	}
	defer peer.Process.Close()
	if peer.Process.PID() != child.process.PID() || peer.Identity.SID != child.hello.Identity.SID {
		t.Fatal("retained launch-handle proof changed the actual pipe writer")
	}
	status, _, _ = setSecurity.Call(uintptr(handle), 6, 4, 0, 0, uintptr(originalDACL), 0)
	if status != 0 {
		t.Fatalf("owned process DACL restore failed before exit: status=%d", status)
	}
	restored = true
	child.finish(t)
}

type fixtureDOSDrive struct {
	define, query *syscall.Proc
	name          string
	target        string
	owned         map[string]bool
}

func newFixtureDOSDrive(t *testing.T, directory string) *fixtureDOSDrive {
	t.Helper()
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	define, err := api.event.Dll.FindProc("DefineDosDeviceW")
	if err != nil {
		t.Fatal(err)
	}
	query, err := api.event.Dll.FindProc("QueryDosDeviceW")
	if err != nil {
		t.Fatal(err)
	}
	drive := &fixtureDOSDrive{define: define, query: query, owned: make(map[string]bool)}
	for candidate := 'Z'; candidate >= 'D'; candidate-- {
		name := string(candidate) + ":"
		_, err := drive.read(name)
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			drive.name = name
			break
		}
		if err != nil {
			t.Fatal("native DOS mapping inventory was not readable:", err)
		}
	}
	if drive.name == "" {
		t.Fatal("native DOS mapping fixture has no unused local drive name")
	}
	t.Cleanup(func() {
		for target, retained := range drive.owned {
			if !retained {
				continue
			}
			if err := drive.remove(target); err != nil {
				t.Error("exact owned DOS mapping cleanup failed:", err)
			}
		}
	})
	if err := drive.replace(directory); err != nil {
		t.Fatal(err)
	}
	return drive
}

func (drive *fixtureDOSDrive) read(name string) (string, error) {
	encoded, _ := syscall.UTF16PtrFromString(name)
	buffer := make([]uint16, 32768)
	length, _, callErr := drive.query.Call(uintptr(unsafe.Pointer(encoded)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", callErr
	}
	return syscall.UTF16ToString(buffer[:length]), nil
}

func (drive *fixtureDOSDrive) remove(target string) error {
	name, _ := syscall.UTF16PtrFromString(drive.name)
	value, _ := syscall.UTF16PtrFromString(target)
	ok, _, callErr := drive.define.Call(0x1|0x2|0x4|0x8 /* RAW | REMOVE | EXACT_MATCH | NO_BROADCAST */, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(value)))
	if ok == 0 {
		return callErr
	}
	return nil
}

func (drive *fixtureDOSDrive) replace(directory string) error {
	if drive.target != "" {
		if err := drive.remove(drive.target); err != nil {
			return err
		}
		drive.owned[drive.target] = false
	}
	target := `\??\` + directory
	name, _ := syscall.UTF16PtrFromString(drive.name)
	value, _ := syscall.UTF16PtrFromString(target)
	ok, _, callErr := drive.define.Call(0x1|0x8 /* RAW | NO_BROADCAST */, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(value)))
	if ok == 0 {
		return callErr
	}
	drive.target = target
	drive.owned[target] = true
	actual, err := drive.read(drive.name)
	if err != nil || !strings.EqualFold(actual, target) {
		return errors.Join(err, errors.New("owned DOS mapping did not retain its exact target"))
	}
	return nil
}

func TestWindowsControllerFoundationCapturedVolumeSurvivesDriveRebind(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil || !identity.Elevated || !identity.Administrator {
		t.Fatal("mandatory native UAC mapping gate requires its elevated test host:", err)
	}
	first, second := t.TempDir(), t.TempDir()
	fixtureCopy(t, fixtureExecutable(t), filepath.Join(first, "captured.exe"))
	fixtureCopy(t, fixtureExecutable(t), filepath.Join(second, "captured.exe"))
	drive := newFixtureDOSDrive(t, first)
	alias := drive.name + `\captured.exe`
	image, err := PinImage(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if err := drive.replace(second); err != nil {
		t.Fatal("held image did not permit the controlled DOS alias rebind:", err)
	}
	replacement, err := PinImage(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if image.identity.FileIndexHigh == replacement.identity.FileIndexHigh && image.identity.FileIndexLow == replacement.identity.FileIndexLow {
		t.Fatal("DOS rebind control did not select a distinct actual file")
	}
	pipe, err := NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	process, err := LaunchElevated(ctx, image, fixtureArguments("hold", pipe, fixtureExecutable(t)))
	if process != nil {
		defer process.Close()
		defer func() {
			_ = pipe.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := process.Wait(cleanup); err != nil {
				t.Error("mapped-drive UAC child did not join:", err)
			}
		}()
	}
	if err != nil || process == nil {
		t.Fatal("actual UAC could not launch the retained local volume image:", err)
	}
	if err := pipe.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pipe.ReadFrame(ctx); err != nil {
		t.Fatal(err)
	}
	peer, err := pipe.VerifyPeer(process, image)
	if err != nil {
		t.Fatal("retargeted DOS drive replaced the retained executable:", err)
	}
	defer peer.Process.Close()
	if err := process.VerifyImage(replacement); err == nil {
		t.Fatal("UAC ran the new DOS-drive target instead of the retained image")
	}
	if !strings.HasPrefix(strings.ToLower(image.Path()), strings.ToLower(volumeGUIDPrefix)) {
		t.Fatal("captured executable retained a mutable DOS drive name")
	}
	if err := pipe.Close(); err != nil {
		t.Fatal(err)
	}
	if exit, err := process.Wait(ctx); err != nil || exit != 0 {
		t.Fatal("retained-volume UAC child did not finish:", err)
	}
}

func TestWindowsControllerFoundationRejectRemoteVolumeNames(t *testing.T) {
	for _, path := range []string{
		`\\server\share\controller.exe`, `\\?\UNC\server\share\controller.exe`,
		`\\?\GLOBALROOT\Device\Mup\server\share\controller.exe`,
		`\\?\Volume{00000000-0000-0000-0000-00000000000x}\controller.exe`,
		`\\?\Volume{00000000-0000-0000-0000-000000000000}\..\controller.exe`,
	} {
		if image, err := PinImage(path); err == nil {
			_ = image.Close()
			t.Fatal("remote or invalid volume path acquired a local image identity")
		}
	}
	// The positive comes from the real held image API, not a path fixture.
	image, err := PinImage(fixtureExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if _, err := os.Stat(image.Path()); err != nil {
		t.Fatal("actual captured volume path cannot address its held file:", err)
	}
}
