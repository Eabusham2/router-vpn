//go:build windows

package windowscontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsControllerFoundationActualTokenAndABI(t *testing.T) {
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := CurrentIdentity()
	if err != nil || !identity.Primary || identity.SID == "" || identity.AuthenticationID == 0 || identity.ModifiedID == 0 {
		t.Fatal("native process token was not captured:", err)
	}
	self, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	actual, err := self.Identity()
	if err != nil || actual != identity {
		t.Fatal("retained process token differs from actual current token:", err)
	}
	if unsafe.Sizeof(tokenStatistics{}) != 56 || unsafe.Sizeof(jobLimits{}) != 144 || unsafe.Sizeof(shellExecuteInfo{}) != 112 {
		t.Fatal("native Windows controller ABI changed")
	}
	if !filepath.IsAbs(api.systemDirectory) || !strings.EqualFold(filepath.Dir(api.shellExecute.Dll.Name), api.systemDirectory) ||
		!strings.EqualFold(filepath.Dir(api.impersonate.Dll.Name), api.systemDirectory) {
		t.Fatal("controller DLL resolution escaped the actual OS system directory")
	}
}

func TestWindowsControllerFoundationSingleLocalPipe(t *testing.T) {
	pipe, err := NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	if second, err := createPipe(pipe.Name()); err == nil {
		_ = second.Close()
		t.Fatal("a second server acquired the captured first-instance pipe")
	}
	for _, name := range []string{
		`\\remote\pipe\RouterVPN-Controller-v1-` + strings.Repeat("a", 32),
		pipePrefix + strings.Repeat("A", 32), pipe.Name() + `\child`,
		pipePrefix + strings.Repeat("a", 31), "", pipePrefix + strings.Repeat("a", 32) + "\x00",
	} {
		if value, err := DialPipe(context.Background(), name); err == nil {
			_ = value.Close()
			t.Fatal("an alternate or malformed pipe address was admitted")
		}
	}
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := withDescriptor(identity.SID+";WD", func(*syscall.SecurityAttributes) error { called = true; return nil }); err == nil || called {
		t.Fatal("noncanonical principal modified the private object ACL boundary")
	}
}

func TestWindowsControllerFoundationActualPeerAndPrivateFrames(t *testing.T) {
	child := startFixtureChild(t, "peer", fixtureExecutable(t))
	child.verify(t)
	ctx, _ := mustNativeContext(t)
	private := append(bytes.Repeat([]byte{'s'}, 256), '\n')
	if err := child.pipe.WriteFrame(ctx, private); err != nil {
		t.Fatal(err)
	}
	acknowledgement, err := child.pipe.ReadFrame(ctx)
	digest := sha256.Sum256(private)
	if err != nil || string(acknowledgement) != hex.EncodeToString(digest[:])+"\n" {
		t.Fatal("captured native child did not acknowledge the exact private frame:", err)
	}
	// ReadFrame must leave later bytes for the owner observer. A forged extra
	// frame revokes the channel rather than being hidden in a buffered read.
	if err := child.pipe.WriteFrame(ctx, []byte("unexpected second frame\n")); err != nil {
		t.Fatal(err)
	}
	exit, err := child.process.Wait(ctx)
	if err != nil || exit == 0 {
		t.Fatal("native child accepted an extra lifetime frame:", err)
	}
}

func TestWindowsControllerFoundationRejectWrongProcessAndImage(t *testing.T) {
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	self, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	if peer, err := child.pipe.VerifyPeer(self, child.image); err == nil {
		_ = peer.Process.Close()
		t.Fatal("same executable with a different retained PID acquired the private channel")
	}
	copyPath := filepath.Join(t.TempDir(), "same-bytes-different-image.exe")
	fixtureCopy(t, fixtureExecutable(t), copyPath)
	copyImage, err := PinImage(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer copyImage.Close()
	if peer, err := child.pipe.VerifyPeer(child.process, copyImage); err == nil {
		_ = peer.Process.Close()
		t.Fatal("different file with identical executable bytes acquired the private channel")
	}
	child.verify(t)
	child.finish(t)
}

func TestWindowsControllerFoundationRejectImpersonatingPipe(t *testing.T) {
	child := startFixtureChild(t, "wrong-sqos", fixtureExecutable(t))
	if peer, err := child.pipe.VerifyPeer(child.process, child.image); err == nil {
		_ = peer.Process.Close()
		t.Fatal("a client granting impersonation acquired the identification-only boundary")
	}
	before, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := child.pipe.Peer(); err == nil {
			t.Fatal("repeated inspection admitted an impersonating pipe")
		}
	}
	after, err := CurrentIdentity()
	if err != nil || before != after {
		t.Fatal("rejected pipe identity changed the actual native process authority:", err)
	}
	child.finish(t)
}

func TestWindowsControllerFoundationCancelledAcceptAndRead(t *testing.T) {
	pipe, err := NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	done := make(chan error, 1)
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := pipe.operation(ctx, false, func(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
			ok, _, callErr := api.connectPipe.Call(uintptr(handle), uintptr(unsafe.Pointer(overlapped)))
			close(entered)
			if ok != 0 || !errors.Is(callErr, syscall.ERROR_IO_PENDING) {
				return 0, errors.New("real unconnected pipe did not enter pending kernel accept")
			}
			return 0, callErr
		})
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled accept installed a native client:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled native accept did not join")
	}
	if err := pipe.Close(); err != nil {
		t.Fatal(err)
	}
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan error, 1)
	entered = make(chan struct{})
	go func() {
		var buffer [1]byte
		_, err := child.pipe.operation(ctx, true, func(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
			var count uint32
			err := syscall.ReadFile(handle, buffer[:], &count, overlapped)
			close(entered)
			if !errors.Is(err, syscall.ERROR_IO_PENDING) {
				return 0, errors.New("real empty pipe did not enter pending kernel read")
			}
			return count, err
		})
		runtime.KeepAlive(buffer)
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled read installed a native frame:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled native read did not join")
	}
	child.verify(t)
	child.finish(t)
}

func TestWindowsControllerFoundationCloseJoinsEnteredOperation(t *testing.T) {
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := child.pipe.operation(context.Background(), true, func(handle syscall.Handle, _ *syscall.Overlapped) (uint32, error) {
			close(entered)
			<-release
			var flags uint32
			ok, _, _ := api.pipeInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&flags)), 0, 0, 0)
			if ok == 0 {
				return 0, errors.New("captured pipe handle closed before its entered operation joined")
			}
			return 0, nil
		})
		done <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- child.pipe.Close() }()
	select {
	case <-child.pipe.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not revoke new operation admission")
	}
	select {
	case err := <-closed:
		close(release)
		t.Fatal("Close returned before the entered pipe operation joined:", err)
	case <-time.After(time.Second):
	}
	if _, _, err := child.pipe.borrow(true); !errors.Is(err, ErrClosed) {
		close(release)
		t.Fatal("closing pipe admitted a replacement operation")
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatal("entered operation did not preserve cancellation after join:", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	child.finish(t)
}

func TestWindowsControllerFoundationCloseJoinsPendingKernelRead(t *testing.T) {
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		var buffer [1]byte
		_, err := child.pipe.operation(context.Background(), true, func(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
			var count uint32
			err := syscall.ReadFile(handle, buffer[:], &count, overlapped)
			close(started)
			if !errors.Is(err, syscall.ERROR_IO_PENDING) {
				return 0, errors.New("real empty pipe did not enter pending kernel read")
			}
			return count, err
		})
		runtime.KeepAlive(buffer)
		result <- err
	}()
	<-started
	if err := child.pipe.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) {
			t.Fatal("pending native read did not return its owner closure:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close abandoned an outstanding native pipe read")
	}
	child.finish(t)
}

func TestWindowsControllerFoundationPinnedImageRejectsReplacement(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "captured.exe")
	fixtureCopy(t, fixtureExecutable(t), executable)
	image, err := PinImage(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if writer, err := os.OpenFile(executable, os.O_WRONLY, 0); err == nil {
		_ = writer.Close()
		t.Fatal("pinned image allowed a concurrent writer")
	}
	if err := os.Rename(executable, filepath.Join(directory, "replaced.exe")); err == nil {
		t.Fatal("pinned executable could be renamed before launch verification")
	}
	if err := os.Rename(directory, directory+"-moved"); err == nil {
		t.Fatal("pinned image ancestor could be renamed before launch verification")
	}
	if err := image.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(executable, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal("closing the captured image retained an unowned write lock:", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsControllerFoundationRejectHardlinkAndReparse(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "source.exe")
	fixtureCopy(t, fixtureExecutable(t), executable)
	linked := filepath.Join(directory, "linked.exe")
	if err := os.Link(executable, linked); err != nil {
		t.Fatal("native hardlink negative could not be created:", err)
	}
	for _, name := range []string{executable, linked} {
		if image, err := PinImage(name); err == nil {
			_ = image.Close()
			t.Fatal("hardlinked executable was admitted as one owned image")
		}
	}
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias.exe")
	if err := os.Symlink(executable, alias); err != nil {
		t.Fatal("native reparse negative could not be created:", err)
	}
	if image, err := PinImage(alias); err == nil {
		_ = image.Close()
		t.Fatal("reparse executable was admitted as the captured image")
	}
	parentAlias := filepath.Join(t.TempDir(), "parent-alias")
	if err := os.Symlink(directory, parentAlias); err != nil {
		t.Fatal("native ancestor reparse negative could not be created:", err)
	}
	if image, err := PinImage(filepath.Join(parentAlias, "source.exe")); err == nil {
		_ = image.Close()
		t.Fatal("reparse ancestor was admitted into the captured image path")
	}
}

func TestWindowsControllerFoundationFramesAreBounded(t *testing.T) {
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	for _, frame := range [][]byte{nil, []byte("no terminator"), []byte("two\nframes\n"), append(bytes.Repeat([]byte{'x'}, maxFrame), '\n')} {
		if err := child.pipe.WriteFrame(context.Background(), frame); err == nil {
			t.Fatal("unbounded or ambiguous private frame reached native write")
		}
	}
	child.finish(t)
	if _, err := child.pipe.Peer(); !errors.Is(err, ErrClosed) {
		t.Fatal("retired pipe returned a reusable peer identity:", err)
	}
}

func TestWindowsControllerFoundationProcessCloseJoinsBorrow(t *testing.T) {
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	handle, release, err := child.process.borrow()
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- child.process.Close() }()
	<-child.process.closed
	select {
	case err := <-closed:
		release()
		t.Fatal("process reference closed before its entered read joined:", err)
	case <-time.After(time.Second):
	}
	status, err := syscall.WaitForSingleObject(handle, 0)
	if err != nil || status != syscall.WAIT_TIMEOUT {
		release()
		t.Fatal("retained process handle did not remain live through read ownership:", err)
	}
	release()
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := child.process.Alive(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed process owner admitted a new operation:", err)
	}
	// Closing the query handle never kills an unrelated running process.
	again, err := OpenProcess(uint32(child.command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.Alive(); err != nil {
		t.Fatal("closing a process reference terminated the process:", err)
	}
	if err := child.pipe.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, _ := mustNativeContext(t)
	if exit, err := again.Wait(ctx); err != nil || exit != 0 {
		t.Fatal("closing lifetime channel did not join its exact child:", err)
	}
}

func TestWindowsControllerFoundationProcessDeathOwnsDescendants(t *testing.T) {
	control := startFixtureChild(t, "hold", fixtureExecutable(t))
	control.verify(t)
	controller := startFixtureChild(t, "job", fixtureExecutable(t))
	controller.verify(t)
	ctx, _ := mustNativeContext(t)
	if err := controller.pipe.WriteFrame(ctx, []byte("start owned descendant\n")); err != nil {
		t.Fatal(err)
	}
	frame, err := controller.pipe.ReadFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.ParseUint(strings.TrimSuffix(string(frame), "\n"), 10, 32)
	if err != nil || pid == 0 || pid == uint64(controller.process.PID()) || pid == uint64(control.process.PID()) {
		t.Fatal("controller returned no distinct captured descendant")
	}
	descendantHandle, err := syscall.OpenProcess(0x00100000|0x1000|0x1, false, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	descendant, err := adoptProcess(descendantHandle)
	if err != nil {
		t.Fatal(err)
	}
	defer descendant.Close()
	defer func() {
		// A deliberately broken kill-on-close mutant must not leave the owned
		// negative-control child running. Retain the original kernel handle;
		// cleanup never reopens a PID or reaches another test's process.
		if state, _ := syscall.WaitForSingleObject(descendantHandle, 0); state != syscall.WAIT_OBJECT_0 {
			_ = syscall.TerminateProcess(descendantHandle, 125)
			if state, err := syscall.WaitForSingleObject(descendantHandle, 5000); err != nil || state != syscall.WAIT_OBJECT_0 {
				t.Error("owned descendant negative-control cleanup did not join:", err)
			}
		}
	}()
	if err := descendant.VerifyImage(controller.image); err != nil {
		t.Fatal(err)
	}
	if err := controller.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.process.Wait(ctx); err != nil {
		t.Fatal("captured controller termination did not join:", err)
	}
	if _, err := descendant.Wait(ctx); err != nil {
		t.Fatal("controller process death left its owned descendant alive:", err)
	}
	if err := control.process.Alive(); err != nil {
		t.Fatal("controller Job cleanup terminated an unrelated owner:", err)
	}
	control.finish(t)
}

func TestWindowsControllerFoundationRejectCancelledUAC(t *testing.T) {
	image, err := PinImage(fixtureExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	process, err := launchElevated(context.Background(), image, []string{"public"}, api, func(info *shellExecuteInfo) (bool, error) {
		if syscall.UTF16ToString(unsafe.Slice(info.Verb, 6)) != "runas" || info.Mask != 0x540 || info.Size != 112 || info.Process != 0 {
			t.Error("elevation request lost its actual UAC and retained-process flags")
		}
		return false, syscall.Errno(1223)
	})
	if process != nil || !errors.Is(err, ErrElevationCancelled) {
		t.Fatal("cancelled UAC did not preserve its distinct user cancellation result:", err)
	}
	process, err = launchElevated(context.Background(), image, []string{"public"}, api, func(*shellExecuteInfo) (bool, error) {
		return false, syscall.Errno(5)
	})
	if process != nil || err == nil || errors.Is(err, ErrElevationCancelled) {
		t.Fatal("native launch failure was reported as cancellation or success:", err)
	}
}

func TestWindowsControllerFoundationLateLaunchKeepsOwner(t *testing.T) {
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	type result struct {
		process *Process
		err     error
	}
	done := make(chan result, 1)
	go func() {
		process, err := launchElevated(ctx, child.image, []string{"public"}, api, func(info *shellExecuteInfo) (bool, error) {
			close(entered)
			<-release
			handle, err := syscall.OpenProcess(0x00100000|0x1000, false, child.process.PID())
			info.Process = handle
			return err == nil, err
		})
		done <- result{process, err}
	}()
	<-entered
	cancel()
	select {
	case value := <-done:
		close(release)
		if value.process != nil {
			_ = value.process.Close()
		}
		t.Fatal("cancelled launch abandoned a native call before its late process joined")
	default:
	}
	close(release)
	value := <-done
	if value.process == nil || value.process.PID() != child.process.PID() || !errors.Is(value.err, context.Canceled) {
		t.Fatal("late native launch was hidden behind cancellation without its owner:", value.err)
	}
	defer value.process.Close()
	if err := value.process.Alive(); err != nil {
		t.Fatal(err)
	}
	child.finish(t)
}

func TestWindowsControllerFoundationActualElevatedLaunch(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil || !identity.Elevated || !identity.Administrator {
		t.Fatal("mandatory native elevation gate requires its actual elevated CI process:", err)
	}
	pipe, err := NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	image, err := PinImage(fixtureExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	ctx, _ := mustNativeContext(t)
	process, err := LaunchElevated(ctx, image, fixtureArguments("hold", pipe, fixtureExecutable(t)))
	if process != nil {
		defer process.Close()
	}
	if err != nil || process == nil {
		fixtureStableShellDiagnostics(t, image)
		t.Fatal("actual ShellExecuteEx did not return its retained elevated process:", err)
	}
	defer func() {
		_ = pipe.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := process.Wait(cleanup); err != nil {
			t.Error("actual elevated child did not join its owner shutdown:", err)
		}
	}()
	if err := pipe.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pipe.ReadFrame(ctx); err != nil {
		t.Fatal(err)
	}
	peer, err := pipe.VerifyPeer(process, image)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Process.Close()
	primary, err := process.Identity()
	if err != nil || !primary.Elevated || !primary.Administrator || !primary.Primary || peer.Identity.SID != primary.SID {
		t.Fatal("actual elevated launch did not preserve its independently proved administrator identity:", err)
	}
	if err := pipe.Close(); err != nil {
		t.Fatal(err)
	}
	if exit, err := process.Wait(ctx); err != nil || exit != 0 {
		t.Fatal("actual elevated child exited without its expected lifetime acknowledgment:", err)
	}
}

// Failure-only native diagnostics isolate Shell pathname/namespace handling
// from the captured executable. Every variant keeps the same held image and
// verifies any actual child before closing its private lifetime pipe. A PIDL
// that normalizes back to a remappable DOS name is rejected before execution.
// No remappable DOS executable or unowned fallback is tried.
func fixtureStableShellDiagnostics(t *testing.T, image *Image) {
	t.Helper()
	api, err := native()
	if err != nil {
		t.Log("stable Shell diagnostic could not load the native API:", err)
		return
	}
	for _, variant := range []string{"no-directory", "system-directory", "global-root", "invoke-stable-guid", "pidl-stable-guid", "machine-class-stable-guid"} {
		func() {
			pipe, err := NewPipe()
			if err != nil {
				t.Logf("stable Shell diagnostic %s pipe: %v", variant, err)
				return
			}
			defer pipe.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var instance uintptr
			process, launchErr := launchElevated(ctx, image, fixtureArguments("hold", pipe, fixtureExecutable(t)), api, func(info *shellExecuteInfo) (bool, error) {
				info.Directory = nil
				var directory *uint16
				if variant == "system-directory" {
					directory, _ = syscall.UTF16PtrFromString(api.systemDirectory)
					info.Directory = directory
				}
				if variant == "global-root" {
					buffer := make([]uint16, 32768)
					length, _, callErr := api.finalPath.Call(uintptr(image.handles[len(image.handles)-1]), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 2 /* VOLUME_NAME_NT */)
					if length == 0 || length >= uintptr(len(buffer)) {
						return false, nativeError("diagnostic retained NT image path", callErr)
					}
					path := syscall.UTF16ToString(buffer[:length])
					if !strings.HasPrefix(path, `\Device\`) {
						return false, errors.New("diagnostic retained image did not return a device path")
					}
					file, err := syscall.UTF16PtrFromString(`\\?\GLOBALROOT` + path)
					if err != nil {
						return false, err
					}
					held, err := syscall.CreateFile(file, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000, 0)
					if err != nil {
						return false, nativeError("diagnostic global-root image capture", err)
					}
					defer syscall.CloseHandle(held)
					var actual syscall.ByHandleFileInformation
					if err := syscall.GetFileInformationByHandle(held, &actual); err != nil ||
						actual.VolumeSerialNumber != image.identity.VolumeSerialNumber || actual.FileIndexHigh != image.identity.FileIndexHigh || actual.FileIndexLow != image.identity.FileIndexLow {
						return false, errors.Join(err, errors.New("diagnostic global-root path replaced the captured executable"))
					}
					info.File = file
				}
				if variant == "invoke-stable-guid" {
					info.Mask |= 0x0c /* SEE_MASK_INVOKEIDLIST: the same fully qualified parsing name */
				}
				if variant == "machine-class-stable-guid" {
					// Isolate Shell association parsing while retaining the exact
					// captured volume-GUID filename. Use only the existing machine
					// executable class, read-only, never a user-writable association
					// or a remappable filename/zone-check bypass.
					path, _ := syscall.UTF16PtrFromString(`SOFTWARE\Classes\exefile`)
					var key syscall.Handle
					if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_READ|syscall.KEY_WOW64_64KEY, &key); err != nil {
						return false, nativeError("diagnostic machine executable class", err)
					}
					defer syscall.RegCloseKey(key)
					info.Mask |= 0x03 /* SEE_MASK_CLASSKEY */
					info.ClassKey = key
				}
				if variant == "pidl-stable-guid" {
					parse, err := api.shellExecute.Dll.FindProc("SHParseDisplayName")
					if err != nil {
						return false, err
					}
					getPath, err := api.shellExecute.Dll.FindProc("SHGetPathFromIDListEx")
					if err != nil {
						return false, err
					}
					free, err := api.initializeCOM.Dll.FindProc("CoTaskMemFree")
					if err != nil {
						return false, err
					}
					var pidl uintptr
					var attributes uint32
					status, _, _ := parse.Call(uintptr(unsafe.Pointer(info.File)), 0, uintptr(unsafe.Pointer(&pidl)), 0x40000000 /* SFGAO_FILESYSTEM */, uintptr(unsafe.Pointer(&attributes)))
					if pidl != 0 {
						defer free.Call(pidl)
					}
					if status != 0 || pidl == 0 || attributes&0x40000000 == 0 {
						return false, fmt.Errorf("diagnostic stable GUID PIDL parse failed (HRESULT=0x%08x, filesystem=%t)", uint32(status), attributes&0x40000000 != 0)
					}
					buffer := make([]uint16, 32768)
					ok, _, callErr := getPath.Call(pidl, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
					if ok == 0 || !strings.EqualFold(syscall.UTF16ToString(buffer), image.path) {
						return false, errors.Join(callErr, errors.New("diagnostic Shell PIDL did not retain the stable GUID parsing path"))
					}
					info.File, info.IDList = nil, pidl
					info.Mask |= 0x04 /* SEE_MASK_IDLIST */
				}
				ok, _, err := api.shellExecute.Call(uintptr(unsafe.Pointer(info)))
				instance = uintptr(info.Instance)
				runtime.KeepAlive(directory)
				return ok != 0, err
			})
			if process == nil {
				t.Logf("stable Shell diagnostic %s launch=%v instance=%d owned_process=false", variant, launchErr, instance)
				return
			}
			defer process.Close()
			defer func() {
				_ = pipe.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := process.Wait(cleanup); err != nil {
					t.Errorf("stable Shell diagnostic %s did not join its exact child: %v", variant, err)
				}
			}()
			proofErr := pipe.Accept(ctx)
			if proofErr == nil {
				_, proofErr = pipe.ReadFrame(ctx)
			}
			if proofErr == nil {
				var peer *Peer
				peer, proofErr = pipe.VerifyPeer(process, image)
				if peer != nil {
					_ = peer.Process.Close()
				}
			}
			t.Logf("stable Shell diagnostic %s launch=%v instance=%d owned_process=true exact_image_proof=%v", variant, launchErr, instance, proofErr)
		}()
	}
}

func TestWindowsControllerFoundationReadFrameLeavesLifetimeByte(t *testing.T) {
	server, err := NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, _ := mustNativeContext(t)
	client, err := DialPipe(ctx, server.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := server.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteFrame(ctx, []byte("public\n")); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteFrame(ctx, []byte("extra\n")); err != nil {
		t.Fatal(err)
	}
	frame, err := server.ReadFrame(ctx)
	if err != nil || string(frame) != "public\n" {
		t.Fatal("bounded frame consumed unrelated channel bytes:", err)
	}
	if err := server.ObserveLifetime(ctx); err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("buffered frame hid a later invalid lifetime byte:", err)
	}
}
