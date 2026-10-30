//go:build windows

package windowscontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"router-vpn/internal/windowsbootstrap"
)

// Only the independently created test binary consumes this real bootstrap
// entry. The shipping package has no test init or alternate child mode.
func init() {
	if !windowsbootstrap.Requested(os.Args[1:]) {
		return
	}
	if err := fixtureProtectedBootstrapEntry(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "protected bootstrap fixture:", err)
		os.Exit(82)
	}
	os.Exit(0)
}

type protectedBootstrapFixtureHello struct {
	PID       uint32        `json:"pid"`
	Identity  TokenIdentity `json:"identity"`
	Protected bool          `json:"protected"`
}

func fixtureProtectedBootstrapEntry(arguments []string) error {
	rendezvous, err := windowsbootstrap.ParseArguments(arguments)
	if err != nil {
		return err
	}
	identity, err := CurrentIdentity()
	if err != nil || !identity.Primary || !identity.Elevated || !identity.Administrator {
		return errors.Join(err, errors.New("actual bootstrap child is not an elevated primary owner"))
	}
	// The actual high-side image and global mapping are independently pinned
	// before even a public hello. No payload-supplied image becomes self proof.
	image, err := PinCurrentImage()
	if err != nil {
		return err
	}
	defer image.Close()
	capture, err := PinProtectedShellImage(image)
	if capture != nil {
		defer capture.Close()
	}
	if err != nil {
		return err
	}
	self, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	defer self.Close()
	if err := errors.Join(self.VerifyImage(image), capture.Verify(), OwnProcessLifetime()); err != nil {
		return err
	}
	parent, err := OpenProcess(rendezvous.ParentPID)
	if err != nil {
		return err
	}
	defer parent.Close()
	parentImage, err := PinImage(rendezvous.ParentImage)
	if err != nil {
		return err
	}
	defer parentImage.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pipe, err := DialPipe(ctx, rendezvous.PipeName)
	if err != nil {
		return err
	}
	defer pipe.Close()
	peer, err := pipe.VerifyPeer(parent, parentImage)
	if err != nil {
		return err
	}
	if err := peer.Process.Close(); err != nil {
		return err
	}
	frame, err := json.Marshal(protectedBootstrapFixtureHello{uint32(os.Getpid()), identity, true})
	if err != nil {
		return err
	}
	if err := pipe.WriteFrame(ctx, append(frame, '\n')); err != nil {
		return err
	}
	if err := pipe.ObserveLifetime(ctx); !errors.Is(err, io.EOF) {
		return errors.Join(err, errors.New("protected bootstrap did not observe its retained caller closing"))
	}
	return nil
}

type protectedBootstrapFixture struct {
	api       *nativeAPI
	image     *Image
	capture   *ProtectedShellImage
	pipe      *Pipe
	arguments []string
	process   *Process
}

func newProtectedBootstrapFixture(t *testing.T) *protectedBootstrapFixture {
	t.Helper()
	fixture := &protectedBootstrapFixture{}
	t.Cleanup(func() { fixture.close(t) })
	var err error
	fixture.api, err = native()
	if err != nil {
		t.Fatal(err)
	}
	fixture.image, err = PinCurrentImage()
	if err != nil {
		t.Fatal(err)
	}
	fixture.capture, err = PinProtectedShellImage(fixture.image)
	if err != nil {
		t.Fatal("actual protected bootstrap image capture failed", err)
	}
	fixture.pipe, err = NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	fixture.arguments, err = windowsbootstrap.Arguments(fixture.pipe.Name(), uint32(os.Getpid()), fixture.image.Path())
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *protectedBootstrapFixture) close(t *testing.T) {
	t.Helper()
	if fixture.pipe != nil {
		if err := fixture.pipe.Close(); err != nil {
			t.Error("protected bootstrap private rendezvous close failed", err)
		}
	}
	if fixture.process != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, waitErr := fixture.process.Wait(ctx)
		cancel()
		if waitErr != nil {
			// Only a deliberately broken native fixture may require this
			// final cleanup. It uses the actual retained creation object.
			handle, release, err := fixture.process.borrow()
			if err == nil {
				err = syscall.TerminateProcess(handle, 125)
				release()
			}
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			_, waitErr = fixture.process.Wait(ctx)
			cancel()
			if waitErr != nil {
				t.Error("protected bootstrap cleanup retains its unjoined exact child and image", err, waitErr)
				return
			}
		}
		if err := fixture.process.Close(); err != nil {
			t.Error("protected bootstrap joined process handle did not close", err)
			return
		}
		fixture.process = nil
	}
	if fixture.capture != nil {
		if err := fixture.capture.Close(); err != nil {
			t.Error(err)
			return
		}
	}
	if fixture.image != nil {
		if err := fixture.image.Close(); err != nil {
			t.Error(err)
		}
	}
}

func (fixture *protectedBootstrapFixture) hello(t *testing.T) {
	t.Helper()
	if fixture.process == nil {
		t.Fatal("protected bootstrap did not retain its exact child")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := fixture.pipe.Accept(ctx); err != nil {
		t.Fatal("actual protected bootstrap never connected its private rendezvous", err)
	}
	frame, err := fixture.pipe.ReadFrame(ctx)
	if err != nil {
		t.Fatal("actual protected bootstrap did not authenticate before its hello", err)
	}
	peer, err := fixture.pipe.VerifyPeer(fixture.process, fixture.image)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Process.Close(); err != nil {
		t.Fatal(err)
	}
	primary, err := fixture.process.Identity()
	if err != nil {
		t.Fatal(err)
	}
	var hello protectedBootstrapFixtureHello
	if json.Unmarshal(frame, &hello) != nil || hello.PID != fixture.process.PID() ||
		!hello.Protected || hello.Identity != primary || protectedBootstrapIdentity(fixture.capture.identity, primary) != nil ||
		peer.Identity.Primary || peer.Identity.SID != primary.SID || peer.Identity.AuthenticationID != primary.AuthenticationID ||
		peer.Identity.SessionID != primary.SessionID || peer.Identity.Elevated != primary.Elevated || peer.Identity.Administrator != primary.Administrator {
		t.Fatal("actual protected bootstrap hello lost its independently captured image and token")
	}
}

func TestWindowsControllerFoundationProtectedShellBootstrapLaunch(t *testing.T) {
	fixture := newProtectedBootstrapFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var err error
	fixture.process, err = LaunchProtectedBootstrapElevated(ctx, fixture.capture, fixture.arguments)
	if err != nil {
		t.Fatal("actual protected bootstrap runas launch failed", err)
	}
	fixture.hello(t)
	if err := fixture.pipe.Close(); err != nil {
		t.Fatal(err)
	}
	code, err := fixture.process.Wait(ctx)
	if err != nil || code != 0 {
		t.Fatal("actual protected bootstrap did not join its cooperative lifetime", code, err)
	}
	t.Log("Actual retained global spelling, normal runas, high-side self capture, exact private peer and cooperative join passed in this token context; ordinary and cross-account consent remain separate acceptance.")
}

func TestWindowsControllerFoundationProtectedShellBootstrapArguments(t *testing.T) {
	fixture := newProtectedBootstrapFixture(t)
	for _, change := range []struct {
		name string
		edit func([]string) []string
	}{
		{"another-parent", func(value []string) []string { value[2] = strconv.FormatUint(uint64(os.Getpid())+1, 10); return value }},
		{"other-mode", func(value []string) []string { value[0] = "--ordinary"; return value }},
		{"extra-argument", func(value []string) []string { return append(value, "private-material") }},
		{"wrong-pipe", func(value []string) []string { value[1] = `\\.\pipe\unowned`; return value }},
		{"remote-image", func(value []string) []string { value[3] = `\\server\share\parent.exe`; return value }},
		{"device-image", func(value []string) []string { value[3] = `\\.\C:\parent.exe`; return value }},
	} {
		t.Run(change.name, func(t *testing.T) {
			called := false
			process, err := launchProtectedBootstrapElevated(context.Background(), fixture.capture, change.edit(append([]string(nil), fixture.arguments...)), fixture.api, func(*shellExecuteInfo) (bool, error) {
				called = true
				return false, syscall.Errno(1223)
			})
			if process != nil || err == nil || called {
				t.Fatal("another or unbounded caller rendezvous reached protected Shell", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	process, err := launchProtectedBootstrapElevated(ctx, fixture.capture, fixture.arguments, fixture.api, func(*shellExecuteInfo) (bool, error) {
		called = true
		return false, syscall.Errno(1223)
	})
	if process != nil || !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled protected bootstrap admitted a new native launch", err)
	}
	if err := fixture.capture.Close(); err != nil {
		t.Fatal(err)
	}
	process, err = launchProtectedBootstrapElevated(context.Background(), fixture.capture, fixture.arguments, fixture.api, func(*shellExecuteInfo) (bool, error) {
		called = true
		return false, syscall.Errno(1223)
	})
	if process != nil || !errors.Is(err, ErrClosed) || called {
		t.Fatal("retired protected bootstrap admitted another Shell operation", err)
	}
}

func TestWindowsControllerFoundationProtectedShellBootstrapLateCancellation(t *testing.T) {
	fixture := newProtectedBootstrapFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var actualHandle syscall.Handle
	encodedPath, err := syscall.UTF16FromString(fixture.capture.path)
	if err != nil {
		t.Fatal(err)
	}
	process, err := launchProtectedBootstrapElevated(ctx, fixture.capture, fixture.arguments, fixture.api, func(info *shellExecuteInfo) (bool, error) {
		if info.Directory != nil || info.IDList != 0 || info.Icon != 0 || info.Mask != 0x540 ||
			info.File == nil || syscall.UTF16ToString(unsafe.Slice(info.File, len(encodedPath))) != fixture.capture.path {
			return false, errors.New("protected bootstrap changed its captured Shell request")
		}
		ok, _, callErr := fixture.api.shellExecute.Call(uintptr(unsafe.Pointer(info)))
		actualHandle = info.Process
		cancel()
		return ok != 0, callErr
	})
	fixture.process = process
	if actualHandle != 0 && process == nil {
		// A missing-owner mutant must still clean up this exact real child.
		pid, _, readErr := fixture.api.processID.Call(uintptr(actualHandle))
		fixture.process = &Process{handle: actualHandle, pid: uint32(pid), closed: make(chan struct{})}
		if pid == 0 || pid > 0xffffffff {
			t.Fatal("late protected bootstrap cleanup cannot read its actual child", readErr)
		}
	}
	if process == nil || actualHandle == 0 || process.handle != actualHandle || !errors.Is(err, context.Canceled) {
		t.Fatal("late protected bootstrap cancellation discarded its actual process owner", err)
	}
	fixture.hello(t)
	if err := fixture.pipe.Close(); err != nil {
		t.Fatal(err)
	}
	joined, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if code, err := process.Wait(joined); err != nil || code != 0 {
		t.Fatal("late protected bootstrap child did not join its exact private owner", code, err)
	}
}

func fixtureProtectedReturnedProcess(process *Process, info *shellExecuteInfo) (bool, error) {
	handle, release, err := process.borrow()
	if err != nil {
		return false, err
	}
	defer release()
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return false, err
	}
	err = syscall.DuplicateHandle(current, handle, current, &info.Process, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	return err == nil, err
}

func TestWindowsControllerFoundationProtectedShellBootstrapReturnedImage(t *testing.T) {
	fixture := newProtectedBootstrapFixture(t)
	executable := filepath.Join(t.TempDir(), "different-retained-image.exe")
	fixtureCopy(t, fixtureExecutable(t), executable)
	other := startFixtureChild(t, "hold", executable)
	other.verify(t)
	process, err := launchProtectedBootstrapElevated(context.Background(), fixture.capture, fixture.arguments, fixture.api, func(info *shellExecuteInfo) (bool, error) {
		return fixtureProtectedReturnedProcess(other.process, info)
	})
	if process != nil {
		defer process.Close()
	}
	if process == nil || process.PID() != other.process.PID() || err == nil || !strings.Contains(err.Error(), "different captured file") {
		t.Fatal("protected bootstrap authorized another retained actual image", err)
	}
	other.finish(t)
}

func TestWindowsControllerFoundationProtectedShellBootstrapChangedCapture(t *testing.T) {
	fixture := newProtectedBootstrapFixture(t)
	child := startFixtureChild(t, "hold", fixtureExecutable(t))
	child.verify(t)
	original := fixture.capture.identity
	process, err := launchProtectedBootstrapElevated(context.Background(), fixture.capture, fixture.arguments, fixture.api, func(info *shellExecuteInfo) (bool, error) {
		fixture.capture.identity.AuthenticationID ^= 1
		return fixtureProtectedReturnedProcess(child.process, info)
	})
	fixture.capture.identity = original
	if process != nil {
		defer process.Close()
	}
	if process == nil || err == nil || !strings.Contains(err.Error(), "changed its original process identity") {
		t.Fatal("protected bootstrap accepted its changed original capture after creation", err)
	}
	child.finish(t)
}

func TestWindowsControllerFoundationProtectedShellBootstrapToken(t *testing.T) {
	actual, err := CurrentIdentity()
	if err != nil || !actual.Elevated || !actual.Administrator || !actual.Primary {
		t.Fatal("protected bootstrap token fixture requires its actual elevated primary identity", err)
	}
	if err := protectedBootstrapIdentity(actual, actual); err != nil {
		t.Fatal("actual elevated bootstrap identity was rejected", err)
	}
	otherAccount := actual
	otherAccount.SID = "S-1-5-21-111-222-333-444"
	otherAccount.AuthenticationID ^= 1
	if err := protectedBootstrapIdentity(actual, otherAccount); err != nil {
		t.Fatal("typed bootstrap proof incorrectly equated the two account identities", err)
	}
	for _, change := range []func(*TokenIdentity){
		func(value *TokenIdentity) { value.Elevated = false },
		func(value *TokenIdentity) { value.Administrator = false },
		func(value *TokenIdentity) { value.Primary = false },
		func(value *TokenIdentity) { value.SessionID++ },
		func(value *TokenIdentity) { value.SID = "" },
	} {
		changed := actual
		change(&changed)
		if err := protectedBootstrapIdentity(actual, changed); err == nil {
			t.Fatal("protected bootstrap accepted an unproved elevated desktop token")
		}
	}
	// The changed structures above exercise the shared proof predicate. They
	// do not pretend to be actual other-account or ordinary-user UAC tokens.
}
