//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

type inheritedParentReport struct {
	Accepted, Failed, HandleClosed, Retired bool
	PID                                     uint32
	Created                                 int64
	Flags                                   uint32
}

func TestWindowsControllerInheritedParentFixture(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 5 {
		t.Fatal("inherited parent fixture requires its fixed public arguments")
	}
	if err := runInheritedParentFixture(arguments); err != nil {
		_ = os.WriteFile(arguments[4], []byte(err.Error()), 0600)
		t.Fatal(err)
	}
}

func runInheritedParentFixture(arguments []string) error {
	mode, name, rawText, imagePath := arguments[0], arguments[1], arguments[2], arguments[3]
	if mode != "accepted" && mode != "excess-rights" && mode != "not-inherited" && mode != "protected-close" {
		return errors.New("inherited parent fixture selected an unknown case")
	}
	raw, err := strconv.ParseUint(rawText, 10, 64)
	if err != nil || raw == 0 || strconv.FormatUint(raw, 10) != rawText {
		return errors.New("inherited parent fixture has no canonical handle")
	}
	api, err := native()
	if err != nil {
		return err
	}
	handle := syscall.Handle(raw)
	if mode == "excess-rights" {
		pid, _, callErr := api.processID.Call(uintptr(handle))
		if pid == 0 || pid > math.MaxUint32 {
			return nativeError("fixture retained parent PID", callErr)
		}
		extra, err := syscall.OpenProcess(inheritedParentAccess|syscall.PROCESS_TERMINATE, true, uint32(pid))
		if err != nil {
			return err
		}
		if err := syscall.CloseHandle(handle); err != nil {
			_ = syscall.CloseHandle(extra)
			return err
		}
		handle, raw = extra, uint64(extra)
		if access, err := guiGrantedAccess(handle); err != nil || access != inheritedParentAccess|syscall.PROCESS_TERMINATE {
			_ = syscall.CloseHandle(handle)
			return errors.Join(err, errors.New("fixture did not independently acquire its excess-right parent handle"))
		}
	} else if mode == "not-inherited" {
		if err := syscall.SetHandleInformation(handle, syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
			_ = syscall.CloseHandle(handle)
			return err
		}
	} else if mode == "protected-close" {
		if err := syscall.SetHandleInformation(handle, inheritedParentProtectClose, inheritedParentProtectClose); err != nil {
			_ = syscall.CloseHandle(handle)
			return err
		}
		flags, err := inheritedProcessHandleFlags(api, handle)
		if err != nil || flags != syscall.HANDLE_FLAG_INHERIT|inheritedParentProtectClose {
			_ = syscall.SetHandleInformation(handle, inheritedParentProtectClose, 0)
			_ = syscall.CloseHandle(handle)
			return errors.Join(err, errors.New("fixture did not retain its actual protected inherited duplicate"))
		}
	}
	parent, captureErr := CaptureInheritedElevatedParent(raw)
	report := inheritedParentReport{Accepted: parent != nil && captureErr == nil, Failed: captureErr != nil}
	if parent != nil {
		defer parent.Close()
	}
	if mode == "accepted" {
		if captureErr != nil || parent == nil {
			return errors.Join(captureErr, errors.New("actual creation handle did not become its retained parent"))
		}
		report.PID = parent.PID()
		report.Created, err = parent.StartTimeUTCTicks()
		if err != nil {
			return err
		}
		report.Flags, err = inheritedProcessHandleFlags(api, handle)
		if err != nil || report.Flags != 0 {
			return errors.Join(err, errors.New("captured parent retained inheritable authority"))
		}
	} else {
		_, closedErr := inheritedProcessHandleFlags(api, handle)
		report.HandleClosed = closedErr != nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	pipe, err := DialPipe(ctx, name)
	if err != nil {
		return err
	}
	defer pipe.Close()
	if parent != nil {
		image, err := PinImage(imagePath)
		if err != nil {
			return err
		}
		defer image.Close()
		peer, err := pipe.VerifyPeer(parent, image)
		if err != nil {
			return err
		}
		if err := peer.Process.Close(); err != nil {
			return err
		}
	}
	if err := guiWriteJSON(ctx, pipe, report); err != nil {
		return err
	}
	frame, err := pipe.ReadFrame(ctx)
	if err != nil || string(frame) != "retire\n" {
		return errors.Join(err, errors.New("inherited parent fixture lost its exact close request"))
	}
	if parent != nil {
		if err := parent.Close(); err != nil || !errors.Is(parent.Alive(), ErrClosed) {
			return errors.Join(err, errors.New("retired inherited parent admitted another operation"))
		}
		_, closedErr := inheritedProcessHandleFlags(api, handle)
		report.HandleClosed = closedErr != nil
		if !report.HandleClosed {
			return errors.New("retired inherited parent retained its native handle")
		}
	}
	report.Retired = true
	return guiWriteJSON(ctx, pipe, report)
}

func TestWindowsControllerInheritedParentActual(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil || !identity.Primary || !identity.Elevated || !identity.Administrator {
		t.Fatal("inherited native parent gate requires its actual elevated primary fixture", err)
	}
	self, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	created, err := self.StartTimeUTCTicks()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"accepted", "excess-rights", "not-inherited", "protected-close"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			pipe, err := NewPipe()
			if err != nil {
				t.Fatal(err)
			}
			fixture := &guiFixture{pipe: pipe}
			t.Cleanup(func() {
				if err := fixture.close(); err != nil {
					t.Error("inherited parent fixture failed its exact child/Job join", err)
					// Retry the same retained owner. guiFixture.close keeps the
					// image pinned whenever its child/Job has not joined.
					if retry := fixture.close(); retry != nil {
						t.Error("inherited parent fixture cleanup remains owned", retry)
					}
				}
			})
			image, err := PinCurrentImage()
			if err != nil {
				t.Fatal(err)
			}
			fixture.image = image
			environment, err := guiFixtureEnvironment(directory)
			if err != nil {
				t.Fatal(err)
			}
			reportPath := filepath.Join(directory, "inherited-parent-failure.txt")
			child, err := LaunchGUIChild(ctx, image, func(handle uint64) ([]string, error) {
				return []string{"-test.run=^TestWindowsControllerInheritedParentFixture$", "-test.count=1", "-test.timeout=40s", "--",
					mode, pipe.Name(), strconv.FormatUint(handle, 10), image.Path(), reportPath}, nil
			}, environment, directory)
			fixture.child = child
			diagnostic := func() string { raw, _ := os.ReadFile(reportPath); return string(raw) }
			if err != nil || child == nil {
				t.Fatal("inherited parent fixture launch failed", err, diagnostic())
			}
			if err := pipe.Accept(ctx); err != nil {
				t.Fatal("inherited parent fixture did not connect", err, diagnostic())
			}
			var report inheritedParentReport
			if err := guiReadJSON(ctx, pipe, &report); err != nil {
				t.Fatal("inherited parent fixture did not report actual capture", err, diagnostic())
			}
			peer, err := child.VerifyPeer(pipe, image)
			if err != nil {
				t.Fatal("inherited parent fixture writer was not the retained child", err)
			}
			if err := peer.Process.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "accepted" {
				if !report.Accepted || report.Failed || report.PID != self.PID() || report.Created != created || report.Flags != 0 {
					t.Fatal("native child did not retain its exact inherited parent identity", report)
				}
			} else if report.Accepted || !report.Failed || !report.HandleClosed {
				t.Fatal("invalid inherited parent capability was admitted", mode, report)
			}
			if err := pipe.WriteFrame(ctx, []byte("retire\n")); err != nil {
				t.Fatal(err)
			}
			if err := guiReadJSON(ctx, pipe, &report); err != nil || !report.Retired || !report.HandleClosed {
				t.Fatal("inherited parent fixture did not retire its captured handle", err, report, diagnostic())
			}
			if code, err := child.Wait(ctx); err != nil || code != 0 {
				t.Fatal("inherited parent fixture did not exit successfully", code, err, diagnostic())
			}
			if err := self.Alive(); err != nil {
				t.Fatal("child handle retirement affected its actual parent", err)
			}
		})
	}
}

func TestWindowsControllerInheritedParentInvalidHandles(t *testing.T) {
	for _, value := range []uint64{0, math.MaxUint64, uint64(math.MaxInt64) + 1} {
		if owner, err := CaptureInheritedElevatedParent(value); err == nil || owner != nil {
			if owner != nil {
				_ = owner.Close()
			}
			t.Fatal("invalid or pseudo parent handle acquired native authority", value)
		}
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var self syscall.Handle
	if err := syscall.DuplicateHandle(current, current, current, &self, inheritedParentAccess, true, 0); err != nil {
		t.Fatal(err)
	}
	if owner, err := CaptureInheritedElevatedParent(uint64(self)); err == nil || owner != nil {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatal("native child accepted itself as its inherited parent")
	}
	api, err := native()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inheritedProcessHandleFlags(api, self); err == nil {
		t.Fatal("rejected inherited self handle was not consumed")
	}
	value, _, callErr := api.event.Call(0, 1, 0, 0)
	if value == 0 {
		t.Fatal(nativeError("inherited fixture event", callErr))
	}
	event := syscall.Handle(value)
	if err := syscall.SetHandleInformation(event, syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT); err != nil {
		_ = syscall.CloseHandle(event)
		t.Fatal(err)
	}
	if owner, err := CaptureInheritedElevatedParent(uint64(event)); err == nil || owner != nil {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatal("inherited event acquired process authority")
	}
	if _, err := inheritedProcessHandleFlags(api, event); err == nil {
		t.Fatal("rejected inherited event handle was not consumed")
	}
}

func TestWindowsControllerInheritedParentIdentity(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil || !identity.Primary || !identity.Elevated || !identity.Administrator || !sameInheritedElevatedParent(identity, identity) {
		t.Fatal("inherited identity gate requires its actual elevated primary token", err)
	}
	for name, mutate := range map[string]func(*TokenIdentity){
		"sid":            func(value *TokenIdentity) { value.SID += "-1" },
		"authentication": func(value *TokenIdentity) { value.AuthenticationID++ },
		"session":        func(value *TokenIdentity) { value.SessionID++ },
		"primary":        func(value *TokenIdentity) { value.Primary = false },
		"elevation":      func(value *TokenIdentity) { value.Elevated = false },
		"administrator":  func(value *TokenIdentity) { value.Administrator = false },
	} {
		for _, child := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-child-%t", name, child), func(t *testing.T) {
				current, parent := identity, identity
				if child {
					mutate(&current)
				} else {
					mutate(&parent)
				}
				if sameInheritedElevatedParent(current, parent) {
					t.Fatal("inherited native parent ignored the actual token policy", name, child)
				}
			})
		}
	}
}
