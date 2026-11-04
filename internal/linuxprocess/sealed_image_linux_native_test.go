//go:build linux && routervpn_controller_privileged

package linuxprocess

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// These tests require actual root-owned process/memfd/socket capabilities, but
// do not mutate a namespace or network. The mandatory installed gate also runs
// them in its actual isolated native namespace on each shipped Linux target.
func sealedProcessFixture(t *testing.T, seal bool) *os.File {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("sealed executable proof requires actual root ownership")
	}
	number := uintptr(319)
	if runtime.GOARCH == "arm64" {
		number = 279
	} else if runtime.GOARCH != "amd64" {
		t.Fatal("unsupported shipped Linux memfd ABI")
	}
	name, _ := syscall.BytePtrFromString("original-sealed-process-test")
	fd, _, errno := syscall.Syscall(number, uintptr(unsafe.Pointer(name)), 3, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	f := os.NewFile(fd, "original-sealed-process-image")
	t.Cleanup(func() { f.Close() })
	original, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(f, original)
	err = errors.Join(copyErr, original.Close(), f.Chmod(0500))
	if err != nil {
		t.Fatal(err)
	}
	if seal {
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1033, 15); errno != 0 {
			t.Fatal(errno)
		}
	}
	return f
}

func TestLinuxProcessNamespaceSealedWorker(t *testing.T) {
	scenario := os.Getenv("ROUTERVPN_SEALED_PROCESS_CHILD")
	if scenario == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	original := os.NewFile(5, "inherited-original-image")
	defer original.Close()
	if err := SetCloseOnExec(original); err != nil {
		t.Fatal(err)
	}
	image, err := CaptureSealedImage(original)
	if err != nil {
		t.Fatal(err)
	}
	// Ordinary authentication must still reject the anonymous image.
	ordinary, ordinaryErr := CaptureSelf(ctx)
	if ordinary != nil {
		if err := ordinary.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ordinaryErr == nil || !strings.Contains(ordinaryErr.Error(), "sole protected directory entry") {
		t.Fatal("generic process capture admitted sealed anonymous executable", ordinaryErr)
	}
	fmt.Println("generic-image-rule-preserved")
	channel, err := CaptureChannel(os.NewFile(3, "inherited-original-channel"))
	if err != nil {
		if channel != nil {
			channel.Close(context.Background())
		}
		t.Fatal(err)
	}
	peer, err := BindInheritedSealedParent(ctx, channel, os.NewFile(4, "inherited-original-parent"), processFixtureCapture, image)
	defer peer.Close(context.Background())
	if err != nil {
		if scenario == "complete" || scenario == "closed-after-bind" || scenario == "replaced-after-bind" || scenario == "reexecuted" {
			t.Fatal(err)
		}
		fmt.Println("sealed-bootstrap-refused")
		return
	}
	if err := peer.Send(ctx, []byte("sealed-child-ready")); err != nil {
		t.Fatal(err)
	}
	for {
		body, err := peer.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil {
				t.Fatal(err)
			}
			return
		}
		switch string(body) {
		case "ping":
			if err := peer.Send(ctx, []byte("pong")); err != nil {
				t.Fatal(err)
			}
		case "exec":
			if err := peer.Send(ctx, []byte("exec-original-task")); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Exec("/bin/sleep", []string{"sleep", "8"}, []string{"PATH=/usr/bin:/bin"}); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("unknown sealed fixture command")
		}
	}
}

func TestLinuxProcessNamespaceSealedImageAdmission(t *testing.T) {
	for _, scenario := range []string{"original", "unsealed", "writable", "non-executable", "ordinary-file", "closed", "replaced", "nil"} {
		t.Run(scenario, func(t *testing.T) {
			original := sealedProcessFixture(t, scenario != "unsealed")
			switch scenario {
			case "writable":
				if err := original.Chmod(0700); err != nil {
					t.Fatal(err)
				}
			case "non-executable":
				if err := original.Chmod(0400); err != nil {
					t.Fatal(err)
				}
			case "ordinary-file":
				var err error
				original, err = os.Open("/proc/self/exe")
				if err != nil {
					t.Fatal(err)
				}
				defer original.Close()
			case "nil":
				original = nil
			}
			captured, err := CaptureSealedImage(original)
			if scenario != "original" && scenario != "closed" && scenario != "replaced" {
				if err == nil {
					t.Fatal("foreign or mutable executable admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !captured.Uses(original) {
				t.Fatal("capture did not retain its exact original file")
			}
			if scenario == "closed" {
				original.Close()
			} else if scenario == "replaced" {
				foreign := sealedProcessFixture(t, true)
				if _, _, errno := syscall.Syscall(syscall.SYS_DUP3, foreign.Fd(), original.Fd(), syscall.O_CLOEXEC); errno != 0 {
					t.Fatal(errno)
				}
			}
			err = captured.Current()
			if scenario == "original" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := original.WriteAt([]byte("x"), 0); err == nil {
					t.Fatal("sealed executable remained writable")
				}
			} else if err == nil {
				t.Fatal("lost original sealed descriptor remained current")
			}
		})
	}
}

func TestLinuxProcessNamespaceSealedBootstrap(t *testing.T) {
	for _, scenario := range []string{"complete", "generic-refused", "foreign-image", "foreign-pidfd", "nil-image", "closed-before-bind", "closed-after-bind", "replaced-after-bind", "reexecuted"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			parent, err := CaptureSelf(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close(context.Background())
			directory, err := parent.DuplicateDirectory(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			channel, childEndpoint, err := ChannelPair()
			if err != nil {
				t.Fatal(err)
			}
			defer childEndpoint.Close()
			original := sealedProcessFixture(t, true)
			captured, err := CaptureSealedImage(original)
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, "/proc/self/fd/5", "-test.run=^TestLinuxProcessNamespaceSealedWorker$", "-test.count=1", "-test.timeout=14s")
			command.Env = []string{"PATH=/usr/bin:/bin", "ROUTERVPN_SEALED_PROCESS_CHILD=" + scenario}
			command.ExtraFiles = []*os.File{childEndpoint, directory, original}
			pidfd := -1
			command.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			if pidfd < 0 {
				command.Process.Kill()
				command.Wait()
				t.Fatal("clone omitted its actual pidfd")
			}
			descriptor := os.NewFile(uintptr(pidfd), "original-created-child-pidfd")
			childEndpoint.Close()
			directory.Close()
			joined := make(chan struct{})
			var joinErr error
			go func() { joinErr = command.Wait(); close(joined) }()
			var bootstrap *Bootstrap
			defer func() {
				if bootstrap != nil {
					if err := bootstrap.Close(context.Background()); err != nil {
						t.Error(err)
					}
				} else {
					channel.Close(context.Background())
					descriptor.Close()
				}
				cancel()
				<-joined
			}()
			if scenario == "foreign-image" {
				captured, err = CaptureSealedImage(sealedProcessFixture(t, true))
				if err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "nil-image" {
				captured = nil
			}
			if scenario == "closed-before-bind" {
				original.Close()
			}
			if scenario == "foreign-pidfd" {
				foreignFD := -1
				foreign := exec.CommandContext(ctx, "/bin/sleep", "8")
				foreign.SysProcAttr = &syscall.SysProcAttr{PidFD: &foreignFD}
				if err := foreign.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { foreign.Process.Kill(); foreign.Wait() }()
				descriptor.Close()
				descriptor = os.NewFile(uintptr(foreignFD), "actual-foreign-created-child-pidfd")
			}
			bound, stop := context.WithTimeout(ctx, 4*time.Second)
			defer stop()
			if scenario == "generic-refused" {
				bootstrap, err = BindCreatedChild(bound, channel, parent, descriptor, command.Process.Pid, captured.identity, processFixtureCapture)
			} else {
				bootstrap, err = BindCreatedSealedChild(bound, channel, parent, descriptor, command.Process.Pid, captured, processFixtureCapture)
			}
			positive := scenario == "complete" || scenario == "closed-after-bind" || scenario == "replaced-after-bind" || scenario == "reexecuted"
			if !positive {
				if err == nil || bootstrap == nil {
					t.Fatal("foreign sealed bootstrap admitted or partial owner lost", err)
				}
				if scenario == "generic-refused" && !strings.Contains(err.Error(), "sole protected directory entry") {
					t.Fatal("generic refusal did not enforce original image rule", err)
				}
				if scenario == "foreign-image" && !strings.Contains(err.Error(), "original sealed image") {
					t.Fatal("foreign image did not reach exact native comparison", err)
				}
				if scenario == "foreign-pidfd" && !strings.Contains(err.Error(), "pidfd") {
					t.Fatal("foreign pidfd did not reach native creation comparison", err)
				}
				if err := bootstrap.Close(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case <-joined:
				case <-ctx.Done():
					t.Fatal("rejected original child did not join")
				}
				if joinErr != nil || !strings.Contains(output.String(), "generic-image-rule-preserved") || !strings.Contains(output.String(), "sealed-bootstrap-refused") {
					t.Fatal("child did not independently reject original challenge", joinErr, output.String())
				}
				return
			}
			if err != nil {
				bootstrap.Close(context.Background())
				cancel()
				<-joined
				t.Fatal("original sealed child did not authenticate", err, output.String())
			}
			body, err := bootstrap.Receive(bound)
			if err != nil || string(body) != "sealed-child-ready" {
				t.Fatal("original child did not deliver its authenticated ready", string(body), err)
			}
			if err := bootstrap.Send(bound, []byte("ping")); err != nil {
				t.Fatal(err)
			}
			body, err = bootstrap.Receive(bound)
			if err != nil || string(body) != "pong" {
				t.Fatal("original channel failed", err)
			}
			switch scenario {
			case "closed-after-bind":
				original.Close()
			case "replaced-after-bind":
				foreign := sealedProcessFixture(t, true)
				if _, _, errno := syscall.Syscall(syscall.SYS_DUP3, foreign.Fd(), original.Fd(), syscall.O_CLOEXEC); errno != 0 {
					t.Fatal(errno)
				}
			case "reexecuted":
				if err := bootstrap.Send(bound, []byte("exec")); err != nil {
					t.Fatal(err)
				}
				// Exec can complete before the reply post-check; rejection then is
				// required and the response must not count as authenticated success.
				_, _ = bootstrap.Receive(bound)
				for {
					err = bootstrap.Current(bound)
					if err != nil {
						break
					}
					select {
					case <-bound.Done():
						t.Fatal("reexecuted image remained authenticated")
					case <-time.After(time.Millisecond):
					}
				}
			}
			err = bootstrap.Current(bound)
			if scenario == "complete" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("lost sealed image authority remained current")
			}
			if err := bootstrap.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if scenario == "reexecuted" {
				command.Process.Kill()
			}
			select {
			case <-joined:
			case <-ctx.Done():
				t.Fatal("original child did not join after channel close")
			}
			if scenario != "reexecuted" && joinErr != nil {
				t.Fatal(joinErr, output.String())
			}
			if _, err := parent.Current(ctx); err != nil {
				t.Fatal("child cleanup closed borrowed parent", err)
			}
			if scenario == "complete" {
				if err := captured.Current(); err != nil {
					t.Fatal("bootstrap closed borrowed sealed image", err)
				}
			}
		})
	}
}
