//go:build windows

package windowscontroller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// This helper runs only as an independently created native process. It does not
// impersonate one goroutine while another performs controller operations.
// Arguments contain only the public rendezvous and the retained parent image;
// private frames never appear in a command line, environment or test output.
func TestWindowsControllerFixtureProcess(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) == 1 && arguments[0] == "descendant" {
		time.Sleep(40 * time.Second)
		return
	}
	if len(arguments) != 4 {
		t.Fatal("native controller fixture arguments are invalid")
	}
	mode, name, parentText, parentImage := arguments[0], arguments[1], arguments[2], arguments[3]
	if mode != "peer" && mode != "hold" && mode != "job" && mode != "wrong-sqos" {
		t.Fatal("native controller fixture mode is invalid")
	}
	parentPID, err := strconv.ParseUint(parentText, 10, 32)
	if err != nil || parentPID == 0 {
		t.Fatal("native controller fixture parent is invalid")
	}
	if mode == "job" {
		if err := OwnProcessLifetime(); err != nil {
			t.Fatal(err)
		}
		if err := OwnProcessLifetime(); err != nil {
			t.Fatal("retained process Job could not be reverified:", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	parent, err := OpenProcess(uint32(parentPID))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	image, err := PinImage(parentImage)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	var pipe *Pipe
	if mode == "wrong-sqos" {
		// An actual same-user client with delegation-capable default SQOS must
		// not satisfy the identification-only controller boundary.
		encoded, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := syscall.CreateFile(encoded, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0x40000000, 0)
		if err != nil {
			t.Fatal(err)
		}
		pipe = &Pipe{handle: handle, name: name, connected: true, closed: make(chan struct{})}
	} else {
		pipe, err = DialPipe(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer pipe.Close()
	peer, err := pipe.VerifyPeer(parent, image)
	if err != nil {
		t.Fatal("child did not prove its actual parent:", err)
	}
	if err := peer.Process.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hello, err := json.Marshal(fixtureHello{PID: uint32(os.Getpid()), Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipe.WriteFrame(ctx, append(hello, '\n')); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "peer":
		frame, err := pipe.ReadFrame(ctx)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(frame)
		if err := pipe.WriteFrame(ctx, append([]byte(hex.EncodeToString(digest[:])), '\n')); err != nil {
			t.Fatal(err)
		}
	case "job":
		frame, err := pipe.ReadFrame(ctx)
		if err != nil || string(frame) != "start owned descendant\n" {
			t.Fatal("owned descendant was not requested by its retained parent")
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(executable, "-test.run=^TestWindowsControllerFixtureProcess$", "-test.count=1", "-test.timeout=45s", "--", "descendant")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		// No test teardown may substitute for kernel Job ownership. The parent
		// kills this process after retaining the descendant's actual handle.
		if err := pipe.WriteFrame(ctx, []byte(strconv.Itoa(child.Process.Pid)+"\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := pipe.ObserveLifetime(ctx); !errors.Is(err, io.EOF) {
		t.Fatal("native fixture did not observe its exact owner closing:", err)
	}
}

type fixtureHello struct {
	PID      uint32        `json:"pid"`
	Identity TokenIdentity `json:"identity"`
}

type fixtureChild struct {
	pipe    *Pipe
	process *Process
	image   *Image
	command *exec.Cmd
	done    chan error
	output  *os.File
	hello   fixtureHello
}

func fixtureExecutable(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureArguments(mode string, pipe *Pipe, parentImage string) []string {
	return []string{"-test.run=^TestWindowsControllerFixtureProcess$", "-test.count=1", "-test.timeout=35s", "--", mode, pipe.Name(), strconv.Itoa(os.Getpid()), parentImage}
}

func startFixtureChild(t *testing.T, mode, executable string) *fixtureChild {
	t.Helper()
	pipe, err := NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	image, err := PinImage(executable)
	if err != nil {
		_ = pipe.Close()
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "child-output-")
	if err != nil {
		_ = pipe.Close()
		_ = image.Close()
		t.Fatal(err)
	}
	child := &fixtureChild{pipe: pipe, image: image, done: make(chan error, 1), output: output}
	t.Cleanup(func() {
		_ = child.pipe.Close()
		if child.command != nil && child.command.Process != nil {
			select {
			case <-child.done:
			case <-time.After(5 * time.Second):
				_ = child.command.Process.Kill()
				select {
				case <-child.done:
				case <-time.After(5 * time.Second):
					t.Error("fixture did not join the captured child")
				}
			}
		}
		if child.process != nil {
			_ = child.process.Close()
		}
		_ = child.image.Close()
		_ = output.Close()
	})
	child.command = exec.Command(executable, fixtureArguments(mode, pipe, fixtureExecutable(t))...)
	child.command.Stdout, child.command.Stderr = output, output
	if err := child.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { child.done <- child.command.Wait() }()
	child.process, err = OpenProcess(uint32(child.command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pipe.Accept(ctx); err != nil {
		t.Fatal("fixture did not accept its captured child:", err)
	}
	if _, err := pipe.Peer(); err == nil {
		t.Fatal("server accepted a writer before reading the public hello")
	}
	hello, err := pipe.ReadFrame(ctx)
	if err != nil {
		_, _ = output.Seek(0, io.SeekStart)
		raw, _ := io.ReadAll(io.LimitReader(output, 16384))
		t.Fatalf("fixture public hello failed: %v; child diagnostics: %s", err, raw)
	}
	if err := json.Unmarshal(hello, &child.hello); err != nil || child.hello.PID != child.process.PID() {
		t.Fatal("fixture hello did not identify the expected public process")
	}
	return child
}

func (child *fixtureChild) verify(t *testing.T) *Peer {
	t.Helper()
	peer, err := child.pipe.VerifyPeer(child.process, child.image)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Process.Close() })
	primary, err := child.process.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if peer.Identity.Primary || !primary.Primary || peer.Identity.SID != primary.SID ||
		peer.Identity.AuthenticationID != primary.AuthenticationID || peer.Identity.SessionID != primary.SessionID ||
		peer.Process.PID() != child.process.PID() || child.hello.Identity != primary {
		t.Fatal("native pipe identity did not preserve the independently read process principal")
	}
	return peer
}

func (child *fixtureChild) finish(t *testing.T) {
	t.Helper()
	if err := child.pipe.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exit, err := child.process.Wait(ctx)
	if err != nil || exit != 0 {
		_, _ = child.output.Seek(0, io.SeekStart)
		raw, _ := io.ReadAll(io.LimitReader(child.output, 16384))
		t.Fatalf("captured fixture child did not finish: exit=%d err=%v diagnostics=%s", exit, err, raw)
	}
}

func mustNativeContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx, cancel
}

func fixtureCopy(t *testing.T, source, target string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	if err := errors.Join(copyErr, output.Sync(), output.Close()); err != nil {
		t.Fatal(err)
	}
}
