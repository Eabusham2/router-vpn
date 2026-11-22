//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDesktopDarwinGuardianOriginalLockLifetime(t *testing.T) {
	const roleKey = "ROUTERVPN_TEST_DARWIN_LOCK_PROCESS"
	dir := os.Getenv("ROUTERVPN_TEST_DARWIN_LOCK_DIRECTORY")
	role := os.Getenv(roleKey)
	if role == "" {
		dir = t.TempDir()
	}
	path := func(name string) string { return filepath.Join(dir, name) }
	mark := func(name string) {
		t.Helper()
		if err := os.WriteFile(path(name), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(name string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path(name)); err == nil {
				return
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		log, _ := os.ReadFile(path("children.log"))
		t.Fatalf("timed out waiting for %s: %s", name, log)
	}
	// All subprocesses execute this exact same compiled test image. A role
	// receives no other descriptors except its explicit launch arguments.
	child := func(next string) *exec.Cmd {
		command := exec.Command(os.Args[0], "-test.run=^TestDesktopDarwinGuardianOriginalLockLifetime$", "-test.count=1")
		command.Env = []string{roleKey + "=" + next, "ROUTERVPN_TEST_DARWIN_LOCK_DIRECTORY=" + dir, "GORACE=atexit_sleep_ms=0"}
		log, err := os.OpenFile(path("children.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { log.Close() })
		command.Stdout, command.Stderr = log, log
		return command
	}
	open := func(name string) *os.File {
		t.Helper()
		file, err := os.OpenFile(path(name), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		return file
	}
	names := []string{"install.lock", "process.lock"}
	switch role {
	case "engine":
		locks := []*os.File{open(names[0]), open(names[1])}
		for i, mode := range []int{syscall.LOCK_SH, syscall.LOCK_EX} {
			if err := syscall.Flock(int(locks[i].Fd()), mode|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
		}
		ctx := WithDesktopDarwinProcessAuthority(context.Background(), locks)
		null, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer null.Close()
		lifetime := os.NewFile(3, "original-guardian-exit-writer")
		guardian := child("guardian")
		guardian.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		guardian.ExtraFiles = []*os.File{null, lifetime}
		hasLocks, err := desktopDarwinAttachGuardianLocks(ctx, guardian)
		if err != nil || !hasLocks {
			t.Fatal("original lock pair was not attached", err)
		}
		if err := guardian.Start(); err != nil {
			t.Fatal(err)
		}
		if err := guardian.Process.Release(); err != nil {
			t.Fatal(err)
		}
		wait("guardian-ready")
		// Abruptly lose this original lock owner. Its OS descriptors and its
		// observation-pipe copy disappear without an application cleanup.
		os.Exit(0)
	case "guardian":
		if group, err := syscall.Getpgid(os.Getpid()); err != nil || group != os.Getpid() {
			t.Fatal("guardian did not retain its independent process group", err)
		}
		syscall.CloseOnExec(4) // original outer observer sees EOF on actual exit
		release, err := desktopDarwinHoldGuardianLocks(true)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if _, err := desktopDarwinHoldGuardianLocks(true); err == nil {
			t.Fatal("second guardian scope replaced original descriptors")
		}
		mark("guardian-ready")
		wait("start-utilities")
		for _, next := range []string{"isolated", "privileged"} {
			command := child(next)
			if next == "privileged" {
				err = desktopDarwinStartPrivilegedCommand(context.Background(), command)
			} else {
				err = command.Start()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Process.Release(); err != nil {
				t.Fatal(err)
			}
			wait(next + "-ready")
		}
		wait("exit-guardian")
		os.Exit(0)
	case "same-file":
		if release, err := desktopDarwinHoldGuardianLocks(true); err == nil {
			release()
			t.Fatal("two copies of one descriptor substituted for the original pair")
		}
		return
	case "privileged", "isolated":
		for i, name := range names {
			expected, err := os.Stat(path(name))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for fd := 3; fd <= 12; fd++ {
				// Inspect descriptor identities without adopting/closing them.
				var stat syscall.Stat_t
				if syscall.Fstat(fd, &stat) != nil {
					continue
				}
				want := expected.Sys().(*syscall.Stat_t)
				if uint64(stat.Dev) == uint64(want.Dev) && uint64(stat.Ino) == uint64(want.Ino) {
					if role == "privileged" && fd != i+3 {
						t.Fatal("privileged utility lost the original descriptor position")
					}
					found = true
				}
			}
			if found != (role == "privileged") {
				t.Fatalf("%s original lock inheritance for %s = %t", role, name, found)
			}
		}
		mark(role + "-ready")
		wait("exit-" + role)
		mark(role + "-done")
		return
	case "":
	default:
		t.Fatal("invalid lock observation process", role)
	}
	// The two locks must be independently unavailable whenever any original
	// privileged holder survives. The isolated process stays alive across
	// final reacquisition, so an inherited lock there cannot go unnoticed.
	expectLocks := func(held bool) {
		t.Helper()
		for _, name := range names {
			file := open(name)
			err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if held && !errors.Is(err, syscall.EWOULDBLOCK) || !held && err != nil {
				t.Fatalf("%s original lock held=%t: %v", name, held, err)
			}
			file.Close()
		}
	}
	invalid := child("same-file")
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	one := open(names[0])
	invalid.ExtraFiles = []*os.File{null, null, one, one}
	if err := invalid.Run(); err != nil {
		t.Fatal("same-file lock refusal", err)
	}
	null.Close()
	one.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	engine := child("engine")
	engine.ExtraFiles = []*os.File{w}
	if err := engine.Start(); err != nil {
		w.Close()
		t.Fatal(err)
	}
	w.Close()
	if err := engine.Wait(); err != nil {
		data, _ := os.ReadFile(path("children.log"))
		t.Fatalf("original engine: %v: %s", err, data)
	}
	expectLocks(true)
	mark("start-utilities")
	wait("privileged-ready")
	wait("isolated-ready")
	mark("exit-guardian")
	if err := r.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := r.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("original guardian exit pipe: n=%d err=%v", n, err)
	}
	expectLocks(true)
	mark("exit-privileged")
	wait("privileged-done")
	// The child marks immediately before returning from testing.Main. Probe
	// until its actual kernel-owned file description disappears.
	deadline := time.Now().Add(10 * time.Second)
	for {
		file := open(names[1])
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		file.Close()
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			t.Fatal("privileged utility retained the original lock after exit", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	expectLocks(false)
	mark("exit-isolated")
	wait("isolated-done")
}

func TestDesktopDarwinGuardianLockAttachmentBounds(t *testing.T) {
	control, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	command := &exec.Cmd{ExtraFiles: []*os.File{control, control}}
	if ok, err := desktopDarwinAttachGuardianLocks(context.Background(), command); ok || err != nil || len(command.ExtraFiles) != 2 {
		t.Fatal("independent guardian changed original slots", err)
	}
	for _, pair := range [][]*os.File{{control}, {control, nil}, {nil, control}, {control, control, control}} {
		if ok, err := desktopDarwinAttachGuardianLocks(WithDesktopDarwinProcessAuthority(context.Background(), pair), command); ok || err == nil || len(command.ExtraFiles) != 2 {
			t.Fatal("malformed original lock pair admitted")
		}
	}
}
