//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDesktopLinuxNodeParentProcessStartBounds(t *testing.T) {
	fields := append([]string{"S"}, strings.Fields(strings.Repeat("0 ", 18))...)
	fields = append(fields, "123456")
	valid := "451 (name ) ( tricky) " + strings.Join(fields, " ") + "\n"
	if pid, start, err := desktopLinuxNodeProcessStart([]byte(valid)); err != nil || pid != 451 || start != 123456 {
		t.Fatal("native process identity confused comm with the start field", pid, start, err)
	}
	for name, raw := range map[string]string{
		"missing": "", "pid-zero": strings.Replace(valid, "451 ", "0 ", 1),
		"pid-alias":    strings.Replace(valid, "451 ", "0451 ", 1),
		"pid-overflow": strings.Replace(valid, "451 ", "2147483648 ", 1),
		"no-comm":      "451 S " + strings.Join(fields, " "),
		"short":        "451 (native) S 0 0", "zero-start": strings.Replace(valid, "123456", "0", 1),
		"negative-start":  strings.Replace(valid, "123456", "-1", 1),
		"start-alias":     strings.Replace(valid, "123456", "0123456", 1),
		"overflow":        strings.Replace(valid, "123456", "18446744073709551616", 1),
		"too-many-fields": valid + strings.Repeat("0 ", 80), "oversized": strings.Repeat("x", 8193),
	} {
		t.Run(name, func(t *testing.T) {
			if pid, start, err := desktopLinuxNodeProcessStart([]byte(raw)); err == nil || pid != 0 || start != 0 {
				t.Fatal("malformed process record acquired an original start", pid, start, err)
			}
		})
	}
	if pid, start, err := readDesktopLinuxNodeProcessStart(); err != nil || pid < 1 || start == 0 {
		t.Fatal("actual self process has no bounded kernel identity", pid, start, err)
	}
}

func desktopLinuxNodePartialFixture(t *testing.T) *desktopLinuxNodeParent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &desktopLinuxNodeParent{ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1), joined: make(chan struct{})}
	p.gate <- struct{}{}
	go func() { <-ctx.Done(); close(p.joined) }()
	file, err := os.CreateTemp(t.TempDir(), "captured-parent-")
	if err != nil {
		t.Fatal(err)
	}
	p.image = file
	t.Cleanup(func() { _ = p.Close(context.Background()) })
	return p
}

func TestDesktopLinuxNodeParentPartialCloseJoinsAndRetainsOriginalFiles(t *testing.T) {
	p := desktopLinuxNodePartialFixture(t)
	borrowed, err := os.CreateTemp(t.TempDir(), "original-controller-lock-")
	if err != nil {
		t.Fatal(err)
	}
	defer borrowed.Close()
	p.input, p.installLock, p.processLock = borrowed, borrowed, borrowed
	image := p.image
	// Hold one real readback/close transaction. A cancelled waiter cannot close
	// a descriptor currently used by that transaction or lose the retry owner.
	<-p.gate
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() { close(started); result <- p.Close(ctx) }()
	<-started
	cancel()
	if err := <-result; err == nil || p.image != image {
		t.Fatal("cancelled parent join discarded its retained original image", err)
	}
	if _, err := image.Stat(); err != nil {
		t.Fatal("cancelled parent join closed an entered native witness", err)
	}
	p.gate <- struct{}{}
	if err := p.Close(context.Background()); err != nil || !p.closed || p.image != nil {
		t.Fatal("retry did not join the exact partial native parent", err)
	}
	if _, err := image.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("successful parent join left its own descriptor alive", err)
	}
	if _, err := borrowed.Stat(); err != nil {
		t.Fatal("Node parent closed its controller's borrowed lifetime or locks", err)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal("acknowledged parent retirement was not idempotent", err)
	}
}

func TestDesktopLinuxNodeParentOldClosePreservesReplacement(t *testing.T) {
	old, replacement := desktopLinuxNodePartialFixture(t), desktopLinuxNodePartialFixture(t)
	owner := &ownedDesktopController{nodeParent: replacement}
	old.controller, replacement.controller = owner, owner
	oldImage, replacementImage := old.image, replacement.image
	if err := old.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if owner.nodeParent != replacement || replacement.image != replacementImage || replacement.ctx.Err() != nil {
		t.Fatal("stale parent retirement replaced the current owner")
	}
	if _, err := replacementImage.Stat(); err != nil {
		t.Fatal("stale parent completion closed the replacement descriptor", err)
	}
	if _, err := oldImage.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("stale parent failed to retire only its own descriptor", err)
	}
}

func TestDesktopLinuxNodeParentAlreadyClosedWitnessesJoin(t *testing.T) {
	for _, kind := range []string{"image", "network-namespace", "pid-namespace", "root"} {
		t.Run(kind, func(t *testing.T) {
			p := desktopLinuxNodePartialFixture(t)
			borrowed, err := os.CreateTemp(t.TempDir(), "borrowed-controller-")
			if err != nil {
				t.Fatal(err)
			}
			defer borrowed.Close()
			p.input, p.installLock, p.processLock = borrowed, borrowed, borrowed
			if kind == "root" {
				p.root, err = os.OpenRoot(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				err = p.root.Close()
			} else {
				file := p.image
				if kind != "image" {
					file, err = os.CreateTemp(t.TempDir(), "exact-witness-")
					if err != nil {
						t.Fatal(err)
					}
					if kind == "network-namespace" {
						p.networkNamespace = file
					} else {
						p.pidNamespace = file
					}
				}
				err = file.Close()
			}
			if err != nil {
				t.Fatal("fixture did not acknowledge its exact original close", err)
			}
			if err := p.Close(context.Background()); err != nil || !p.closed || p.image != nil || p.root != nil ||
				p.networkNamespace != nil || p.pidNamespace != nil {
				t.Fatal("already-closed original witness prevented a complete native join", err)
			}
			if _, err := borrowed.Stat(); err != nil {
				t.Fatal("already-closed witness cleanup retired a borrowed controller", err)
			}
		})
	}
}

func TestDesktopLinuxNodeParentRetainsNativeCloseFailure(t *testing.T) {
	p := desktopLinuxNodePartialFixture(t)
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil || limit.Max >= 1<<31-1 {
		t.Fatal("fixture has no provably invalid descriptor above its native limit", limit, err)
	}
	// This value cannot identify any real descriptor under the observed hard
	// limit. No live descriptor is raw-closed or made available for reuse.
	p.networkNamespace = os.NewFile(uintptr(1<<31-1), "unassigned-native-descriptor")
	if p.networkNamespace == nil {
		t.Fatal("fixture did not retain its invalid native descriptor wrapper")
	}
	if err := p.Close(context.Background()); !errors.Is(err, syscall.EBADF) || p.retirementErr == nil || p.closed {
		t.Fatal("genuine native close failure was accepted as already retired", err)
	}
	if err := p.Close(context.Background()); !errors.Is(err, syscall.EBADF) || p.closed {
		t.Fatal("subsequent Go ErrClosed erased an unacknowledged native close", err)
	}
	if p.networkNamespace != nil || p.image != nil {
		t.Fatal("retry did not join remaining exact native wrappers")
	}
}

type desktopLinuxNodeCloseRetryFixture struct{ calls int }

func (p *desktopLinuxNodeCloseRetryFixture) Close(context.Context) error {
	p.calls++
	if p.calls == 1 {
		return errors.New("exact partial parent is still joining")
	}
	return nil
}

func TestDesktopLinuxNodeControllerCloseRetainsLocksUntilParentJoin(t *testing.T) {
	parent := &desktopLinuxNodeCloseRetryFixture{}
	owner := &ownedDesktopController{nodeParent: parent}
	for index, field := range []**os.File{&owner.input, &owner.installLock, &owner.processLock} {
		path := filepath.Join(t.TempDir(), string(rune('a'+index)))
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		*field = file
		defer file.Close()
	}
	owner.close()
	for _, file := range []*os.File{owner.input, owner.installLock, owner.processLock} {
		if _, err := file.Stat(); err != nil {
			t.Fatal("partial parent join released its authenticated controller owner", err)
		}
	}
	owner.close()
	for _, file := range []*os.File{owner.input, owner.installLock, owner.processLock} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("successful parent retry did not retire the original controller descriptors", err)
		}
	}
}

func TestDesktopLinuxNodeParentRejectsUncapturedApplication(t *testing.T) {
	for _, a := range []*app{nil, {}, {localController: testLocalControllerOwner()}} {
		if capture, err := captureDesktopLinuxNodeParent(a); err == nil || capture != nil {
			t.Fatal("ordinary HTTP or selected profile became a captured Linux parent")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var missing *desktopLinuxNodeParentCapture
	if missing.Current(ctx) == nil {
		t.Fatal("missing parent acquired current ownership")
	}
}
