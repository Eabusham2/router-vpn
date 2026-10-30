package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func desktopNodeProcessArgumentsFixture(t *testing.T) (string, []string) {
	t.Helper()
	directory := t.TempDir()
	return directory, []string{"routervpn-node", "--runtime-dir", directory, "--session", strings.Repeat("a", 32),
		"--config-sha256", strings.Repeat("b", 64), "--physical-source-sha256", strings.Repeat("c", 64),
		"--physical-transfer-sha256", strings.Repeat("d", 64)}
}

func TestDesktopNodeProcessArguments(t *testing.T) {
	directory, arguments := desktopNodeProcessArgumentsFixture(t)
	for _, mtu := range []string{"", "1280", "1420", "9000"} {
		candidate := append([]string(nil), arguments...)
		if mtu != "" {
			candidate = append(candidate, "--physical-mtu", mtu)
		}
		captured, err := validateDesktopNodeProcessArguments(candidate, directory)
		if err != nil {
			t.Fatal(err)
		}
		candidate[0] = "another-command"
		if captured[0] != "routervpn-node" {
			t.Fatal("captured Node argv retained caller-mutable storage")
		}
	}
	for _, item := range []struct {
		name  string
		alter func([]string) []string
	}{
		{"interpreter", func(v []string) []string { v[0] = "powershell.exe"; return v }},
		{"another-directory", func(v []string) []string { v[2] = filepath.Join(directory, "replacement"); return v }},
		{"missing-source", func(v []string) []string { return append(v[:7], v[9:]...) }},
		{"duplicate-source", func(v []string) []string { return append(v, "--physical-source-sha256", v[8]) }},
		{"credential-flag", func(v []string) []string { return append(v, "--owner-token", strings.Repeat("f", 64)) }},
		{"upper-session", func(v []string) []string { v[4] = strings.ToUpper(v[4]); return v }},
		{"short-session", func(v []string) []string { v[4] = v[4][1:]; return v }},
		{"invalid-config", func(v []string) []string { v[6] = strings.Repeat("g", 64); return v }},
		{"upper-transfer", func(v []string) []string { v[10] = strings.ToUpper(v[10]); return v }},
		{"zero-mtu", func(v []string) []string { return append(v, "--physical-mtu", "0") }},
		{"low-mtu", func(v []string) []string { return append(v, "--physical-mtu", "1279") }},
		{"large-mtu", func(v []string) []string { return append(v, "--physical-mtu", "9001") }},
		{"noncanonical-mtu", func(v []string) []string { return append(v, "--physical-mtu", "01420") }},
		{"flag-injection", func(v []string) []string { v[10] += "\n--config"; return v }},
	} {
		t.Run(item.name, func(t *testing.T) {
			candidate := item.alter(append([]string(nil), arguments...))
			if _, err := validateDesktopNodeProcessArguments(candidate, directory); err == nil {
				t.Fatal("native Node launch accepted substituted or incomplete authority")
			}
		})
	}
	if _, err := validateDesktopNodeProcessArguments(arguments, "."); err == nil {
		t.Fatal("native Node launch accepted a relative working directory")
	}
}

type desktopNodeProcessFakeChild struct {
	alive func() error
	close func(context.Context) error
}

func (child *desktopNodeProcessFakeChild) Alive() error                    { return child.alive() }
func (child *desktopNodeProcessFakeChild) Close(ctx context.Context) error { return child.close(ctx) }

type desktopNodeProcessFakeWaiter struct {
	exit       chan struct{}
	code       uint32
	err        error
	closeCalls atomic.Int32
}

func (waiter *desktopNodeProcessFakeWaiter) Wait(ctx context.Context) (uint32, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-waiter.exit:
		return waiter.code, waiter.err
	}
}
func (waiter *desktopNodeProcessFakeWaiter) Close() error { waiter.closeCalls.Add(1); return nil }

type desktopNodeProcessCloseFunc func() error

func (close desktopNodeProcessCloseFunc) Close() error { return close() }

func TestDesktopNodeProcessFailedJoinRetainsPinsAndExactWait(t *testing.T) {
	waiter := &desktopNodeProcessFakeWaiter{exit: make(chan struct{}), code: 19}
	owner := newDesktopNodeProcessOwner(func() error { return nil })
	var joins, pins atomic.Int32
	joinErr := errors.New("actual child Job join failed")
	owner.child = &desktopNodeProcessFakeChild{alive: func() error { return nil }, close: func(context.Context) error {
		if joins.Add(1) == 1 {
			return joinErr
		}
		close(waiter.exit)
		return nil
	}}
	owner.pins = []io.Closer{desktopNodeProcessCloseFunc(func() error { pins.Add(1); return nil })}
	owner.started = true
	owner.observe(waiter)
	if err := owner.Alive(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := owner.Close(ctx); !errors.Is(err, joinErr) || pins.Load() != 0 || waiter.closeCalls.Load() != 0 {
		t.Fatal("failed native join released a retained image or exit owner", err)
	}
	if owner.Alive() == nil {
		t.Fatal("pending native retirement still admitted new use")
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if code, err := owner.Wait(ctx); err != nil || code != 19 {
		t.Fatal("native retirement lost the actual retained exit observation", code, err)
	}
	if err := owner.Close(ctx); err != nil || joins.Load() != 2 || pins.Load() != 1 || waiter.closeCalls.Load() != 1 {
		t.Fatal("duplicate native close changed or repeated a retired owner", err)
	}
}

func TestDesktopNodeProcessConcurrentCloseJoinsAndHonorsCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := newDesktopNodeProcessOwner(func() error { return nil })
		release := make(chan struct{})
		var calls, pins atomic.Int32
		owner.child = &desktopNodeProcessFakeChild{alive: func() error { return nil }, close: func(context.Context) error {
			calls.Add(1)
			<-release
			return nil
		}}
		owner.pins = []io.Closer{desktopNodeProcessCloseFunc(func() error { pins.Add(1); return nil })}
		first := make(chan error, 1)
		go func() { first <- owner.Close(context.Background()) }()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		second := make(chan error, 1)
		go func() { second <- owner.Close(ctx) }()
		synctest.Wait()
		if calls.Load() != 1 || pins.Load() != 0 {
			t.Fatal("duplicate close bypassed a pending retained child join")
		}
		cancel()
		if err := <-second; !errors.Is(err, context.Canceled) {
			t.Fatal("duplicate native close ignored its cancelled caller", err)
		}
		close(release)
		if err := <-first; err != nil || pins.Load() != 1 {
			t.Fatal("joined native close lost its retained pins", err)
		}
	})
}

func TestDesktopNodeProcessCancelledWaitDoesNotManufactureExit(t *testing.T) {
	waiter := &desktopNodeProcessFakeWaiter{exit: make(chan struct{}), code: 5}
	owner := newDesktopNodeProcessOwner(func() error { return nil })
	var join sync.Once
	owner.child = &desktopNodeProcessFakeChild{alive: func() error { return nil }, close: func(context.Context) error {
		join.Do(func() { close(waiter.exit) })
		return nil
	}}
	owner.started = true
	owner.observe(waiter)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := owner.Wait(ctx); !errors.Is(err, context.Canceled) || waiter.closeCalls.Load() != 0 {
		t.Fatal("cancelled native wait replaced actual exit evidence", err)
	}
	if err := owner.Alive(); err != nil {
		t.Fatal("cancelled observer retired a live child", err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := owner.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	if code, err := owner.Wait(cleanup); err != nil || code != 5 {
		t.Fatal("retrying the cancelled observer lost the actual child exit", code, err)
	}
}

func TestDesktopNodeProcessControllerReplacementAndPartialOwner(t *testing.T) {
	var replaced atomic.Bool
	owner := newDesktopNodeProcessOwner(func() error {
		if replaced.Load() {
			return errors.New("original controller was replaced")
		}
		return nil
	})
	var closes, pins atomic.Int32
	owner.child = &desktopNodeProcessFakeChild{alive: func() error { return nil }, close: func(context.Context) error { closes.Add(1); return nil }}
	owner.started = true
	owner.pins = []io.Closer{desktopNodeProcessCloseFunc(func() error { pins.Add(1); return nil })}
	if err := owner.Alive(); err != nil {
		t.Fatal(err)
	}
	replaced.Store(true)
	if owner.Alive() == nil || closes.Load() != 0 || pins.Load() != 0 {
		t.Fatal("replacement controller adopted or silently retired an earlier child")
	}
	if _, err := owner.Wait(context.Background()); err == nil {
		t.Fatal("partial creation without a retained waiter fabricated child exit")
	}
	if err := owner.Close(context.Background()); err != nil || closes.Load() != 1 || pins.Load() != 1 {
		t.Fatal("partial native owner did not join its exact retained child", err)
	}
}

func TestDesktopNodeProcessPinReleaseRetriesAfterJoinedChild(t *testing.T) {
	owner := newDesktopNodeProcessOwner(func() error { return nil })
	var childCloses, pinCloses atomic.Int32
	owner.child = &desktopNodeProcessFakeChild{alive: func() error { return nil }, close: func(context.Context) error { childCloses.Add(1); return nil }}
	failed := errors.New("retained image handle close failed")
	owner.pins = []io.Closer{desktopNodeProcessCloseFunc(func() error {
		if pinCloses.Add(1) == 1 {
			return failed
		}
		return nil
	})}
	if err := owner.Close(context.Background()); !errors.Is(err, failed) {
		t.Fatal("failed image release was hidden", err)
	}
	if err := owner.Close(context.Background()); err != nil || childCloses.Load() != 1 || pinCloses.Load() != 2 {
		t.Fatal("retained image release did not retry after the already joined child", err)
	}
}
