package main

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type macOSParentTestWitness struct {
	failed     atomic.Bool
	closes     atomic.Int32
	closeError atomic.Bool
	read       func()
}

func (w *macOSParentTestWitness) Current(ctx context.Context) error {
	if w.read != nil {
		w.read()
	}
	if w.failed.Load() {
		return errors.New("native witness replaced")
	}
	return ctx.Err()
}
func (w *macOSParentTestWitness) Close(context.Context) error {
	w.closes.Add(1)
	if w.closeError.Load() {
		return errors.New("native join pending")
	}
	return nil
}

type macOSParentTestChild struct{ close func(context.Context) error }

func (c *macOSParentTestChild) Close(ctx context.Context) error { return c.close(ctx) }

func macOSParentFixture(t *testing.T) (*desktopMacOSParent, *desktopMacOSSession, *ownedDesktopController, *macOSParentTestWitness, chan struct{}) {
	t.Helper()
	input, other, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); other.Close() })
	install, err := os.CreateTemp(t.TempDir(), "install")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { install.Close() })
	process, err := os.CreateTemp(t.TempDir(), "process")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { process.Close() })
	done := make(chan struct{})
	c := &ownedDesktopController{processID: os.Getpid(), callerUID: 501, accessToken: testLocalControllerAccess, ownerToken: testControllerOwner,
		input: input, installLock: install, processLock: process, ownerDone: done}
	w := &macOSParentTestWitness{}
	p, err := newDesktopMacOSParent(c, w)
	if err != nil {
		t.Fatal(err)
	}
	c.nodeParent = p
	s, err := p.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return p, s, c, w, done
}

func TestDesktopMacOSParentOriginalSessionAndJoin(t *testing.T) {
	p, s, c, w, _ := macOSParentFixture(t)
	same, err := p.Session(context.Background())
	if err != nil || same != s || s.Current(context.Background()) != nil {
		t.Fatal("original session was not retained", err)
	}
	var joined atomic.Int32
	child := &macOSParentTestChild{close: func(ctx context.Context) error {
		if p.Current(ctx) == nil || s.Current(ctx) == nil {
			return errors.New("closing parent still admits work")
		}
		for _, f := range []*os.File{c.input, c.installLock, c.processLock} {
			if _, err := f.Stat(); err != nil {
				return errors.New("borrowed descriptor closed before dependent join")
			}
		}
		if w.closes.Load() != 0 {
			return errors.New("native witnesses closed before dependent joined")
		}
		joined.Add(1)
		return nil
	}}
	if s.Retain(context.Background(), child) != nil || s.Retain(context.Background(), child) == nil {
		t.Fatal("dependent registration lost unique ownership")
	}
	c.close()
	if joined.Load() != 1 || w.closes.Load() != 1 || p.Current(context.Background()) == nil || s.Current(context.Background()) == nil {
		t.Fatal("parent retirement was not joined")
	}
	for _, f := range []*os.File{c.input, c.installLock, c.processLock} {
		if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("controller did not close borrowed descriptors after join", err)
		}
	}
	c.close()
	if joined.Load() != 1 || w.closes.Load() != 1 {
		t.Fatal("repeated close repeated native retirement")
	}
}

func TestDesktopMacOSParentFailedDependentRetainsOriginalLocks(t *testing.T) {
	p, s, c, w, _ := macOSParentFixture(t)
	var attempts atomic.Int32
	child := &macOSParentTestChild{close: func(context.Context) error {
		if attempts.Add(1) == 1 {
			return errors.New("child not joined")
		}
		return nil
	}}
	if err := s.Retain(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	c.close()
	if attempts.Load() != 1 || w.closes.Load() != 0 || p.Current(context.Background()) == nil {
		t.Fatal("failed child manufactured closed parent")
	}
	for _, f := range []*os.File{c.input, c.installLock, c.processLock} {
		if _, err := f.Stat(); err != nil {
			t.Fatal("failed join lost original lock", err)
		}
	}
	if err := s.Retain(context.Background(), &macOSParentTestChild{}); err == nil {
		t.Fatal("retiring session admitted successor")
	}
	c.close()
	if attempts.Load() != 2 || w.closes.Load() != 1 {
		t.Fatal("original dependent did not finish its retry")
	}
}

func TestDesktopMacOSParentRejectsReplacedControllerAndSession(t *testing.T) {
	for _, fault := range []string{"parent", "session", "input", "install", "process", "peer", "uid", "pid", "credential", "native"} {
		t.Run(fault, func(t *testing.T) {
			p, s, c, w, _ := macOSParentFixture(t)
			var replacementCloses atomic.Int32
			replacement := &macOSParentTestChild{close: func(context.Context) error { replacementCloses.Add(1); return nil }}
			switch fault {
			case "parent":
				c.nodeParent = replacement
			case "session":
				p.session = &desktopMacOSSession{parent: p, dependents: map[ownedDesktopNodeParent]struct{}{replacement: {}}}
			case "input":
				c.input = c.installLock
			case "install":
				c.installLock = c.processLock
			case "process":
				c.processLock = c.installLock
			case "peer":
				c.ownerDone = make(chan struct{})
			case "uid":
				c.callerUID++
			case "pid":
				c.processID++
			case "credential":
				c.accessToken = testControllerOwner
			case "native":
				w.failed.Store(true)
			}
			if p.Current(context.Background()) == nil || s.Current(context.Background()) == nil {
				t.Fatal("replacement retained old authority")
			}
			// Restoring a pathname/pointer cannot revive an invalidated lifetime.
			c.nodeParent = p
			c.input = p.input
			c.installLock = p.installLock
			c.processLock = p.processLock
			c.ownerDone = p.ownerDone
			c.callerUID = p.callerUID
			c.processID = p.processID
			c.accessToken = testLocalControllerAccess
			p.session = s
			w.failed.Store(false)
			if p.Current(context.Background()) == nil {
				t.Fatal("invalidated parent revived")
			}
			if err := p.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if replacementCloses.Load() != 0 {
				t.Fatal("old owner closed replacement")
			}
		})
	}
}

func TestDesktopMacOSParentLifetimeCancellationAndBoundedJoin(t *testing.T) {
	p, s, _, w, done := macOSParentFixture(t)
	close(done)
	select {
	case <-p.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("native peer exit did not revoke parent")
	}
	if s.Current(context.Background()) == nil {
		t.Fatal("session survived lost native desktop")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(p.Close(cancelled), context.Canceled) || w.closes.Load() != 0 {
		t.Fatal("cancelled caller invented joined cleanup")
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopMacOSParentConcurrentCloseJoinsEnteredDependent(t *testing.T) {
	p, s, _, w, _ := macOSParentFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	child := &macOSParentTestChild{close: func(ctx context.Context) error {
		if calls.Add(1) != 1 {
			return errors.New("duplicate entered close")
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	if err := s.Retain(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- p.Close(context.Background()) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if p.Close(ctx) == nil || w.closes.Load() != 0 {
		t.Fatal("second closer acknowledged pending dependent")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || w.closes.Load() != 1 {
		t.Fatal("concurrent retirement lost original join")
	}
}

func TestDesktopMacOSSessionCloseDoesNotCloseBorrowedController(t *testing.T) {
	p, s, c, w, _ := macOSParentFixture(t)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Current(context.Background()) == nil || p.Current(context.Background()) == nil || w.closes.Load() != 0 {
		t.Fatal("closed session still admits work or closed parent witnesses")
	}
	for _, f := range []*os.File{c.input, c.installLock, c.processLock} {
		if _, err := f.Stat(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDesktopMacOSSessionCapturesOriginalApplication(t *testing.T) {
	p, s, c, _, _ := macOSParentFixture(t)
	a := &app{localController: c}
	captured, err := captureDesktopMacOSSession(context.Background(), a)
	if err != nil || captured.parent != p || captured.session != s {
		t.Fatal("application lost original session", err)
	}
	a.localController = &ownedDesktopController{}
	if captured.Current(context.Background()) == nil {
		t.Fatal("old session capture accepted replacement controller")
	}
	if p.Current(context.Background()) != nil {
		t.Fatal("foreign application pointer revoked original native parent")
	}
	a.localController = c
	if captured.Current(context.Background()) == nil {
		t.Fatal("retired application capture revived after pointer restoration")
	}
}

func TestDesktopMacOSParentCancelledReadDoesNotRetireSharedSession(t *testing.T) {
	p, s, _, w, _ := macOSParentFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.read = cancel
	if err := p.Current(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled native read lost original error", err)
	}
	w.read = nil
	if err := s.Current(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("already cancelled caller lost original error", err)
	}
	if err := s.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled session close lost original error", err)
	}
	deadline, finish := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer finish()
	if err := p.Current(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired request lost original deadline", err)
	}
	if p.ctx.Err() != nil || s.Current(context.Background()) != nil {
		t.Fatal("one cancelled caller retired shared native authority")
	}
}
