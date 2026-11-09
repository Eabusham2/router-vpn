//go:build go1.25

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

type desktopRecoveryWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *desktopRecoveryWaitingContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

// The original context requests Done only after its real mutex admission
// fails TryLock. Cancel after that witness, keep the mutex held until the
// operation returns, then join before inspecting its captured state.
func desktopRecoveryCancelHeldAdmission(t *testing.T, mutex *sync.Mutex, run func(context.Context) error) {
	t.Helper()
	mutex.Lock()
	var released sync.Once
	unlock := func() { released.Do(mutex.Unlock) }
	defer unlock()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &desktopRecoveryWaitingContext{Context: parent, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	select {
	case <-ctx.waiting:
	case <-time.After(2 * time.Second):
		cancel()
		unlock()
		<-done
		t.Fatal("recovery or Off work did not reach the original caller's lock admission")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled recovery or Off work admitted a new effect")
		}
	case <-time.After(2 * time.Second):
		unlock()
		<-done
		t.Fatal("recovery or Off work waited for an ambient lock after original cancellation")
	}
}

func TestDesktopNodeRecoveryContextCancelsHeldAdmission(t *testing.T) {
	for _, where := range []string{"operation-capture", "application-capture", "startup-operation", "startup-application", "slot-initialize", "pending-off", "pending-recovery"} {
		t.Run(where, func(t *testing.T) {
			f := newDesktopRecoveryFixture(t, false, false)
			before := cloneRouterProfileStore(f.a.profiles)
			mutex := &f.a.mu
			var run func(context.Context) error
			switch where {
			case "operation-capture":
				run = func(ctx context.Context) error {
					_, finish, err := f.a.captureDesktopNodeRecoveryOperation(ctx, f.slot)
					if finish != nil {
						finish()
					}
					return err
				}
			case "application-capture":
				run = func(ctx context.Context) error { return f.a.ensureDesktopNodeRecovery(ctx, f.slot) }
			case "startup-operation", "startup-application":
				if where == "startup-operation" {
					mutex = &f.a.operationMu
				}
				run = func(ctx context.Context) error { return f.a.initializeDesktopNodeRecoveryWith(ctx, f.backend) }
			case "slot-initialize":
				mutex = &f.slot.mu
				run = func(ctx context.Context) error {
					return f.slot.initializeRecovery(ctx, f.a.profiles.SelectedID, f.a.cfg.ProfilesFile, func() bool { return true })
				}
			case "pending-off":
				mutex = &f.slot.mu
				run = func(ctx context.Context) error { _, err := f.slot.pendingOffContext(ctx); return err }
			case "pending-recovery":
				mutex = &f.slot.mu
				run = func(ctx context.Context) error { _, err := f.slot.recoveryPendingContext(ctx); return err }
			}
			desktopRecoveryCancelHeldAdmission(t, mutex, run)
			if f.opens != 0 || f.begins != 0 || f.recovery.runs != 0 || f.removeCalls != 0 || f.a.nodeRecovery != nil ||
				f.a.nodeProtection != f.slot || f.slot.recovery != nil || f.slot.journal != nil || f.slot.off != nil ||
				!reflect.DeepEqual(before, f.a.profiles) || !reflect.DeepEqual(f.kernel.target, &f.target) {
				t.Fatal("cancelled recovery admission changed the original native, profile or operation owner")
			}
		})
	}
}

func TestDesktopNodeRecoveryContextGuardKeepsOriginalCaller(t *testing.T) {
	for _, requireJournal := range []bool{false, true} {
		name := "read-only"
		if requireJournal {
			name = "source-start"
		}
		t.Run(name, func(t *testing.T) {
			f := newDesktopRecoveryFixture(t, false, false)
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &desktopRecoveryWaitingContext{Context: parent, waiting: make(chan struct{})}
			bootstrap := f.slot.backend.bootstrap
			held := make(chan struct{})
			f.slot.backend.bootstrap = func(actual context.Context, profiles string) (desktopNodeRecoveryBackend, error) {
				if actual != ctx {
					return desktopNodeRecoveryBackend{}, errors.New("recovery bootstrap replaced its original caller")
				}
				backend, err := bootstrap(actual, profiles)
				if err == nil {
					f.a.mu.Lock()
					close(held)
				}
				return backend, err
			}
			done := make(chan error, 1)
			go func() { done <- f.a.ensureDesktopNodeRecoveryMode(ctx, f.slot, requireJournal) }()
			select {
			case <-held:
			case err := <-done:
				t.Fatal("fixture did not reach the original recovery guard", err)
			case <-time.After(2 * time.Second):
				t.Fatal("fixture did not enter original recovery bootstrap")
			}
			var released sync.Once
			unlock := func() { released.Do(f.a.mu.Unlock) }
			defer unlock()
			select {
			case <-ctx.waiting:
			case <-time.After(2 * time.Second):
				cancel()
				unlock()
				<-done
				t.Fatal("recovery guard detached from its original caller while waiting")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil || f.opens != 0 || f.begins != 0 || f.slot.journal != nil || f.slot.known {
					t.Fatal("cancelled captured recovery guard opened or adopted a durable owner", err)
				}
			case <-time.After(2 * time.Second):
				unlock()
				<-done
				t.Fatal("captured recovery guard waited for an ambient application lock")
			}
		})
	}
}

func TestDesktopProtectionOffContextCancelsHeldAdmission(t *testing.T) {
	for _, where := range []string{"capture", "readiness", "current", "apply-slot", "apply-application", "save-slot", "save-application", "finish-slot", "finish-application"} {
		t.Run(where, func(t *testing.T) {
			f := newDesktopProtectionOffFixture(t)
			capture := f.capture(t)
			if where == "save-slot" || where == "save-application" || where == "finish-slot" || where == "finish-application" {
				if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err != nil {
					t.Fatal(err)
				}
			}
			if where == "finish-slot" || where == "finish-application" {
				if _, err := f.a.persistCapturedProtectionOff(context.Background(), f.slot, capture, false); err != nil {
					t.Fatal(err)
				}
			}
			before, target := cloneRouterProfileStore(f.a.profiles), copyDesktopNodeProtectionTarget(f.kernel.target)
			written, saved, owner, calls := capture.profileWritten.Load(), capture.profileSaved.Load(), capture.owner, f.calls
			fileBefore, err := os.ReadFile(f.a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			mutex := &f.slot.mu
			var run func(context.Context) error
			switch where {
			case "capture":
				run = func(ctx context.Context) error {
					_, err := f.slot.captureOff(ctx, capture.profileID, capture.profileRevision, capture.resultRevision, capture.token)
					return err
				}
			case "readiness":
				run = func(ctx context.Context) error { _, err := f.slot.offReadyToSaveContext(ctx, capture); return err }
			case "current":
				mutex = &f.a.mu
				run = func(ctx context.Context) error {
					if f.a.capturedProtectionOffCurrentContext(ctx, f.slot, capture, false) {
						return nil
					}
					return ctx.Err()
				}
			case "apply-slot":
				run = func(ctx context.Context) error { return f.slot.applyOff(ctx, capture, func() bool { return true }) }
			case "apply-application":
				mutex = &f.a.mu
				run = func(ctx context.Context) error {
					_, err := f.a.resumeDesktopProtectionOff(ctx, f.slot, capture, false)
					return err
				}
			case "save-slot", "save-application":
				if where == "save-application" {
					mutex = &f.a.mu
				}
				run = func(ctx context.Context) error {
					_, err := f.a.persistCapturedProtectionOff(ctx, f.slot, capture, false)
					return err
				}
			case "finish-slot", "finish-application":
				if where == "finish-application" {
					mutex = &f.a.mu
				}
				run = func(ctx context.Context) error {
					current := func() bool { return f.a.capturedProtectionOffCurrentContext(ctx, f.slot, capture, false) }
					return f.slot.finishOffSave(ctx, capture, current)
				}
			}
			desktopRecoveryCancelHeldAdmission(t, mutex, run)
			fileAfter, err := os.ReadFile(f.a.cfg.ProfilesFile)
			if err != nil || !bytes.Equal(fileBefore, fileAfter) || !reflect.DeepEqual(before, f.a.profiles) ||
				!reflect.DeepEqual(target, f.kernel.target) || f.a.nodeProtection != f.slot || f.slot.off != capture ||
				capture.profileWritten.Load() != written || capture.profileSaved.Load() != saved || capture.owner != owner || f.calls != calls {
				t.Fatal("cancelled Off admission changed or discarded its captured native and durable effects", err)
			}
		})
	}
}

func TestDesktopProtectionOffContextCancelsRecoveredProfileAdmission(t *testing.T) {
	for _, resume := range []bool{false, true} {
		name := "capture"
		if resume {
			name = "resume"
		}
		t.Run(name, func(t *testing.T) {
			f := newDesktopRecoveryFixture(t, true, false)
			if err := f.a.ensureDesktopNodeRecovery(context.Background(), f.slot); err != nil {
				t.Fatal(err)
			}
			capture := f.slot.pendingOff()
			if capture == nil || !capture.recovered {
				t.Fatal("fixture did not recover the original durable Off intent")
			}
			before := cloneRouterProfileStore(f.a.profiles)
			desktopRecoveryCancelHeldAdmission(t, &f.a.mu, func(ctx context.Context) error {
				if resume {
					_, err := f.a.resumeDesktopProtectionOff(ctx, f.slot, capture, false)
					return err
				}
				return f.a.captureRecoveredOffProfileContext(ctx, f.slot, capture)
			})
			if f.slot.off != capture || f.removeCalls != 0 || capture.profileWritten.Load() || capture.profileSaved.Load() ||
				!reflect.DeepEqual(f.kernel.target, &f.target) || !reflect.DeepEqual(before, f.a.profiles) {
				t.Fatal("cancelled recovered profile admission removed protection or published Off")
			}
		})
	}
}

func TestDesktopProtectionOffContextKeepsSavedResultForCleanup(t *testing.T) {
	f := newDesktopDurableOffFixture(t, "always")
	capture := f.capture(t)
	current := func() bool { return f.a.capturedProtectionOffCurrent(f.slot, capture, false) }
	if err := f.slot.applyOff(context.Background(), capture, current); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.persistCapturedProtectionOff(context.Background(), f.slot, capture, false); err != nil {
		t.Fatal(err)
	}
	info := desktopRecoveryHoldSavedProfile(t, f.a.cfg.ProfilesFile)
	saved, err := os.ReadFile(f.a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	owner := capture.owner
	desktopRecoveryCancelHeldAdmission(t, &f.slot.mu, func(ctx context.Context) error {
		return f.slot.finishOffSave(ctx, capture, func() bool { return f.a.capturedProtectionOffCurrentContext(ctx, f.slot, capture, false) })
	})
	if !capture.profileWritten.Load() || !capture.profileSaved.Load() || capture.owner != owner || f.a.profiles.Profiles[0].KillSwitchPolicy != "off" {
		t.Fatal("cancelled settlement admission rolled back the already published Off result")
	}
	// Shutdown resumes only this accepted operation under its existing cleanup
	// authority. The cancelled work context cannot deny that independent join.
	f.a.closing, f.a.state.Phase = true, "stopping"
	if _, err := f.a.resumeDesktopProtectionOff(context.Background(), f.slot, capture, true); err != nil {
		t.Fatal("cancelled work admission denied original cleanup", err)
	}
	f.finished(t)
	after, err := os.ReadFile(f.a.cfg.ProfilesFile)
	currentInfo, statErr := os.Stat(f.a.cfg.ProfilesFile)
	if err != nil || statErr != nil || !bytes.Equal(saved, after) || !os.SameFile(info, currentInfo) || f.calls != 1 || capture.owner != owner {
		t.Fatal("cleanup resaved Off or replaced the accepted native removal", err, statErr)
	}
}
