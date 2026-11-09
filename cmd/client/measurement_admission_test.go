//go:build go1.25

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

type measurementAdmissionWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
	ready   func() bool
}

func (ctx *measurementAdmissionWaitingContext) Done() <-chan struct{} {
	if ctx.ready == nil || ctx.ready() {
		ctx.once.Do(func() { close(ctx.waiting) })
	}
	return ctx.Context.Done()
}

func TestStoppedDNSResultCannotReserveReplacementTransaction(t *testing.T) {
	a, tracker, observed, id := dnsPathFixture(t)
	parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx, stop, err := tracker.dnsProofPathContextWithCaller(parent, id, observed, observed.RuntimeMode)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	// Hold the observer before Stop. The old result keeps its real captured
	// DNS context; rejection cannot be supplied by a periodic observer tick.
	releaseTracker := measurementHeldLock(&tracker.mu)
	defer releaseTracker()
	a.modes = []common.Mode{{ID: "multihop"}}
	a.operationMu.Lock()
	err = a.stopModeWithIntent(true)
	a.operationMu.Unlock()
	if err != nil || a.state.Connected || a.state.Phase != "off" {
		t.Fatal("original Stop did not finish before late DNS result", err, a.state)
	}
	releaseApp := measurementHeldLock(&a.mu)
	defer releaseApp()
	caller := &measurementAdmissionWaitingContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		release, err := a.beginAsyncMeasurementAdoption(caller)
		if release != nil {
			release()
		}
		done <- err
	}()
	// The new path witnesses a context-aware wait before reservation. The
	// old generic guard instead reserves operationMu then blocks on app.mu.
	// Both outcomes are observed directly; no scheduling sleep grants proof.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	available := false
observe:
	for {
		select {
		case <-caller.waiting:
			available = a.operationMu.TryLock()
			if available {
				a.operationMu.Unlock()
			}
			break observe
		case <-tick.C:
			if !a.operationMu.TryLock() {
				break observe
			}
			a.operationMu.Unlock()
		case <-deadline.C:
			releaseApp()
			releaseTracker()
			cancel()
			<-done
			t.Fatal("late result did not reach either actual admission boundary")
		}
	}
	releaseApp()
	releaseTracker()
	if err := measurementContextResult(t, done, func() { releaseApp(); releaseTracker() }); err == nil {
		t.Fatal("stopped DNS result was admitted")
	}
	if !available {
		t.Fatal("stopped DNS result reserved the replacement connection transaction before validating its retired owner")
	}
	_, finish, err := a.beginConnectionTransactionContext(context.Background())
	if err != nil {
		t.Fatal("retired DNS result blocked a replacement connection", err)
	}
	finish()
}

func TestAsyncMeasurementAdoptionRetainsProtectionAndViaEntryGuards(t *testing.T) {
	for _, guard := range []string{"healthy", "closing", "protection-off", "via-entry-running", "via-entry-undrained", "via-entry-drained", "other-transaction"} {
		t.Run(guard, func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			ctx, stop, _, err := asyncMeasurementPathContext(context.Background(), a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			control := viaEntryControlFor(a)
			t.Cleanup(func() { viaEntryControls.Delete(a) })
			receipt := &viaEntryReceipt{}
			switch guard {
			case "closing":
				a.closing = true
			case "protection-off":
				a.nodeProtection = &desktopNodeProtectionSlot{off: &desktopNodeProtectionOff{}}
			case "via-entry-running", "via-entry-undrained", "via-entry-drained":
				control.owner = &viaEntryOwner{running: guard == "via-entry-running", drained: guard == "via-entry-drained", receipt: receipt}
			case "other-transaction":
				a.operationMu.Lock()
			}
			release, err := a.beginAsyncMeasurementAdoption(ctx)
			want := guard == "healthy" || guard == "via-entry-drained"
			if release != nil {
				if a.operationMu.TryLock() {
					a.operationMu.Unlock()
					t.Error("accepted adoption did not retain its transaction")
				}
				release()
			}
			if guard == "other-transaction" {
				a.operationMu.Unlock()
			}
			if (err == nil) != want || (release != nil) != want {
				t.Fatal("measurement changed an existing admission guard", guard, err)
			}
			if !a.operationMu.TryLock() {
				t.Fatal("guard failure retained transaction ownership")
			}
			a.operationMu.Unlock()
			if control.owner != nil && (control.owner.receipt == nil) != (guard == "via-entry-drained") {
				t.Fatal("via-entry guard changed an active receipt or retained an expired one")
			}
			if !a.state.Connected || a.profiles.Profiles[1].FastestDNSHost != "old-result" || guard == "protection-off" && a.nodeProtection.off == nil {
				t.Fatal("admission changed the healthy runtime, result or retained protection owner")
			}
		})
	}
}

func TestStaleMeasurementCannotStartReplacementProtectionRecovery(t *testing.T) {
	for _, change := range []string{"current", "stopped", "session", "profile", "lifecycle"} {
		t.Run(change, func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx, stop, _, err := asyncMeasurementPathContext(parent, a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			tracker := sessionTrackerFor(a)
			releaseTracker := measurementHeldLock(&tracker.mu)
			defer releaseTracker()
			a.mu.Lock()
			switch change {
			case "stopped":
				a.state.Connected, a.state.Phase = false, "off"
			case "session":
				tracker.session.ID = "replacement-session"
			case "profile":
				a.profiles.Profiles[1].APIToken = "replacement-secret"
			case "lifecycle":
				homeExitProofs.Delete(a)
			}
			calls, reads := 0, 0
			witness := errors.New("actual protection bootstrap entered")
			slot := &desktopNodeProtectionSlot{backend: desktopNodeProtectionBackend{bootstrap: func(context.Context, string) (desktopNodeRecoveryBackend, error) {
				calls++
				return desktopNodeRecoveryBackend{}, witness
			}, read: func(context.Context, *mobiletor.DesktopWindowsProtectionTarget) error {
				reads++
				return errors.New("read must follow successful bootstrap")
			}}}
			a.nodeProtection = slot
			a.mu.Unlock()
			caller := &measurementAdmissionWaitingContext{Context: ctx, waiting: make(chan struct{})}
			done := make(chan error, 1)
			go func() {
				release, err := a.beginAsyncMeasurementAdoption(caller)
				if release != nil {
					release()
				}
				done <- err
			}()
			select {
			case <-caller.waiting:
				releaseTracker()
				err = measurementContextResult(t, done, releaseTracker)
			case err = <-done:
				releaseTracker()
			case <-time.After(time.Second):
				cancel()
				releaseTracker()
				<-done
				t.Fatal("measurement did not reach captured admission or protection guard")
			}
			want := 0
			if change == "current" {
				want = 1
				if !errors.Is(err, witness) || slot.recovery == nil || !errors.Is(slot.recovery.failure, witness) || slot.recovery.ready {
					t.Fatal("valid admission did not execute the existing recovery guard", err)
				}
			}
			if err == nil || calls != want || reads != 0 || a.nodeProtection != slot || a.nodeRecovery != nil || change != "current" && slot.recovery != nil {
				t.Fatal("stale result entered or changed replacement protection recovery", change, calls, err)
			}
		})
	}
}

func TestMeasurementAdoptionCancellationAfterOperationReservation(t *testing.T) {
	for _, guard := range []string{"protection", "via-entry"} {
		t.Run(guard, func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, stop, _, err := asyncMeasurementPathContext(parent, a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			control := viaEntryControlFor(a)
			t.Cleanup(func() { viaEntryControls.Delete(a) })
			mutex := &control.mu
			if guard == "protection" {
				a.nodeProtection = &desktopNodeProtectionSlot{}
				mutex = &a.nodeProtection.mu
			}
			releaseGuard := measurementHeldLock(mutex)
			defer releaseGuard()
			caller := &measurementAdmissionWaitingContext{Context: ctx, waiting: make(chan struct{}), ready: func() bool {
				// Only this adoption can own operationMu here. Ignore an earlier
				// observer/app wait; signal the retained guard after reservation.
				if a.operationMu.TryLock() {
					a.operationMu.Unlock()
					return false
				}
				return true
			}}
			done := make(chan error, 1)
			go func() {
				release, err := a.beginAsyncMeasurementAdoption(caller)
				if release != nil {
					release()
				}
				done <- err
			}()
			select {
			case <-caller.waiting:
			case <-time.After(time.Second):
				cancel()
				releaseGuard()
				<-done
				t.Fatal("admitted transaction did not reach its original guard")
			}
			if a.operationMu.TryLock() {
				a.operationMu.Unlock()
				cancel()
				releaseGuard()
				<-done
				t.Fatal("guard fixture never owned the measurement transaction")
			}
			cancel()
			if err := measurementContextResult(t, done, releaseGuard); !errors.Is(err, context.Canceled) {
				t.Fatal("entered guard lost original caller cancellation", err)
			}
			stop()
			// The guard remains held by this test until the admitted operation
			// has returned and released every lock it acquired itself.
			for name, mutex := range map[string]*sync.Mutex{"operation": &a.operationMu, "app": &a.mu, "tracker": &sessionTrackerFor(a).mu} {
				if !mutex.TryLock() {
					t.Fatal("cancelled guard retained owned lock", name)
				}
				mutex.Unlock()
			}
			if !a.state.Connected || a.profiles.Profiles[1].FastestDNSHost != "old-result" || control.owner != nil || a.nodeRecovery != nil {
				t.Fatal("cancelled admitted guard changed healthy runtime, result or cleanup ownership")
			}
		})
	}
}

func TestMeasurementAdoptionJoinsEnteredRecoveryAfterCancellation(t *testing.T) {
	a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), measurementCallerKey{}, "original-result"))
	defer cancel()
	ctx, stop, _, err := asyncMeasurementPathContext(parent, a, profile, a.state, session, asyncMeasurementProfileToken(profile))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	entered, cancelled, releaseCleanup := make(chan context.Context, 1), make(chan struct{}), make(chan struct{})
	var cleanupOnce sync.Once
	finishCleanup := func() { cleanupOnce.Do(func() { close(releaseCleanup) }) }
	defer finishCleanup()
	reads := 0
	slot := &desktopNodeProtectionSlot{backend: desktopNodeProtectionBackend{
		read: func(context.Context, *mobiletor.DesktopWindowsProtectionTarget) error {
			reads++
			return errors.New("cancelled bootstrap cannot reach native read")
		},
		bootstrap: func(actual context.Context, _ string) (desktopNodeRecoveryBackend, error) {
			entered <- actual
			select {
			case <-actual.Done():
				close(cancelled)
				<-releaseCleanup
				return desktopNodeRecoveryBackend{}, actual.Err()
			case <-releaseCleanup:
				return desktopNodeRecoveryBackend{}, errors.New("fixture released recovery without original cancellation")
			}
		},
	}}
	a.nodeProtection = slot
	done := make(chan error, 1)
	go func() {
		release, err := a.beginAsyncMeasurementAdoption(ctx)
		if release != nil {
			release()
		}
		done <- err
	}()
	select {
	case actual := <-entered:
		if actual.Value(measurementCallerKey{}) != "original-result" {
			finishCleanup()
			<-done
			t.Fatal("admitted recovery replaced the original result caller")
		}
	case <-time.After(time.Second):
		cancel()
		finishCleanup()
		<-done
		t.Fatal("admitted result did not enter the actual recovery bootstrap")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		finishCleanup()
		<-done
		t.Fatal("entered recovery ignored original measurement cancellation")
	}
	select {
	case <-done:
		t.Fatal("measurement detached an entered recovery before its cleanup joined")
	default:
	}
	if a.operationMu.TryLock() {
		a.operationMu.Unlock()
		t.Error("entered recovery released transaction before cleanup joined")
	}
	finishCleanup()
	if err := measurementContextResult(t, done, finishCleanup); !errors.Is(err, context.Canceled) {
		t.Fatal("joined recovery lost original cancellation", err)
	}
	stop()
	if !a.operationMu.TryLock() {
		t.Fatal("joined recovery retained measurement transaction")
	}
	a.operationMu.Unlock()
	if a.nodeRecovery != nil || a.nodeProtection != slot || reads != 0 || slot.recovery == nil || !errors.Is(slot.recovery.failure, context.Canceled) || !a.state.Connected || a.profiles.Profiles[1].FastestDNSHost != "old-result" {
		t.Fatal("cancelled joined recovery changed result or lost its exact failed cleanup receipt")
	}
}
