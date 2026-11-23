package main

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// Completion of a fifty-response request releases its MTU hold. That release
// resumes the original Auto worker before op.done closes, but does not join it.
// Wait for that exact worker and any DNS observation it registered before this
// fixture submits the next independent public request. Do not retry a request,
// cancel Auto/DNS, take operationMu, or retire the still-connected native owner.
func joinDesktopOrderedLatencyFixtureAutomatic(ctx context.Context, a *app, command *exec.Cmd, tracker *sessionTracker, sessionID string) error {
	if ctx == nil || a == nil || command == nil || tracker == nil || sessionID == "" {
		return errors.New("ordered fixture resume join lost its original identity")
	}
	current := func() error {
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return err
		}
		valid := a.cmd == command && a.state.Connected && a.state.Phase == "connected" && !a.controllerClosingLocked()
		a.mu.Unlock()
		_, session, err := measurementSessionContext(ctx, a, tracker)
		if err != nil || !valid || session.ID != sessionID || !session.Connected || session.Phase != "connected" {
			return errors.Join(err, errors.New("ordered fixture resume join changed its original session"))
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return err
	}
	raw, found := routerNodeAutomaticMTUs.Load(a)
	owner, ok := raw.(*routerNodeAutomaticMTU)
	if !found || !ok || owner == nil {
		return errors.New("ordered fixture lost its resumed Auto owner")
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := current(); err != nil {
			return err
		}
		actual, registered := routerNodeAutomaticMTUs.Load(a)
		if err := desktopnetwork.LockContext(ctx, &owner.mu); err != nil {
			return err
		}
		valid := registered && actual == owner && owner.command == command && !owner.retired && owner.workers >= 0
		joined := owner.workers == 0 && !owner.waiting
		owner.mu.Unlock()
		if !valid {
			return errors.New("ordered fixture resumed Auto was replaced or retired")
		}
		if joined {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	// Auto registers this worker synchronously before it returns. Waiting for
	// Auto's complete worker count first also covers an original resume handoff.
	if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
		return err
	}
	work := tracker.dnsProofWork
	tracker.mu.Unlock()
	if work != nil {
		if err := waitDesktopSpeedLabDNSObservation(ctx, speedLabPathIdentity{Tracker: tracker, SessionID: sessionID}); err != nil {
			return err
		}
		if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
			return err
		}
		same := tracker.dnsProofWork == work
		tracker.mu.Unlock()
		if !same {
			return errors.New("ordered fixture resumed DNS worker was replaced")
		}
	}
	actual, registered := routerNodeAutomaticMTUs.Load(a)
	if !registered || actual != owner {
		return errors.New("ordered fixture Auto owner changed during DNS join")
	}
	if err := desktopnetwork.LockContext(ctx, &owner.mu); err != nil {
		return err
	}
	joined := owner.command == command && !owner.retired && owner.workers == 0 && !owner.waiting
	owner.mu.Unlock()
	if !joined {
		return errors.New("ordered fixture Auto resumed or changed during DNS join")
	}
	if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
		return err
	}
	sameDNS := tracker.dnsProofWork == work
	tracker.mu.Unlock()
	if !sameDNS {
		return errors.New("ordered fixture registered different DNS work during its join")
	}
	return current()
}

func TestDesktopOrderedLatencyFixtureJoinsResumedAutomaticWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, snapshot := newMTUTransactionFixture(t)
		command := &exec.Cmd{Path: "original-latency-automatic-fixture"}
		a.cmd = command
		tracker := sessionTrackerFor(a)
		tracker.dnsProofRunning = true // DNS adoption is exercised separately below.
		entered, release := make(chan struct{}), make(chan struct{})
		a.startRouterNodeAutomaticMTUWithRun(func(mtuRetestSnapshot) mtuAutomaticResult {
			close(entered)
			<-release
			return mtuAutomaticResult{accepted: true}
		})
		<-entered
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
			synctest.Wait()
			routerNodeAutomaticMTUs.Delete(a)
		}()
		bounded, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := joinDesktopOrderedLatencyFixtureAutomatic(bounded, a, command, tracker, snapshot.SessionID); !errors.Is(err, context.DeadlineExceeded) {
			cancel()
			t.Fatal("fixture reported entered Auto work joined or lost the caller bound", err)
		}
		cancel()
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		done := make(chan error, 1)
		go func() {
			done <- joinDesktopOrderedLatencyFixtureAutomatic(ctx, a, command, tracker, snapshot.SessionID)
		}()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatal("fixture escaped the original held automatic worker", err)
		default:
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal("fixture did not join its original Auto completion", err)
		}
		raw, _ := routerNodeAutomaticMTUs.Load(a)
		owner := raw.(*routerNodeAutomaticMTU)
		if owner.retired || owner.workers != 0 || a.cmd != command || !a.state.Connected || tracker.dnsProofClosed {
			t.Fatal("nonterminal join changed the still-connected original owner")
		}
		a.cmd = &exec.Cmd{Path: "replacement"}
		if err := joinDesktopOrderedLatencyFixtureAutomatic(ctx, a, command, tracker, snapshot.SessionID); err == nil {
			t.Fatal("fixture joined a replacement connection")
		}
	})
}

func TestDesktopOrderedLatencyFixtureJoinsResumedDNSAdoption(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		command := &exec.Cmd{Path: "original-latency-dns-fixture"}
		a.cmd = command
		// The Auto counter is already idle here; this case isolates its actual
		// registered DNS worker and guarded adoption, not native MTU execution.
		routerNodeAutomaticMTUs.Store(a, &routerNodeAutomaticMTU{command: command})
		defer routerNodeAutomaticMTUs.Delete(a)
		control := viaEntryControlFor(a)
		defer viaEntryControls.Delete(a)
		releaseGuard := measurementHeldLock(&control.mu)
		defer releaseGuard()
		work := startSessionDNSFixture(t, tracker, observed, id, successfulDNSProof)
		defer func() { releaseGuard(); work.cancel(); <-work.done }()
		synctest.Wait()
		if a.operationMu.TryLock() {
			a.operationMu.Unlock()
			t.Fatal("original DNS adoption did not own the admission boundary")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- joinDesktopOrderedLatencyFixtureAutomatic(ctx, a, command, tracker, id) }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatal("fixture reported held DNS adoption joined", err)
		default:
		}
		releaseGuard()
		if err := <-done; err != nil {
			t.Fatal("fixture did not join the exact DNS adoption", err)
		}
		if tracker.dnsProofClosed || a.cmd != command || !a.state.Connected || !a.operationMu.TryLock() {
			t.Fatal("DNS join retired the session or left original admission owned")
		}
		a.operationMu.Unlock()
	})
}
