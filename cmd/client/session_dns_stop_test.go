package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"router-vpn/internal/common"
)

func TestOrdinaryStopJoinsSelectedDNSBeforeRuntimeTeardown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		a.modes = []common.Mode{{ID: "multihop"}}
		entered, cancelled, cleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		releaseCleanup := func() { once.Do(func() { close(cleanup) }) }
		work := startSessionDNSFixture(t, tracker, observed, id, func(ctx context.Context, a *app, s observedConnection, mode string) dnsProofState {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-cleanup
			return successfulDNSProof(ctx, a, s, mode)
		})
		defer func() { work.cancel(); releaseCleanup(); <-work.done }()
		<-entered
		done := make(chan error, 1)
		go func() {
			a.operationMu.Lock()
			defer a.operationMu.Unlock()
			done <- a.stopModeWithIntent(true)
		}()
		select {
		case err := <-done:
			t.Fatal("ordinary Stop returned before the original selected-DNS worker joined", err)
		case <-cancelled:
		}
		select {
		case err := <-done:
			t.Fatal("ordinary Stop detached entered DNS cleanup", err)
		default:
		}
		a.mu.Lock()
		connected := a.state.Connected
		a.mu.Unlock()
		if !connected {
			t.Fatal("ordinary Stop retired its runtime before selected-DNS cleanup joined")
		}
		releaseCleanup()
		if err := <-done; err != nil {
			t.Fatal("ordinary Stop failed after original DNS cleanup joined", err)
		}
		select {
		case <-work.done:
		default:
			t.Fatal("ordinary Stop completed without the exact DNS join receipt")
		}
		if tracker.dnsProofClosed || a.state.Connected || a.state.Phase != "off" || tracker.snapshot(0).DNSProof.Status == "passed" {
			t.Fatal("ordinary Stop closed its reusable tracker or adopted a late DNS result")
		}
	})
}

func ordinaryDNSStop(t *testing.T, a *app) error {
	t.Helper()
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	return a.stopModeWithIntent(true)
}

// Exercise real connection admission and session declaration on the same
// tracker. Runtime publication is modeled here; native/device acceptance is
// covered by the existing platform gates, not this DNS lifetime fixture.
func ordinaryDNSReconnect(t *testing.T, a *app, tracker *sessionTracker) (observedConnection, string) {
	t.Helper()
	tracker.observe(tracker.capture())
	_, finish, err := a.beginConnectionTransactionContext(context.Background())
	if err != nil {
		t.Fatal("completed Stop did not admit a fresh connection", err)
	}
	defer finish()
	tracker.declareRequest("multihop", "wg")
	a.mu.Lock()
	a.state = state{Connected: true, Phase: "connected", RouterID: "exit", Mode: "multihop", RuntimeMode: "shadowsocks", Base: "wg"}
	entry, exit := a.profiles.Profiles[0], a.profiles.Profiles[1]
	a.mu.Unlock()
	setActiveMultihopGraph(a, multihopSelection{Entry: entry, Exit: exit, Base: "wg", ExitMode: "shadowsocks"})
	tracker.mu.Lock()
	tracker.dnsProofRunning = true // Supply the controlled resolver below.
	tracker.mu.Unlock()
	tracker.observe(tracker.capture())
	if current, ok := sessionTrackers.Load(a); !ok || current != tracker || tracker.dnsProofClosed {
		t.Fatal("reconnect replaced or terminally closed its ordinary tracker")
	}
	return tracker.capture(), tracker.snapshot(0).ID
}

func ordinaryDNSAssertPending(t *testing.T, a *app, tracker *sessionTracker, receipt *sessionDNSStopReceipt) {
	t.Helper()
	if !strings.Contains(tracker.snapshot(0).DNSProof.Reason, "previous Stop") || tracker.snapshot(0).DNSProof.Status == "passed" {
		t.Fatal("pending Stop is missing from selected-DNS status")
	}
	before := a.state
	operation, finish, err := a.beginConnectionTransactionContext(context.Background())
	if finish != nil {
		finish()
	}
	if !errors.Is(err, errSessionDNSStopPending) || operation != nil || finish != nil || a.state != before || a.connectionContext != nil {
		t.Fatal("new Connect bypassed pending Stop or changed connection state", err)
	}
	if tracker.dnsProofStop != receipt || tracker.dnsProofWork != receipt.work {
		t.Fatal("rejected Connect discarded the exact pending Stop receipt")
	}
	if !a.operationMu.TryLock() {
		t.Fatal("pending Stop admission retained the connection transaction")
	}
	a.operationMu.Unlock()
}

func TestOrdinaryStopDNSDeadlineRetainsReceiptUntilExplicitRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		a.modes = []common.Mode{{ID: "multihop"}}
		entered, cleanup := make(chan struct{}), make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(cleanup) }) }
		work := startSessionDNSFixture(t, tracker, observed, id, func(ctx context.Context, a *app, s observedConnection, mode string) dnsProofState {
			close(entered)
			<-ctx.Done()
			<-cleanup
			return successfulDNSProof(ctx, a, s, mode)
		})
		defer func() { work.cancel(); release(); <-work.done }()
		<-entered
		if err := ordinaryDNSStop(t, a); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("Stop lost its original bounded join deadline", err)
		}
		receipt := tracker.dnsProofStop
		if receipt == nil || receipt.work != work || !a.state.Connected || tracker.dnsProofClosed {
			t.Fatal("expired Stop lost the original worker or retired its runtime")
		}
		// A separate failure may already have moved presentation to idle. This
		// must not let Connect silently inherit permanently paused DNS work.
		for _, phase := range []string{"failed", "off"} {
			a.mu.Lock()
			a.state.Connected, a.state.Phase = false, phase
			a.mu.Unlock()
			ordinaryDNSAssertPending(t, a, tracker, receipt)
		}
		release()
		<-work.done
		ordinaryDNSAssertPending(t, a, tracker, receipt)
		if err := ordinaryDNSStop(t, a); err != nil {
			t.Fatal("explicit Stop retry did not join and complete its original receipt", err)
		}
		if tracker.dnsProofStop != nil || tracker.dnsProofWork != nil || tracker.dnsProofClosed {
			t.Fatal("completed retry retained its fence or closed the reusable tracker")
		}
		fresh, freshID := ordinaryDNSReconnect(t, a, tracker)
		next := startSessionDNSFixture(t, tracker, fresh, freshID, successfulDNSProof)
		<-next.done
		if next == work || tracker.snapshot(0).DNSProof.Status != "passed" {
			t.Fatal("fresh connection could not prove selected DNS on the same tracker")
		}
	})
}

func TestOrdinaryStopDNSRuntimeFailureBlocksConnectUntilRetry(t *testing.T) {
	a, tracker, observed, id := dnsPathFixture(t)
	work := startSessionDNSFixture(t, tracker, observed, id, successfulDNSProof)
	<-work.done
	// The actual ordinary cleanup fails because its original mode is absent.
	if err := ordinaryDNSStop(t, a); err == nil || a.state.Phase != "failed" {
		t.Fatal("fixture did not reach the actual runtime cleanup failure", err)
	}
	receipt := tracker.dnsProofStop
	if receipt == nil || receipt.work != work {
		t.Fatal("runtime failure discarded the already joined DNS fence")
	}
	ordinaryDNSAssertPending(t, a, tracker, receipt)
	a.modes = []common.Mode{{ID: "multihop"}}
	if err := ordinaryDNSStop(t, a); err != nil {
		t.Fatal("owned runtime cleanup retry failed", err)
	}
	fresh, freshID := ordinaryDNSReconnect(t, a, tracker)
	next := startSessionDNSFixture(t, tracker, fresh, freshID, successfulDNSProof)
	<-next.done
	if tracker.snapshot(0).DNSProof.Status != "passed" {
		t.Fatal("successful runtime retry left selected DNS permanently paused")
	}
}

func TestOrdinaryStopDNSRejectsSnapshotsAcrossIdenticalReconnect(t *testing.T) {
	a, tracker, before, id := dnsPathFixture(t)
	a.modes = []common.Mode{{ID: "multihop"}}
	a.operationMu.Lock()
	receipt, err := a.drainSessionDNSForStop(context.Background())
	a.operationMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	during := tracker.capture()
	var calls atomic.Int32
	probe := func(context.Context, *app, observedConnection, string) dnsProofState {
		calls.Add(1)
		return dnsProofState{Status: "passed"}
	}
	tracker.mu.Lock()
	tracker.startDNSProofLocked(id, during, during.RuntimeMode, probe)
	refused := tracker.dnsProofWork == nil && tracker.dnsProofStop == receipt
	unexpected := tracker.dnsProofWork
	tracker.mu.Unlock()
	if !refused {
		if unexpected != nil {
			unexpected.cancel()
			<-unexpected.done
		}
		t.Fatal("a fresh observation started DNS while Stop was fenced")
	}
	if err := ordinaryDNSStop(t, a); err != nil {
		t.Fatal(err)
	}
	fresh, freshID := ordinaryDNSReconnect(t, a, tracker)
	for name, stale := range map[string]observedConnection{"before": before, "during": during} {
		tracker.mu.Lock()
		tracker.startDNSProofLocked(freshID, stale, stale.RuntimeMode, probe)
		refused := tracker.dnsProofWork == nil
		unexpected := tracker.dnsProofWork
		tracker.mu.Unlock()
		if !refused {
			unexpected.cancel()
			<-unexpected.done
			t.Fatal("delayed connected snapshot escaped its Stop epoch", name)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("a retired observation reached the resolver")
	}
	work := startSessionDNSFixture(t, tracker, fresh, freshID, successfulDNSProof)
	<-work.done
	if tracker.snapshot(0).DNSProof.Status != "passed" {
		t.Fatal("fresh same-runtime observation did not prove DNS")
	}
}

func TestOrdinaryStopDNSReceiptCannotReopenReplacement(t *testing.T) {
	for _, replacement := range []string{"tracker", "receipt", "worker"} {
		t.Run(replacement, func(t *testing.T) {
			a, tracker, _, _ := dnsPathFixture(t)
			receipt, err := a.drainSessionDNSForStop(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var cancelled atomic.Bool
			work := &sessionDNSProofWork{sessionID: tracker.session.ID, done: make(chan struct{}), cancel: func() { cancelled.Store(true) }}
			current := tracker
			switch replacement {
			case "tracker":
				session := tracker.snapshot(0)
				current = &sessionTracker{a: a, session: &session, dnsProofWork: work}
				sessionTrackers.Store(a, current)
			case "receipt":
				tracker.dnsProofStop = &sessionDNSStopReceipt{tracker: tracker, epoch: tracker.dnsProofEpoch.Load()}
			case "worker":
				tracker.dnsProofWork = work
			}
			fence, epoch := current.dnsProofStop, current.dnsProofEpoch.Load()
			if err := receipt.finish(context.Background()); err == nil {
				t.Fatal("old Stop accepted a replacement retirement owner")
			}
			if current.dnsProofStop != fence || current.dnsProofEpoch.Load() != epoch || cancelled.Load() || current.dnsProofClosed {
				t.Fatal("old Stop changed its replacement's lifecycle")
			}
		})
	}
}

func TestOrdinaryStopDNSKeepsTerminalRetirementClosed(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	a.modes = []common.Mode{{ID: "multihop"}}
	if err := tracker.stopDNSProofs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ordinaryDNSStop(t, a); err != nil {
		t.Fatal(err)
	}
	if !tracker.dnsProofClosed || tracker.dnsProofStop != nil {
		t.Fatal("ordinary Stop reopened terminal DNS observation")
	}
	tracker.mu.Lock()
	tracker.startDNSProofLocked(tracker.session.ID, tracker.capture(), "shadowsocks", successfulDNSProof)
	if tracker.dnsProofWork != nil {
		t.Error("terminal tracker admitted another DNS worker")
	}
	tracker.mu.Unlock()
}

func TestOrdinaryStopDNSFencesConcurrentFirstStatus(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &app{state: state{Mode: "off", Phase: "off"}}
		start := make(chan struct{})
		status := make(chan *sessionTracker, 1)
		go func() { <-start; status <- sessionTrackerFor(a) }()
		close(start)
		receipt, err := a.drainSessionDNSForStop(context.Background())
		tracker := <-status
		defer func() { cancelSessionTracker(a); joinSessionTracker(a, tracker); sessionTrackers.Delete(a) }()
		if err != nil || receipt == nil || receipt.tracker != tracker || tracker.dnsProofStop != receipt {
			t.Fatal("first status escaped the ordinary Stop owner", err)
		}
		a.mu.Lock()
		a.state = state{Connected: true, Phase: "connected", Mode: "multihop", RuntimeMode: "shadowsocks", RouterID: "exit", Base: "wg"}
		a.modes = []common.Mode{{ID: "multihop"}}
		a.mu.Unlock()
		tracker.observe(tracker.capture())
		if tracker.dnsProofWork != nil || tracker.dnsProofClosed {
			t.Fatal("registered reusable tracker started DNS through the Stop fence")
		}
		if err := ordinaryDNSStop(t, a); err != nil || sessionTrackerFor(a) != tracker {
			t.Fatal("ordinary Stop lost its first registered tracker", err)
		}
	})
}

func TestConnectionAdmissionPendingDNSRetainsOriginalCaller(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	a.state = state{Mode: "off", Phase: "off"}
	connectionAdmissionCancelHeld(t, &tracker.mu, func(ctx context.Context) error {
		operation, finish, err := a.beginConnectionTransactionContext(ctx)
		if finish != nil {
			finish()
		}
		if operation != nil || finish != nil {
			return errors.New("cancelled DNS admission published a new connection")
		}
		return err
	})
	if a.connectionContext != nil || a.state.Phase != "off" || !a.operationMu.TryLock() {
		t.Fatal("cancelled DNS admission changed state or retained its transaction")
	}
	a.operationMu.Unlock()
}
