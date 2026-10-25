package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mtuWaitCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !condition() {
		select {
		case <-deadline.C:
			t.Fatal("captured MTU condition did not complete")
		case <-ticker.C:
		}
	}
}

func TestRouterNodeAutomaticMTUWaitsForConnectionAndRejectsReplacedProcess(t *testing.T) {
	a, _ := newMTUTransactionFixture(t)
	a.cmd = &exec.Cmd{Path: "old-owned-runtime"}
	tracker := sessionTrackerFor(a)
	tracker.dnsProofRunning = true // This fixture tests MTU scheduling, not DNS transport.
	t.Cleanup(func() {
		a.mu.Lock()
		a.state.Connected = false
		a.mu.Unlock()
		routerNodeAutomaticMTUs.Delete(a)
	})
	old := make(chan mtuRetestSnapshot, 1)
	a.operationMu.Lock()
	a.startRouterNodeAutomaticMTUWithRun(func(snapshot mtuRetestSnapshot) mtuAutomaticResult {
		old <- snapshot
		return mtuAutomaticResult{accepted: true}
	})
	value, ok := routerNodeAutomaticMTUs.Load(a)
	if !ok {
		t.Fatal("Auto never captured the connection")
	}
	owner := value.(*routerNodeAutomaticMTU)
	a.mu.Lock()
	a.cmd = &exec.Cmd{Path: "replacement-owned-runtime"}
	a.mu.Unlock()
	a.operationMu.Unlock()
	mtuWaitCondition(t, func() bool { owner.mu.Lock(); defer owner.mu.Unlock(); return !owner.waiting })
	select {
	case <-old:
		t.Fatal("old automatic worker adopted the replacement connection")
	default:
	}
	fresh := make(chan mtuRetestSnapshot, 2)
	a.startRouterNodeAutomaticMTUWithRun(func(snapshot mtuRetestSnapshot) mtuAutomaticResult {
		fresh <- snapshot
		return mtuAutomaticResult{accepted: true}
	})
	select {
	case snapshot := <-fresh:
		if snapshot.Profile.ID != "node" || snapshot.SessionID == "" || snapshot.Mode != "shadowsocks" {
			t.Fatal("Auto lost the captured Router-node path", snapshot)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proved replacement connection never ran Auto")
	}
	mtuWaitCondition(t, func() bool { owner.mu.Lock(); defer owner.mu.Unlock(); return !owner.waiting })
	a.startRouterNodeAutomaticMTUWithRun(func(snapshot mtuRetestSnapshot) mtuAutomaticResult {
		fresh <- snapshot
		return mtuAutomaticResult{accepted: true}
	})
	select {
	case <-fresh:
		t.Fatal("Auto reran an already attempted connection")
	default:
	}
}

func TestRouterNodeAutomaticMTUHoldReleaseBeforeWaitingWorkerFinishes(t *testing.T) {
	a, _ := newMTUTransactionFixture(t)
	command := &exec.Cmd{Path: "held-owned-runtime"}
	a.cmd = command
	sessionTrackerFor(a).dnsProofRunning = true
	owner := &routerNodeAutomaticMTU{command: command, waiting: true}
	routerNodeAutomaticMTUs.Store(a, owner)
	t.Cleanup(func() { routerNodeAutomaticMTUs.Delete(a) })
	ran := make(chan struct{}, 1)
	run := func(mtuRetestSnapshot) mtuAutomaticResult {
		ran <- struct{}{}
		return mtuAutomaticResult{accepted: true}
	}
	// Hold release reaches the real scheduling guard while the old worker is
	// still in its final defer. That guard must retain a resume request.
	a.startRouterNodeAutomaticMTUWithRun(run)
	owner.mu.Lock()
	resume := owner.resume
	owner.mu.Unlock()
	if !resume {
		t.Fatal("hold release was lost while the old worker was still waiting")
	}
	owner.finish(a, command, run)
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("old worker completion did not resume Auto for the same owned path")
	}
	mtuWaitCondition(t, func() bool { owner.mu.Lock(); defer owner.mu.Unlock(); return !owner.waiting })
}

func TestRouterNodeAutomaticMTUHoldBeforeViewAcceptanceDoesNotConsumeAttempt(t *testing.T) {
	a, _ := newMTUTransactionFixture(t)
	a.cmd = &exec.Cmd{Path: "owned-pre-acceptance-runtime"}
	sessionTrackerFor(a).dnsProofRunning = true
	t.Cleanup(func() {
		routerNodeAutomaticMTUs.Delete(a)
		mtuSuspensions.Delete(a)
		mtuViewSlots.Delete(a)
	})
	var calls atomic.Int32
	resumed := make(chan struct{}, 1)
	failed := make(chan error, 1)
	a.startRouterNodeAutomaticMTUWithRun(func(snapshot mtuRetestSnapshot) mtuAutomaticResult {
		if calls.Add(1) > 1 {
			resumed <- struct{}{}
			return mtuAutomaticResult{accepted: true}
		}
		// The scheduler has reserved its attempt, but Retest has not published
		// a cancellable view. This is the formerly lost cancellation window.
		release, err := a.holdCapturedMTU(context.Background())
		if err != nil {
			failed <- err
			return mtuAutomaticResult{}
		}
		result := a.runRouterNodeAutomaticMTU(snapshot)
		release() // Release also attempts to start Auto before this worker exits.
		if result.accepted || !result.retry {
			failed <- fmt.Errorf("held request consumed its attempt: %+v", result)
		}
		return result
	})
	select {
	case err := <-failed:
		t.Fatal(err)
	case <-resumed:
	case <-time.After(3 * time.Second):
		t.Fatal("pre-acceptance hold permanently consumed the connection's Auto attempt")
	}
	value, _ := routerNodeAutomaticMTUs.Load(a)
	owner := value.(*routerNodeAutomaticMTU)
	mtuWaitCondition(t, func() bool { owner.mu.Lock(); defer owner.mu.Unlock(); return !owner.waiting })
	if calls.Load() != 2 {
		t.Fatal("hold generated duplicate accepted Auto attempts", calls.Load())
	}
}

func TestMTUTransitionHoldWaitsForRollbackAndNestedSpeedLabStop(t *testing.T) {
	a, snapshot := newMTUTransactionFixture(t)
	t.Cleanup(func() { mtuViewSlots.Delete(a); mtuSuspensions.Delete(a); routerNodeAutomaticMTUs.Delete(a) })
	identity := mtuViewIdentity{Session: snapshot.SessionID, Profile: snapshot.Profile.ID}
	ctx, operation, err := beginMTUViewOperation(a, context.Background(), mtuViewRequest{Request: strings.Repeat("a", 32)}, identity)
	if err != nil {
		t.Fatal(err)
	}
	lock := mtuRetestLockFor(a)
	lock.Lock()
	rollback := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		<-ctx.Done()
		<-rollback
		writer := &mtuViewResponse{ResponseWriter: httptest.NewRecorder(), operation: operation}
		recordMTUViewRollback(writer, mtuLiveSnapshot{OriginalMTU: 1420}, nil)
		http.Error(writer, "canceled after rollback", http.StatusConflict)
		writer.finish()
		lock.Unlock()
		close(drained)
	}()
	type held struct {
		release func()
		err     error
	}
	result := make(chan held, 1)
	go func() {
		release, err := a.holdDesktopMTUForMeasurement(context.Background())
		result <- held{release, err}
	}()
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("transition did not cancel its captured operation")
	}
	select {
	case <-result:
		t.Fatal("Speed Lab captured a provisional MTU before rollback drained")
	default:
	}
	close(rollback)
	<-drained
	var outer held
	select {
	case outer = <-result:
		if outer.err != nil {
			t.Fatal(outer.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("verified rollback did not release its operation")
	}
	defer outer.release()
	nested, err := a.holdCapturedMTU(context.Background())
	if err != nil {
		t.Fatal("Speed Lab's nested stop deadlocked its existing MTU hold", err)
	}
	nested()
	nested() // Repeated teardown cannot release another owner's hold.
	if lock.TryLock() {
		lock.Unlock()
		t.Fatal("nested stop released the surrounding Speed Lab hold")
	}
	response := httptest.NewRecorder()
	a.retestMTU(response, httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(`{}`)))
	if response.Code != http.StatusConflict {
		t.Fatal("new Retest entered a held connection", response.Code)
	}
	outer.release()
	if !lock.TryLock() {
		t.Fatal("final hold did not release MTU ownership")
	}
	lock.Unlock()
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if !operation.status.Restored || operation.status.Running || operation.status.EffectiveMTU != 1420 {
		t.Fatal("hold did not retain the exact rollback receipt", operation.status)
	}
}

func TestMTUHoldCancellationCannotUnlockAnotherOwner(t *testing.T) {
	a := &app{}
	t.Cleanup(func() { mtuSuspensions.Delete(a); mtuRetestLocks.Delete(a) })
	lock := mtuRetestLockFor(a)
	lock.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.holdCapturedMTU(ctx); done <- err }()
	mtuWaitCondition(t, func() bool { return mtuSuspended(a) })
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatal("canceled hold did not return its real cancellation", err)
	}
	if lock.TryLock() {
		lock.Unlock()
		t.Fatal("canceled waiter unlocked an unrelated MTU operation")
	}
	lock.Unlock()
	if mtuSuspended(a) {
		t.Fatal("canceled hold left a permanent suspension")
	}
}
