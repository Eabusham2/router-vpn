package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestSessionTrackerRetirementCancelsDNSCaptureBeforeAppLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, snapshot, id := dnsPathFixture(t)
		var queries atomic.Int32
		a.mu.Lock()
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(a.mu.Unlock) }
		defer release()
		work := startSessionDNSFixture(t, tracker, snapshot, id, func(context.Context, *app, observedConnection, string) dnsProofState {
			queries.Add(1)
			return dnsProofState{Status: "passed"}
		})
		defer func() { work.cancel(); release(); <-work.done }()
		synctest.Wait()
		retired := cancelSessionTracker(a)
		if retired != tracker {
			t.Fatal("retirement captured another tracker")
		}
		synctest.Wait()
		select {
		case <-work.done:
		default:
			t.Fatal("retired observer did not cancel original DNS admission behind the app lock")
		}
		joinSessionTracker(a, retired)
		if queries.Load() != 0 || tracker.snapshot(0).DNSProof.Status == "passed" {
			t.Fatal("retired DNS capture queried or published a result")
		}
	})
}

func TestSessionTrackerRetirementJoinsOriginalWorkersAndPreservesReplacement(t *testing.T) {
	a := &app{}
	original := &sessionTracker{a: a}
	sessionTrackers.Store(a, original)
	defer sessionTrackers.Delete(a)
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	defer finish()
	if !original.startWorker(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
	}) {
		t.Fatal("original worker was not admitted")
	}
	<-started
	joinSessionTracker(a, original)
	if actual, ok := sessionTrackers.Load(a); !ok || actual != original {
		t.Fatal("joining a live tracker removed an owner that still admits workers")
	}
	retired := cancelSessionTracker(a)
	<-cancelled
	if original.startWorker(func(context.Context) { t.Error("late worker ran after retirement") }) {
		t.Fatal("retiring tracker admitted a later worker")
	}
	replacement := &sessionTracker{a: a, session: &connectionSession{ID: "replacement", DNSProof: dnsProofState{Status: "passed"}}}
	sessionTrackers.Store(a, replacement)
	defer func() { joinSessionTracker(a, cancelSessionTracker(a)) }()
	done := make(chan struct{})
	go func() { joinSessionTracker(a, retired); close(done) }()
	select {
	case <-done:
		t.Fatal("retirement acknowledged before the original worker joined")
	default:
	}
	finish()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("original worker was not joined")
	}
	if actual, ok := sessionTrackers.Load(a); !ok || actual != replacement || replacement.observationContext().Err() != nil || replacement.snapshot(0).DNSProof.Status != "passed" {
		t.Fatal("original cleanup cancelled, removed or modified the replacement tracker")
	}
}

func TestSessionTrackerLoopRetiresWhileAppIsLocked(t *testing.T) {
	a := &app{}
	defer sessionTrackers.Delete(a)
	a.mu.Lock()
	defer a.mu.Unlock()
	tracker := initSessionTracker(a)
	retired := cancelSessionTracker(a)
	if tracker != retired {
		t.Fatal("loop retirement changed the registered tracker")
	}
	done := make(chan struct{})
	go func() { joinSessionTracker(a, retired); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retired observation loop waited for the app lock")
	}
	if initSessionTracker(a) != tracker || tracker.startWorker(func(context.Context) { t.Error("late loop was admitted") }) {
		t.Fatal("reading a joined tracker created another observation loop")
	}
}

func TestControllerShutdownJoinsOriginalSessionWorkers(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	tracker := &sessionTracker{a: a}
	sessionTrackers.Store(a, tracker)
	defer sessionTrackers.Delete(a)
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	defer finish()
	if !tracker.startWorker(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
	}) {
		t.Fatal("original observation worker was not admitted")
	}
	<-started
	c := newControllerShutdown(a, testControllerOwner)
	c.begin()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("controller shutdown did not cancel its original observer")
	}
	select {
	case <-c.done:
		t.Fatal("controller shutdown acknowledged an unjoined observer")
	default:
	}
	finish()
	waitControllerShutdown(t, c.done)
	if sessionTrackerFor(a) != tracker || tracker.observationContext().Err() == nil || tracker.snapshot(0).Connected {
		t.Fatal("terminal status reopened observation or retained a connected session")
	}
}

func TestControllerShutdownBeforeFirstStatusRetiresObserverAdmission(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	defer sessionTrackers.Delete(a)
	c := newControllerShutdown(a, testControllerOwner)
	c.begin()
	waitControllerShutdown(t, c.done)
	tracker := sessionTrackerFor(a)
	if c.tracker == nil || c.tracker != tracker || tracker.observationContext().Err() == nil {
		// Also join a late loop in the intentionally broken old-admission control.
		joinSessionTracker(a, cancelSessionTracker(a))
		t.Fatal("first status after shutdown created an unjoined observation loop")
	}
	if tracker.startWorker(func(context.Context) { t.Error("worker ran after terminal shutdown") }) {
		t.Fatal("first status after shutdown reopened observer admission")
	}
}

func TestRetiredSessionSnapshotOnlyPublishesOriginalTerminalState(t *testing.T) {
	for _, change := range []string{"off", "connected", "replacement", "live-observer"} {
		t.Run(change, func(t *testing.T) {
			a := &app{state: state{Mode: "off", Phase: "off"}}
			tracker := &sessionTracker{a: a, declaredAt: time.Now(), session: &connectionSession{
				ID: "original", RequestedMode: "smart-auto", RequestedBase: "awg", Phase: "requested", Connected: true,
				ActualMode: "shadowsocks", ActualBase: "native", ExitIP: "198.51.100.2", PathProof: "passed", DNSProof: dnsProofState{Status: "passed"},
			}}
			sessionTrackers.Store(a, tracker)
			defer sessionTrackers.Delete(a)
			marker := &struct{}{}
			homeExitProofs.Store(a, marker)
			defer homeExitProofs.Delete(a)
			if change != "live-observer" {
				tracker.cancelObservation()
			}
			if err := tracker.stopDNSProofs(context.Background()); err != nil {
				t.Fatal(err)
			}
			joinSessionTracker(a, tracker)
			captured := tracker.capture()
			if change == "connected" {
				captured.Connected = true
				captured.Phase = "connected"
			}
			var replacement *sessionTracker
			if change == "replacement" {
				copied := tracker.snapshot(0)
				replacement = &sessionTracker{a: a, session: &copied}
				sessionTrackers.Store(a, replacement)
			}
			tracker.publishRetiredObservation(captured)
			actual := tracker.snapshot(0)
			if change == "off" {
				if actual.Connected || actual.Phase != "off" || actual.PathProof != "not-run" || actual.DNSProof.Status != "not-proven" || actual.ExitIP != "" || actual.EndedAt == nil || actual.ActualMode != "" || actual.ActualBase != "" || len(actual.Events) != 1 {
					t.Fatalf("retired terminal snapshot kept stale connected state or request grace: %+v", actual)
				}
				if actual.ID != "original" || actual.RequestedMode != "smart-auto" || actual.RequestedBase != "awg" {
					t.Fatal("terminal snapshot changed original request identity")
				}
			} else if !actual.Connected || actual.Phase != "requested" || actual.DNSProof.Status != "passed" || len(actual.Events) != 0 {
				t.Fatal("unowned or nonterminal capture changed the retired snapshot")
			}
			if replacement != nil && (!replacement.snapshot(0).Connected || replacement.dnsProofClosed || replacement.observationContext().Err() != nil) {
				t.Fatal("old publication changed replacement tracker")
			}
			if proof, found := homeExitProofs.Load(a); !found || proof != marker {
				t.Fatal("terminal snapshot changed app-keyed proof ownership")
			}
		})
	}
}
