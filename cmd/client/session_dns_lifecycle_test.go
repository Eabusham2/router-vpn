package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func startSessionDNSFixture(t *testing.T, tracker *sessionTracker, observed observedConnection, id string, probe selectedDNSProbe) *sessionDNSProofWork {
	t.Helper()
	tracker.mu.Lock()
	tracker.dnsProofRunning = false
	tracker.startDNSProofLocked(id, observed, observed.RuntimeMode, probe)
	work := tracker.dnsProofWork
	tracker.mu.Unlock()
	if work == nil {
		t.Fatal("original DNS worker was not retained")
	}
	return work
}

func TestSessionDNSWorkerStopCancelsOriginalAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		a.mu.Lock()
		var released sync.Once
		unlock := func() { released.Do(a.mu.Unlock) }
		defer unlock()
		called := false
		work := startSessionDNSFixture(t, tracker, observed, id, func(context.Context, *app, observedConnection, string) dnsProofState {
			called = true
			return dnsProofState{Status: "passed"}
		})
		// The actual asynchronous setup reaches the held app lock. The stop
		// must join it while that lock is still held, without a resolver call.
		synctest.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := tracker.stopDNSProofs(ctx); err != nil {
			work.cancel()
			unlock()
			<-work.done
			t.Fatal("DNS retirement failed to cancel original setup behind held app owner", err)
		}
		select {
		case <-work.done:
		default:
			t.Fatal("DNS retirement returned before original setup joined")
		}
		if called || tracker.snapshot(0).DNSProof.Status == "passed" {
			t.Fatal("cancelled DNS setup reached a resolver or published proof")
		}
	})
}

func TestSessionDNSWorkerStopRetainsEnteredProbeUntilJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		work := startSessionDNSFixture(t, tracker, observed, id, func(ctx context.Context, a *app, s observedConnection, mode string) dnsProofState {
			deadline, bounded := ctx.Deadline()
			if !bounded || deadline.After(time.Now().Add(sessionDNSProofBudget)) {
				t.Error("DNS worker lost its original whole-operation budget")
			}
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-release
			return successfulDNSProof(ctx, a, s, mode)
		})
		defer func() {
			work.cancel()
			select {
			case <-release:
			default:
				close(release)
			}
			<-work.done
		}()
		<-entered
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := tracker.stopDNSProofs(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("DNS retirement released an entered probe without its join", err)
		}
		<-cancelled
		tracker.mu.Lock()
		retained := tracker.dnsProofWork == work && tracker.dnsProofClosed
		tracker.mu.Unlock()
		if !retained {
			t.Fatal("expired DNS cleanup lost the exact original worker")
		}
		tracker.observe(observed)
		tracker.mu.Lock()
		if tracker.dnsProofWork != work {
			t.Error("terminal tracker admitted a replacement DNS worker")
		}
		tracker.mu.Unlock()
		close(release)
		if err := tracker.stopDNSProofs(context.Background()); err != nil {
			t.Fatal("retained DNS cleanup could not join on retry", err)
		}
		if tracker.snapshot(0).DNSProof.Status == "passed" {
			t.Fatal("late resolver success was published after terminal cancellation")
		}
		a.mu.Lock()
		connected := a.state.Connected
		a.mu.Unlock()
		if !connected {
			t.Fatal("DNS observer retirement stopped the VPN")
		}
	})
}

func TestSessionDNSWorkerRevokesStaleAdmission(t *testing.T) {
	for _, change := range []string{"disconnect", "phase", "runtime", "router", "base", "profile", "session", "same-capture"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, tracker, observed, id := dnsPathFixture(t)
				a.mu.Lock()
				defer a.mu.Unlock()
				called := false
				work := startSessionDNSFixture(t, tracker, observed, id, func(context.Context, *app, observedConnection, string) dnsProofState {
					called = true
					return dnsProofState{Status: "passed"}
				})
				defer func() { work.cancel(); <-work.done }()
				synctest.Wait()
				next := observed
				switch change {
				case "disconnect":
					next.Connected = false
				case "phase":
					next.Phase = "checking"
				case "runtime":
					next.RuntimeMode = "hysteria2"
				case "router":
					next.RouterID = "replacement-node"
				case "base":
					next.Base = "awg"
				case "profile":
					next.Profile.DNSHost = "8.8.8.8"
				case "session":
					tracker.mu.Lock()
					tracker.session.ID = "replacement-session"
					tracker.mu.Unlock()
				case "same-capture":
					next.Phase = " connected "
				}
				// Exercise the actual observation path while the original worker
				// remains unable to install its detailed app/path observer.
				tracker.observe(next)
				synctest.Wait()
				select {
				case <-work.done:
					if change == "same-capture" {
						t.Fatal("unchanged captured DNS owner was retired")
					}
				default:
					if change != "same-capture" {
						t.Fatal("stale DNS setup was not revoked before path admission")
					}
				}
				if called {
					t.Fatal("blocked DNS setup reached an ordinary resolver")
				}
			})
		})
	}
}

func TestSessionDNSWorkerStopCannotRetireReplacementTracker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		a.mu.Lock()
		startSessionDNSFixture(t, tracker, observed, id, successfulDNSProof)
		synctest.Wait()
		replacementSession := tracker.snapshot(0)
		replacement := &sessionTracker{a: a, session: &replacementSession}
		sessionTrackers.Store(a, replacement)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := tracker.stopDNSProofs(ctx)
		cancel()
		a.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		current, present := sessionTrackers.Load(a)
		if !present || current != replacement || replacement.dnsProofClosed || replacement.dnsProofWork != nil {
			t.Fatal("old DNS retirement changed the same-ID replacement tracker")
		}
	})
}

func TestSessionDNSWorkerControllerDrainJoinsBeforeExit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		entered := make(chan struct{})
		work := startSessionDNSFixture(t, tracker, observed, id, func(ctx context.Context, a *app, s observedConnection, mode string) dnsProofState {
			close(entered)
			<-ctx.Done()
			return successfulDNSProof(ctx, a, s, mode)
		})
		<-entered
		a.mu.Lock()
		a.closing = true
		a.state = state{Mode: "off", Phase: "off"}
		a.mu.Unlock()
		if err := a.drainControllerOwner(); err != nil {
			t.Fatal("controller could not retire its actual registered DNS worker", err)
		}
		select {
		case <-work.done:
		default:
			t.Fatal("controller exit preceded original DNS worker join")
		}
		if !tracker.dnsProofClosed || tracker.snapshot(0).DNSProof.Status == "passed" {
			t.Fatal("controller drain preserved live DNS admission or stale proof")
		}
	})
}
