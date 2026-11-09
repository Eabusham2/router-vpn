package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
)

// The actual registered DNS worker reaches its normal terminal adoption and
// reserves operationMu before waiting for the existing protection guard. The
// public Stop must cancel that original worker before waiting for its lock.
func TestPublicStopCancelsSelectedDNSBeforeOperationWait(t *testing.T) {
	for _, route := range []string{"disconnect", "emergency"} {
		t.Run(route, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, tracker, observed, id := dnsPathFixture(t)
				a.modes = []common.Mode{{ID: "multihop"}}
				slot := &desktopNodeProtectionSlot{}
				a.nodeProtection = slot
				slot.mu.Lock()
				var unlockOnce sync.Once
				unlock := func() { unlockOnce.Do(slot.mu.Unlock) }
				defer unlock()
				entered := make(chan context.Context, 1)
				work := startSessionDNSFixture(t, tracker, observed, id, func(ctx context.Context, a *app, s observedConnection, mode string) dnsProofState {
					entered <- ctx
					return successfulDNSProof(ctx, a, s, mode)
				})
				defer func() { work.cancel(); unlock(); <-work.done }()
				original := <-entered
				synctest.Wait()
				if a.operationMu.TryLock() {
					a.operationMu.Unlock()
					t.Fatal("actual DNS adoption did not reserve the operation before its held guard")
				}
				if original.Err() != nil {
					t.Fatal("DNS worker was already cancelled before public Stop")
				}
				cancelBoundary := make(chan bool, 1)
				connection, cancelConnection := context.WithCancel(context.Background())
				defer cancelConnection()
				a.mu.Lock()
				a.connectionContext = connection
				a.connectionCancel = func() {
					// This nonjoining callback witnesses the existing public
					// cancellation boundary while DNS owns operationMu. It does
					// not rely on sync.Mutex being durably blocked in synctest.
					cancelBoundary <- original.Err() != nil
					cancelConnection()
				}
				a.mu.Unlock()
				response, joined := httptest.NewRecorder(), make(chan struct{})
				request := httptest.NewRequest(http.MethodPost, "/api/"+route, nil)
				go func() {
					defer close(joined)
					if route == "emergency" {
						a.emergencyStopTracked(response, request)
					} else {
						a.disconnect(response, request)
					}
				}()
				cancelledBeforeUnlock := <-cancelBoundary
				// Always retire the causal fixture, including on the original
				// implementation, without advancing its 30-second DNS budget.
				work.cancel()
				unlock()
				<-joined
				<-work.done
				if !cancelledBeforeUnlock {
					t.Fatal("public Stop waited for operationMu without cancelling its original selected-DNS worker")
				}
			})
		})
	}
}

func publicStopRequest(a *app, ctx context.Context, route string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/"+route, nil).WithContext(ctx)
	if route == "emergency" {
		a.emergencyStopTracked(w, r)
	} else {
		a.disconnect(w, r)
	}
	return w
}

// Only the existing platform protection process is modeled. Public HTTP
// admission, exact DNS lifetime, ordinary teardown and receipt completion run.
func publicStopProtectionFixture(t *testing.T, a *app) {
	t.Helper()
	a.cfg.ScriptsDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(a.cfg.ScriptsDir, "kill-switch-platform.py"), []byte("import sys\nassert sys.argv[1:] == ['release']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(os.Getenv("HOMEVPN_ROOT"), "client")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "windows-kill-switch.ps1"), []byte("param($Action,$Root)\nif($Action -cne 'release'){exit 1}\nexit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPublicStopCancelledBeforeCaptureIsReadOnly(t *testing.T) {
	for _, route := range []string{"disconnect", "emergency"} {
		t.Run(route, func(t *testing.T) {
			a, tracker, _, _ := dnsPathFixture(t)
			before, session := a.state, tracker.snapshot(0)
			var cancelled atomic.Int32
			a.connectionContext = context.Background()
			a.connectionCancel = func() { cancelled.Add(1) }
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			w := publicStopRequest(a, ctx, route)
			if w.Code != http.StatusConflict || cancelled.Load() != 0 || a.state != before || tracker.dnsProofStop != nil || tracker.dnsProofEpoch.Load() != 0 || !reflect.DeepEqual(tracker.snapshot(0), session) {
				t.Fatal("cancelled public Stop invented cleanup or changed its original owner", w.Code, w.Body.String())
			}
			idle := &app{}
			_ = publicStopRequest(idle, ctx, route)
			if _, registered := sessionTrackers.Load(idle); registered {
				t.Fatal("cancelled first Stop installed an observer")
			}
		})
	}
}

func TestPublicStopCaptureWaitRetainsCallerAndRegistry(t *testing.T) {
	for _, boundary := range []string{"tracker", "app", "registry"} {
		t.Run(boundary, func(t *testing.T) {
			a, tracker, _, _ := dnsPathFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			caller := &measurementAdmissionWaitingContext{Context: ctx, waiting: make(chan struct{})}
			mutex := &tracker.mu
			if boundary == "app" {
				mutex = &a.mu
			}
			release := measurementHeldLock(mutex)
			defer release()
			done := make(chan error, 1)
			go func() { _, err := a.capturePublicStopContext(caller, "emergency-stop"); done <- err }()
			<-caller.waiting
			var replacement *sessionTracker
			if boundary == "registry" {
				replacement = &sessionTracker{a: a}
				sessionTrackers.Store(a, replacement)
				release()
			} else {
				cancel()
			}
			err := <-done
			release()
			if err == nil || boundary != "registry" && !errors.Is(err, context.Canceled) || tracker.dnsProofStop != nil || tracker.dnsProofEpoch.Load() != 0 || replacement != nil && replacement.dnsProofStop != nil {
				t.Fatal("public capture escaped its original caller or registry", boundary, err)
			}
		})
	}
}

func TestPublicStopExpiryRetainsExactRetryableFence(t *testing.T) {
	for _, route := range []string{"disconnect", "emergency"} {
		t.Run(route, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, tracker, observed, id := dnsPathFixture(t)
				publicStopProtectionFixture(t, a)
				a.modes = []common.Mode{{ID: "multihop"}}
				entered := make(chan struct{})
				work := startSessionDNSFixture(t, tracker, observed, id, func(ctx context.Context, a *app, s observedConnection, mode string) dnsProofState {
					close(entered)
					<-ctx.Done()
					return successfulDNSProof(ctx, a, s, mode)
				})
				<-entered
				a.operationMu.Lock()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				w := publicStopRequest(a, ctx, route)
				cancel()
				a.operationMu.Unlock()
				<-work.done
				receipt := tracker.dnsProofStop
				if w.Code != http.StatusConflict || receipt == nil || receipt.work != work || !receipt.publicReserved || !validStopRetryToken(receipt.token) || !a.state.Connected || tracker.dnsProofClosed {
					t.Fatal("expired operation wait lost its original cleanup fence", w.Code, w.Body.String())
				}
				// A transition which was already admitted may clean its runtime,
				// but cannot clear the still-pending public intent.
				if err := ordinaryDNSStop(t, a); err != nil || tracker.dnsProofStop != receipt || tracker.dnsProofEpoch.Load() != receipt.epoch {
					t.Fatal("internal cleanup consumed the public reservation", err)
				}
				ordinaryDNSAssertPending(t, a, tracker, receipt)
				retried := stopRetryRequest(a, context.Background(), http.MethodPost, stopRetryBody(receipt.token))
				if retried.Code != http.StatusOK || tracker.dnsProofStop != nil {
					t.Fatal("owned retry could not complete the exact public fence", retried.Code, retried.Body.String())
				}
				fresh, freshID := ordinaryDNSReconnect(t, a, tracker)
				next := startSessionDNSFixture(t, tracker, fresh, freshID, successfulDNSProof)
				<-next.done
				if next == work || tracker.snapshot(0).DNSProof.Status != "passed" {
					t.Fatal("owned public retry disabled DNS on the reusable tracker")
				}
			})
		})
	}
}

func TestPublicStopJoinsDNSOutsideOwnerLocksAndOriginalCaller(t *testing.T) {
	for _, expires := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "caller-expired"}[expires], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, tracker, observed, id := dnsPathFixture(t)
				publicStopProtectionFixture(t, a)
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
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- publicStopRequest(a, ctx, "disconnect") }()
				<-cancelled
				synctest.Wait()
				for name, mutex := range map[string]*sync.Mutex{"tracker": &tracker.mu, "app": &a.mu} {
					if !mutex.TryLock() {
						t.Fatal("public Stop joined DNS while holding", name)
					}
					mutex.Unlock()
				}
				select {
				case <-done:
					t.Fatal("public Stop detached entered DNS cleanup")
				default:
				}
				if !a.state.Connected {
					t.Fatal("runtime retired before captured DNS joined")
				}
				if expires {
					cancel()
					w := <-done
					if w.Code < 400 || tracker.dnsProofStop == nil || !a.state.Connected {
						t.Fatal("public cleanup replaced its expired caller", w.Code, w.Body.String())
					}
					releaseCleanup()
					<-work.done
					w = stopRetryRequest(a, context.Background(), http.MethodPost, stopRetryBody(tracker.dnsProofStop.token))
					if w.Code != http.StatusOK {
						t.Fatal(w.Code, w.Body.String())
					}
				} else {
					releaseCleanup()
					if w := <-done; w.Code != http.StatusOK {
						t.Fatal(w.Code, w.Body.String())
					}
				}
				if tracker.dnsProofStop != nil || tracker.dnsProofClosed || a.state.Connected {
					t.Fatal("joined public Stop lost reusable completion")
				}
			})
		})
	}
}

// Pause only once the public receipt is published and its tracker lock has
// been released, at the actual contextual operation-admission boundary.
type publicStopAdmissionPause struct {
	context.Context
	tracker         *sessionTracker
	entered, resume chan struct{}
	once            sync.Once
}

func (ctx *publicStopAdmissionPause) Err() error {
	if ctx.tracker.mu.TryLock() {
		reserved := ctx.tracker.dnsProofStop != nil
		ctx.tracker.mu.Unlock()
		if reserved {
			ctx.once.Do(func() { close(ctx.entered); <-ctx.resume })
		}
	}
	return ctx.Context.Err()
}

func TestDelayedPublicStopCannotCancelAfterOwnedRetryAndReconnect(t *testing.T) {
	for _, route := range []string{"disconnect", "emergency"} {
		t.Run(route, func(t *testing.T) {
			a, tracker, _, _ := dnsPathFixture(t)
			publicStopProtectionFixture(t, a)
			a.modes = []common.Mode{{ID: "multihop"}}
			caller := &publicStopAdmissionPause{Context: context.Background(), tracker: tracker, entered: make(chan struct{}), resume: make(chan struct{})}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- publicStopRequest(a, caller, route) }()
			<-caller.entered
			tracker.mu.Lock()
			receipt := tracker.dnsProofStop
			tracker.mu.Unlock()
			w := stopRetryRequest(a, context.Background(), http.MethodPost, stopRetryBody(receipt.token))
			if w.Code != http.StatusOK {
				close(caller.resume)
				<-done
				t.Fatal(w.Code, w.Body.String())
			}
			ordinaryDNSReconnect(t, a, tracker)
			var cancelled atomic.Int32
			a.mu.Lock()
			a.connectionContext = context.Background()
			a.connectionCancel = func() { cancelled.Add(1) }
			before := a.state
			a.mu.Unlock()
			close(caller.resume)
			w = <-done
			if w.Code != http.StatusConflict || cancelled.Load() != 0 || a.state != before || tracker.dnsProofStop != nil {
				t.Fatal("delayed public Stop affected the replacement after its exact receipt completed", w.Code, w.Body.String())
			}
		})
	}
}

func TestPublicStopRepeatedCaptureAndReplacementAdmission(t *testing.T) {
	for _, change := range []string{"completed", "epoch", "registry", "work"} {
		t.Run(change, func(t *testing.T) {
			a, tracker, _, _ := dnsPathFixture(t)
			publicStopProtectionFixture(t, a)
			a.modes = []common.Mode{{ID: "multihop"}}
			receipt, err := a.capturePublicStopContext(context.Background(), "")
			if err != nil {
				t.Fatal(err)
			}
			again, err := a.capturePublicStopContext(context.Background(), "")
			if err != nil || again != receipt || again.token != receipt.token {
				t.Fatal("repeated public Stop rebound its receipt", err)
			}
			switch change {
			case "completed":
				w := publicStopRequest(a, context.Background(), "disconnect")
				if w.Code != http.StatusOK {
					t.Fatal(w.Code, w.Body.String())
				}
			case "epoch":
				tracker.dnsProofEpoch.Add(1)
			case "registry":
				replacement := &sessionTracker{a: a}
				replacement.dnsProofEpoch.Store(receipt.epoch)
				replacement.dnsProofStop = &sessionDNSStopReceipt{tracker: replacement, epoch: receipt.epoch, token: receipt.token}
				sessionTrackers.Store(a, replacement)
			case "work":
				tracker.dnsProofWork = &sessionDNSProofWork{done: make(chan struct{}), cancel: func() { t.Error("stale Stop cancelled replacement work") }}
			}
			release, err := a.beginCapturedPublicStopContext(context.Background(), receipt)
			if release != nil {
				release()
			}
			if err == nil || release != nil {
				t.Fatal("old public receipt admitted replacement cleanup", change)
			}
			if !a.operationMu.TryLock() {
				t.Fatal("rejected stale Stop retained operation ownership")
			}
			a.operationMu.Unlock()
		})
	}
}

func TestPublicStopFencesActualConnectionContextPublication(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	a.state = state{Mode: "off", Phase: "off"}
	slot := &desktopDNSSlot{}
	a.dnsMeasurements = slot
	slot.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	caller := &measurementAdmissionWaitingContext{Context: ctx, waiting: make(chan struct{})}
	type result struct {
		ctx    context.Context
		finish func()
		err    error
	}
	done := make(chan result, 1)
	go func() {
		ctx, finish, err := a.beginConnectionTransactionContext(caller)
		done <- result{ctx, finish, err}
	}()
	<-caller.waiting // the actual selected-DNS invalidation after preflight
	receipt, err := a.capturePublicStopContext(context.Background(), "")
	if err != nil {
		slot.mu.Unlock()
		got := <-done
		if got.finish != nil {
			got.finish()
		}
		t.Fatal(err)
	}
	slot.mu.Unlock()
	got := <-done
	if got.finish != nil {
		got.finish()
	}
	if !errors.Is(got.err, errSessionDNSStopPending) || got.ctx != nil || got.finish != nil || a.connectionContext != nil || a.state.Phase != "off" || tracker.dnsProofStop != receipt {
		t.Fatal("Connect published a context after public Stop had already captured cancellation", got.err)
	}
}

func TestPublicStopCancelsAlreadyPublishedConnectionContext(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	a.state = state{Mode: "off", Phase: "off"}
	ctx, finish, err := a.beginConnectionTransactionContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := a.capturePublicStopContext(context.Background(), "")
	if err != nil || ctx.Err() == nil || a.connectionCancelIntent != ctx || tracker.dnsProofStop != receipt {
		finish()
		t.Fatal("public Stop missed the originally published connection", err)
	}
	finish()
}

func TestPublicStopReservationKeepsTerminalShutdownClosed(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	publicStopProtectionFixture(t, a)
	a.modes = []common.Mode{{ID: "multihop"}}
	if _, err := a.capturePublicStopContext(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	a.closing = true
	if err := a.drainControllerOwner(); err != nil {
		t.Fatal(err)
	}
	if tracker.dnsProofStop != nil || !tracker.dnsProofClosed || a.state.Connected {
		t.Fatal("terminal shutdown reopened or retained a public reservation")
	}
}

func TestOwnedPublicStopRetryRetainsCallerWhileJoiningDNS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, tracker, observed, id := dnsPathFixture(t)
		publicStopProtectionFixture(t, a)
		a.modes = []common.Mode{{ID: "multihop"}}
		entered, cleanup := make(chan struct{}), make(chan struct{})
		var once sync.Once
		releaseCleanup := func() { once.Do(func() { close(cleanup) }) }
		work := startSessionDNSFixture(t, tracker, observed, id, func(ctx context.Context, a *app, s observedConnection, mode string) dnsProofState {
			close(entered)
			<-ctx.Done()
			<-cleanup
			return successfulDNSProof(ctx, a, s, mode)
		})
		defer func() { work.cancel(); releaseCleanup(); <-work.done }()
		<-entered
		receipt, err := a.capturePublicStopContext(context.Background(), "")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		w := stopRetryRequest(a, ctx, http.MethodPost, stopRetryBody(receipt.token))
		cancel()
		if w.Code < 400 || tracker.dnsProofStop != receipt || !a.state.Connected {
			t.Fatal("owned Retry replaced its expired caller or detached DNS cleanup", w.Code, w.Body.String())
		}
		select {
		case <-work.done:
			t.Fatal("fixture did not retain original cleanup")
		default:
		}
		releaseCleanup()
		<-work.done
		w = stopRetryRequest(a, context.Background(), http.MethodPost, stopRetryBody(receipt.token))
		if w.Code != http.StatusOK || tracker.dnsProofStop != nil {
			t.Fatal("same owned Retry could not finish joined cleanup", w.Code, w.Body.String())
		}
	})
}

func TestPublicStopFenceRejectsActualCandidateOwnerPublication(t *testing.T) {
	for _, phase := range []string{"failed", "off"} {
		t.Run(phase, func(t *testing.T) {
			a, entry, candidates := viaEntryFixture(t)
			tracker := &sessionTracker{a: a}
			sessionTrackers.Store(a, tracker)
			t.Cleanup(func() { sessionTrackers.Delete(a) })
			receipt, err := a.capturePublicStopContext(context.Background(), "")
			if err != nil {
				t.Fatal(err)
			}
			a.state.Phase = phase
			lane := &viaEntryTestLane{entry: entry}
			var observations atomic.Int32
			w := runViaEntryTest(a, lane, strings.Repeat("a", 32), candidates[:1], func(context.Context) (string, error) { observations.Add(1); return "captured-network", nil })
			control := viaEntryControlFor(a)
			if w.Code != http.StatusConflict || control.owner != nil || len(control.seen) != 0 || observations.Load() != 0 || lane.proofs != 0 || tracker.dnsProofStop != receipt {
				t.Fatal("pending public Stop admitted a new candidate owner", w.Code, w.Body.String())
			}
		})
	}
}

func TestPublicStopCancelsAlreadyAdmittedCandidateOwner(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(map[bool]string{false: "first-tracker", true: "registered-tracker"}[registered], func(t *testing.T) {
			a, entry, candidates := viaEntryFixture(t)
			publicStopProtectionFixture(t, a)
			a.state.Mode = "off"
			if registered {
				sessionTrackers.Store(a, &sessionTracker{a: a})
			}
			t.Cleanup(func() { tracker := cancelSessionTracker(a); joinSessionTracker(a, tracker); sessionTrackers.Delete(a) })
			lane := &viaEntryTestLane{entry: entry, entered: make(chan struct{}), block: make(chan struct{})}
			requestDone := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				requestDone <- runViaEntryTest(a, lane, strings.Repeat("b", 32), candidates[:1], func(ctx context.Context) (string, error) { return "captured-network", ctx.Err() })
			}()
			<-lane.entered
			control := viaEntryControlFor(a)
			control.mu.Lock()
			owner := control.owner
			control.mu.Unlock()
			w := publicStopRequest(a, context.Background(), "disconnect")
			measured := <-requestDone
			control.mu.Lock()
			current, cancelled, drained, receipt := control.owner, owner.cancelled, owner.drained, owner.receipt
			control.mu.Unlock()
			if w.Code != http.StatusOK || measured.Code == http.StatusOK || current != owner || !cancelled || !drained || receipt != nil {
				t.Fatal("public Stop missed or replaced the already admitted candidate", w.Code, measured.Code)
			}
			select {
			case <-owner.done:
			default:
				t.Fatal("public Stop returned before original candidate joined")
			}
		})
	}
}

func TestPublicStopRetainsExistingCapturedCancellations(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	connection, cancelConnection := context.WithCancel(context.Background())
	startup, cancelStartup := context.WithCancel(context.Background())
	recovery, cancelRecovery := context.WithCancel(context.Background())
	candidate, cancelCandidate := context.WithCancel(context.Background())
	defer cancelConnection()
	defer cancelStartup()
	defer cancelRecovery()
	defer cancelCandidate()
	a.connectionContext, a.connectionCancel = connection, cancelConnection
	a.nodeRecovery = &desktopNodeRecoveryOperation{context: recovery, cancel: cancelRecovery}
	startupPolicyCancels.Store(a, context.CancelFunc(cancelStartup))
	t.Cleanup(func() { startupPolicyCancels.Delete(a); viaEntryControls.Delete(a) })
	control := viaEntryControlFor(a)
	owner := &viaEntryOwner{cancel: cancelCandidate, receipt: &viaEntryReceipt{}}
	control.owner = owner
	receipt, err := a.capturePublicStopContext(context.Background(), "")
	if err != nil || tracker.dnsProofStop != receipt || connection.Err() == nil || startup.Err() == nil || recovery.Err() == nil || candidate.Err() == nil || a.connectionCancelIntent != connection || control.owner != owner || !owner.cancelled || owner.receipt != nil {
		t.Fatal("public Stop lost an existing original cancellation owner", err)
	}
}

func TestPublicStopCandidateWaitRetainsOriginalCaller(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	control := viaEntryControlFor(a)
	t.Cleanup(func() { viaEntryControls.Delete(a) })
	control.mu.Lock()
	defer control.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	caller := &measurementAdmissionWaitingContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := a.capturePublicStopContext(caller, ""); done <- err }()
	<-caller.waiting
	// The public cancellation path must release app before entering candidate
	// control, whose ordinary owner may itself need app. No join runs here.
	if !a.mu.TryLock() {
		cancel()
		<-done
		t.Fatal("public Stop held app while waiting for candidate control")
	}
	a.mu.Unlock()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || tracker.dnsProofStop == nil || !tracker.dnsProofStop.publicReserved {
		t.Fatal("candidate cancellation replaced the public caller or lost pending cleanup", err)
	}
}

func TestOwnedPublicStopRetryCandidateWaitKeepsOriginalReceipt(t *testing.T) {
	a, tracker, receipt := stopRetryFixture(t)
	control := viaEntryControlFor(a)
	t.Cleanup(func() { viaEntryControls.Delete(a) })
	control.mu.Lock()
	defer control.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	caller := &measurementAdmissionWaitingContext{Context: ctx, waiting: make(chan struct{})}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- stopRetryRequest(a, caller, http.MethodPost, stopRetryBody(receipt.token)) }()
	<-caller.waiting
	cancel()
	w := <-done
	if w.Code != http.StatusConflict || tracker.dnsProofStop != receipt || !receipt.publicReserved || !a.state.Connected {
		t.Fatal("owned Retry waited past its caller or lost the exact original receipt", w.Code, w.Body.String())
	}
	for name, mutex := range map[string]*sync.Mutex{"tracker": &tracker.mu, "app": &a.mu, "operation": &a.operationMu} {
		if !mutex.TryLock() {
			t.Fatal("cancelled owned Retry retained", name)
		}
		mutex.Unlock()
	}
}

func TestCapturedPublicStopCancellationCannotRecaptureReplacement(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "finished", true: "replacement-tracker"}[replacement], func(t *testing.T) {
			a, tracker, receipt := stopRetryFixture(t)
			if err := receipt.finish(context.Background()); err != nil {
				t.Fatal(err)
			}
			current := tracker
			if replacement {
				current = &sessionTracker{a: a}
				current.dnsProofEpoch.Store(receipt.epoch)
				sessionTrackers.Store(a, current)
			}
			var cancelled atomic.Int32
			a.connectionContext = context.Background()
			a.connectionCancel = func() { cancelled.Add(1) }
			before := current.dnsProofEpoch.Load()
			if err := a.cancelCapturedStopContext(context.Background(), receipt); err == nil || cancelled.Load() != 0 || current.dnsProofStop != nil || current.dnsProofEpoch.Load() != before {
				t.Fatal("stale cancellation rebound to a replacement Stop or connection", err)
			}
		})
	}
}

type publicStopCandidateCleanupLane struct {
	viaEntryTestLane
	entered chan context.Context
	release chan struct{}
}

func (lane *publicStopCandidateCleanupLane) Close(ctx context.Context) error {
	lane.entered <- ctx
	<-lane.release
	return ctx.Err()
}

func TestOwnedPublicStopRetryJoinsCapturedCandidateWithOriginalCaller(t *testing.T) {
	a, tracker, receipt := stopRetryFixture(t)
	control := viaEntryControlFor(a)
	t.Cleanup(func() { viaEntryControls.Delete(a) })
	lane := &publicStopCandidateCleanupLane{entered: make(chan context.Context, 1), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(lane.release) }) }
	defer release()
	candidate, cancelCandidate := context.WithCancel(context.Background())
	defer cancelCandidate()
	owner := &viaEntryOwner{lane: lane, cancel: cancelCandidate, done: make(chan struct{})}
	close(owner.done)
	control.owner = owner
	type callerKey struct{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), callerKey{}, a), time.Second)
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- stopRetryRequest(a, ctx, http.MethodPost, stopRetryBody(receipt.token)) }()
	actual := <-lane.entered
	cancel()
	if actual.Value(callerKey{}) != a || !errors.Is(actual.Err(), context.Canceled) || candidate.Err() == nil {
		release()
		<-done
		t.Fatal("owned candidate cleanup replaced its original Retry caller")
	}
	select {
	case <-done:
		t.Fatal("owned Retry detached entered candidate cleanup")
	default:
	}
	for name, mutex := range map[string]*sync.Mutex{"tracker": &tracker.mu, "app": &a.mu, "candidate": &control.mu} {
		if !mutex.TryLock() {
			release()
			<-done
			t.Fatal("candidate join held", name)
		}
		mutex.Unlock()
	}
	release()
	w := <-done
	if w.Code != http.StatusServiceUnavailable || tracker.dnsProofStop != receipt || control.owner != owner || !a.state.Connected {
		t.Fatal("cancelled candidate cleanup lost retained Stop ownership", w.Code, w.Body.String())
	}
}
