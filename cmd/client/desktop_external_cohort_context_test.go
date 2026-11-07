package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

type desktopComparisonCallerKey struct{}

func desktopComparisonContextFixture(t *testing.T) (*desktopComparisonTransaction, context.Context) {
	t.Helper()
	f := newDesktopComparisonFixture(t, false)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), desktopComparisonCallerKey{}, "captured-comparison"), 3*time.Second)
	t.Cleanup(cancel)
	intent, cancelIntent := context.WithCancel(context.Background())
	test, cancelTest := context.WithCancel(intent)
	t.Cleanup(cancelIntent)
	owner := &speedLabTemporaryOwner{intent: intent, cancelIntent: cancelIntent, test: test, current: test, cancelTest: cancelTest}
	f.a.connectionContext = test
	speedLabTemporaryOwners.Store(f.a, owner)
	cohort, err := captureDesktopExternalComparisonCohortContext(ctx, f.a, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cohort.close)
	store, err := captureDesktopComparisonStore(f.a, f.a.profiles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(store.raw) })
	return &desktopComparisonTransaction{a: f.a, cohort: cohort, store: store, network: f.network,
		original:  speedLabTemporarySnapshot{Owner: owner, Profiles: cloneRouterProfileStore(f.a.profiles), State: f.a.state},
		currentID: f.a.profiles.SelectedID, checkpoint: desktopComparisonCheckpoint{state: f.a.state, context: test}}, ctx
}

func TestDesktopExternalCohortCallerHeldOwners(t *testing.T) {
	for _, boundary := range []string{"catalog-capture", "catalog-current", "transaction", "before-transition", "after-transition", "transient", "retired-external", "retired-tor", "retired-node"} {
		t.Run(boundary, func(t *testing.T) {
			transaction, parent := desktopComparisonContextFixture(t)
			a := transaction.a
			network := &desktopExternalCohortNetwork{app: a, owner: transaction.original.Owner}
			launch := &desktopNodeLaunch{}
			mutex := &a.mu
			switch boundary {
			case "before-transition", "after-transition", "transient":
				mutex = &network.mu
			case "retired-external":
				launch.external = &desktopExternalRuntime{}
				mutex = &launch.external.mu
			case "retired-tor":
				launch.tor = &desktopTorRuntime{}
				mutex = &launch.tor.mu
			case "retired-node":
				launch.ownedNode = &desktopOwnedNodeRuntime{}
				mutex = &launch.workspaceMu
			}
			release := measurementHeldLock(mutex)
			defer release()
			ctx, cancel := context.WithTimeout(parent, 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch boundary {
				case "catalog-capture":
					_, err = captureDesktopExternalComparisonCohortContext(ctx, a, transaction.cohort.ID)
				case "catalog-current":
					err = transaction.cohort.currentContext(ctx, a, transaction.currentID)
				case "transaction":
					err = transaction.current(ctx, transaction.currentID)
				case "before-transition":
					err = network.BeforeTransition(ctx, speedLabPathIdentity{})
				case "after-transition":
					err = network.AfterTransition(ctx, speedLabPathIdentity{})
				case "transient":
					err = network.RecordTransient(ctx, launch)
				default:
					err = desktopCohortLaunchJoined(ctx, launch)
				}
				done <- err
			}()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("external cohort lost original held-lock deadline", err)
			}
			release()
			if network.transition || len(network.transient) != 0 || a.profiles.SelectedID != transaction.currentID || transaction.original.Owner.intent.Err() != nil {
				t.Fatal("expired observation changed transition, source selection or original cleanup authority")
			}
		})
	}
}

func TestDesktopExternalCohortNetworkReceivesExactCaller(t *testing.T) {
	for _, stage := range []string{"transaction", "native-snapshot"} {
		t.Run(stage, func(t *testing.T) {
			transaction, parent := desktopComparisonContextFixture(t)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			entered, abort := make(chan struct{}), make(chan struct{})
			defer close(abort)
			observe := func(caller context.Context) error {
				if caller.Value(desktopComparisonCallerKey{}) != "captured-comparison" {
					return errors.New("comparison observer lost exact caller values")
				}
				if limit, ok := caller.Deadline(); !ok || limit.After(time.Now().Add(3*time.Second)) {
					return errors.New("comparison observer lost original caller deadline")
				}
				close(entered)
				select {
				case <-caller.Done():
					return caller.Err()
				case <-abort:
					return errors.New("joined counterfactual fixture cleanup")
				}
			}
			network := transaction.network.(*desktopComparisonNetworkFixture)
			network.check = observe
			done := make(chan error, 1)
			go func() {
				if stage == "transaction" {
					done <- transaction.current(ctx, transaction.currentID)
					return
				}
				snapshot := desktopLatencySnapshot{temporary: transaction.original.Owner, cohort: observe}
				done <- snapshot.currentContext(ctx, transaction.a)
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatal("comparison observer was not entered with actual caller", err)
			case <-time.After(time.Second):
				t.Fatal("comparison observer not entered")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("observer cancellation produced a current candidate", err)
				}
			case <-time.After(time.Second):
				t.Fatal("comparison observer outlived its caller")
			}
			if network.closed || transaction.original.Owner.intent.Err() != nil {
				t.Fatal("observation expiry closed original restore or network owner")
			}
		})
	}
}

func TestDesktopExternalCohortRechecksSourceAfterNetworkRead(t *testing.T) {
	for _, replacement := range []string{"credentials", "selected", "owner", "store"} {
		t.Run(replacement, func(t *testing.T) {
			transaction, ctx := desktopComparisonContextFixture(t)
			network := transaction.network.(*desktopComparisonNetworkFixture)
			network.check = func(context.Context) error {
				a := transaction.a
				switch replacement {
				case "credentials":
					a.mu.Lock()
					a.profiles.Profiles[0].External.Hysteria2.Password = "replacement-private-fixture"
					a.mu.Unlock()
				case "selected":
					a.mu.Lock()
					a.profiles.SelectedID = "a-fast"
					a.mu.Unlock()
				case "owner":
					speedLabTemporaryOwners.Store(a, &speedLabTemporaryOwner{})
				case "store":
					return atomicWritePrivate(transaction.store.path, transaction.store.raw)
				}
				return nil
			}
			if err := transaction.current(ctx, transaction.currentID); err == nil {
				t.Fatal("network read adopted replacement source or transaction owner")
			}
			if network.closed || transaction.committed || transaction.winner != nil {
				t.Fatal("replacement observation changed durable selection or original cleanup owner")
			}
		})
	}
}

func TestDesktopExternalCohortTrialKeepsCallerAndIndependentRestore(t *testing.T) {
	transaction, parent := desktopComparisonContextFixture(t)
	ctx, cancel := context.WithCancel(parent)
	trial, err := transaction.beginTrial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.original.Owner.cancelTest()
	if trial.Value(desktopComparisonCallerKey{}) != parent.Value(desktopComparisonCallerKey{}) {
		t.Fatal("candidate trial detached from actual comparison caller")
	}
	limit, ok := trial.Deadline()
	parentLimit, _ := parent.Deadline()
	if !ok || limit.After(parentLimit) {
		t.Fatal("candidate trial extended original comparison deadline")
	}
	cancel()
	select {
	case <-trial.Done():
	case <-time.After(time.Second):
		t.Fatal("candidate trial did not inherit original cancellation")
	}
	if transaction.original.Owner.intent.Err() != nil || transaction.restore() != nil {
		t.Fatal("candidate cancellation retired independent original restore authority")
	}
}

func TestDesktopExternalLatencyCallerWorkspaceAdmission(t *testing.T) {
	for _, operation := range []string{"read", "write", "native-entry"} {
		t.Run(operation, func(t *testing.T) {
			a, launch := desktopLatencyControllerFixture(t, "latency-hold")
			snapshot, err := captureDesktopLatencySnapshot(a)
			if err != nil {
				t.Fatal(err)
			}
			release := measurementHeldLock(&launch.workspaceMu)
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "read":
					_, err = readDesktopLatencyRecordContext(ctx, launch)
				case "write":
					err = writeDesktopLatencyRequestContext(ctx, launch, "latency-request.json", desktopLatencyNativeRequest{})
				default:
					_, err = a.runDesktopLatencyNative(ctx, &desktopLatencyOperation{snapshot: snapshot, request: strings.Repeat("b", 32)})
				}
				done <- err
			}()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("native mailbox admission lost original deadline", err)
			}
			release()
			if launch.external.latencyGeneration != 0 {
				t.Fatal("expired admission acquired native generation")
			}
			if _, err := os.Stat(filepath.Join(launch.directory, "latency-request.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("expired admission published a native request", err)
			}
		})
	}
}

func TestDesktopExternalLatencyCallerJoinsNativeDrain(t *testing.T) {
	for _, observer := range []string{"network", "held-app"} {
		t.Run(observer, func(t *testing.T) {
			a, launch := desktopLatencyControllerFixture(t, "latency-hold")
			snapshot, err := captureDesktopLatencySnapshot(a)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), desktopComparisonCallerKey{}, "native-caller"), 3*time.Second)
			defer cancel()
			entered, abort := make(chan struct{}), make(chan struct{})
			var once, unlock sync.Once
			defer close(abort)
			release := func() {
				if observer == "held-app" {
					unlock.Do(a.mu.Unlock)
				}
			}
			launch.external.networkIdentityContext = func(caller context.Context) (string, error) {
				if caller.Value(desktopComparisonCallerKey{}) != "native-caller" {
					return "", errors.New("native measurement lost exact caller")
				}
				if launch.external.latencyGeneration == 0 {
					return launch.external.network, caller.Err()
				}
				if observer == "held-app" {
					once.Do(func() { a.mu.Lock(); close(entered) })
					return launch.external.network, caller.Err()
				}
				once.Do(func() { close(entered) })
				select {
				case <-caller.Done():
					return "", caller.Err()
				case <-abort:
					return "", errors.New("joined counterfactual native fixture")
				}
			}
			operation := &desktopLatencyOperation{snapshot: snapshot, request: strings.Repeat("c", 32), status: hopmeasure.Status{Results: []hopmeasure.Result{}}}
			done := make(chan error, 1)
			go func() {
				result, err := a.runDesktopLatencyNative(ctx, operation)
				if len(result.Results) != 0 {
					err = errors.New("cancelled native observer exposed a score")
				}
				done <- err
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatal("native measurement observer not reached", err)
			case <-time.After(2 * time.Second):
				t.Fatal("native measurement observer not reached")
			}
			defer release()
			cancel()
			if err := measurementContextResult(t, done, release); !errors.Is(err, context.Canceled) {
				t.Fatal("native measurement lost original cancellation", err)
			}
			release()
			record, err := readDesktopLatencyDrainRecord(launch)
			if err != nil || record.Request != operation.request || record.Generation != 1 || !record.Status.Complete || !record.Status.Drained || record.Status.Stage != "cancelled" || len(record.Status.Results) != 0 || !desktopMeasurementCancelRetired(launch, "latency-cancel.json") {
				t.Fatal("observer returned before exact native generation and sockets drained", record, err)
			}
			exited := false
			select {
			case <-desktopExternalProcessDone(launch):
				exited = true
			default:
			}
			if launch.external.latencyFailed || exited || a.cmd != launch.command {
				t.Fatal("cancelled measurement retired healthy original tunnel")
			}
		})
	}
}

func TestDesktopExternalCohortAdoptionRetainsExactOwnerAcrossNativeRead(t *testing.T) {
	for _, change := range []string{"current", "cancel", "same-id-tracker", "private-store", "credentials"} {
		t.Run(change, func(t *testing.T) {
			transaction, parent := desktopComparisonContextFixture(t)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			a, owner := transaction.a, transaction.original.Owner
			tracker := sessionTrackerFor(a)
			tracker.session = &connectionSession{ID: "exact-captured-winner", Connected: true, PathProof: "passed"}
			a.cmd = exec.Command("captured-winner-fixture")
			a.state.Connected, a.state.Phase = true, "connected"
			owner.runtime, owner.current, a.connectionContext = a.cmd, ctx, ctx
			path := speedLabPathIdentity{Tracker: tracker, Command: a.cmd, SessionID: tracker.session.ID, StateToken: mtuStateSnapshotToken(a.state)}
			before := append([]byte(nil), transaction.store.raw...)
			defer clear(before)
			originalInfo := transaction.store.info
			var replacementInfo os.FileInfo
			calls := 0
			transaction.network.(*desktopComparisonNetworkFixture).check = func(caller context.Context) error {
				calls++
				if caller.Value(desktopComparisonCallerKey{}) != "captured-comparison" {
					return errors.New("adoption observer lost actual caller")
				}
				switch change {
				case "cancel":
					cancel()
				case "same-id-tracker":
					copied := *tracker.session
					sessionTrackers.Store(a, &sessionTracker{a: a, session: &copied})
				case "private-store":
					if err := atomicWritePrivate(transaction.store.path, before); err != nil {
						return err
					}
					var err error
					replacementInfo, err = desktopComparisonCaptureFileInfo(transaction.store.path)
					return err
				case "credentials":
					a.profiles.Profiles[0].External.Hysteria2.Password = "new-private-fixture-password"
				}
				return nil
			}
			updated := cloneRouterProfileStore(a.profiles)
			updated.SelectedID = "a-fast"
			tracker.mu.Lock()
			a.mu.Lock()
			err := transaction.store.writeCheckedContext(ctx, updated, func(caller context.Context) error {
				return transaction.adoptionCurrentLocked(caller, ctx, path, transaction.currentID, tracker)
			})
			a.mu.Unlock()
			tracker.mu.Unlock()
			expectedCalls := 1
			if change == "current" {
				expectedCalls = 2
			} // Original preflight and pre-rename checks both run.
			if calls != expectedCalls {
				t.Fatal("terminal adoption did not observe exact retained network", calls, err)
			}
			if change == "current" {
				if err != nil {
					t.Fatal("current original winner was rejected", err)
				}
				return
			}
			if err == nil || desktopComparisonStoreCommitted(err) {
				t.Fatal("stale/cancelled observer acquired durable winner selection", err)
			}
			raw, readErr := readPrivateRegular(transaction.store.path, maxPrivateStoreBytes)
			defer clear(raw)
			info, statErr := desktopComparisonCaptureFileInfo(transaction.store.path)
			expected := originalInfo
			if change == "private-store" {
				expected = replacementInfo
			}
			if readErr != nil || statErr != nil || expected == nil || !os.SameFile(expected, info) || !bytes.Equal(raw, before) {
				t.Fatal("rejected adoption overwrote original or replacement private decision", readErr, statErr)
			}
		})
	}
}

func TestDesktopExternalCohortDrainKeepsOriginalProcessWaiter(t *testing.T) {
	launch := &desktopNodeLaunch{command: &exec.Cmd{Process: &os.Process{Pid: 1}}, external: &desktopExternalRuntime{stopAcknowledged: true}}
	owned := make(chan struct{})
	launch.external.waitOnce.Do(func() { launch.external.waitDone = owned })
	// A different native-family channel cannot prove this external process.
	launch.nodeWaitOnce.Do(func() { launch.nodeWaitDone = make(chan struct{}); close(launch.nodeWaitDone) })
	if err := desktopCohortLaunchJoined(context.Background(), launch); err == nil {
		t.Fatal("external cohort borrowed another native family's process join")
	}
	close(owned)
	if err := desktopCohortLaunchJoined(context.Background(), launch); err != nil {
		t.Fatal("original acknowledged external process join was rejected", err)
	}
	launch.external.stopAcknowledged = false
	if err := desktopCohortLaunchJoined(context.Background(), launch); err == nil {
		t.Fatal("process exit replaced original native drain acknowledgment")
	}
}
