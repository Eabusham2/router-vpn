package main

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"time"

	"router-vpn/internal/hopmeasure"
)

// Only operating-system launch/stop and notification registration are seams.
// The source cohort, Speed Lab transaction, native mailbox, restoration capture,
// selection commit and history writers below are the shipping composition.
type desktopExternalComparisonRuntime struct {
	prepare func(speedLabRequest) (*speedLabExternalPreparation, error)
	start   func(speedLabRequest) (speedLabPath, error)
	stop    func(bool) error
	restart func(speedLabRestorePlan) error
	network func(context.Context, *app, speedLabPathIdentity) (desktopExternalComparisonNetwork, error)
}

func (a *app) desktopComparisonRuntime() desktopExternalComparisonRuntime {
	return desktopExternalComparisonRuntime{prepare: func(q speedLabRequest) (*speedLabExternalPreparation, error) {
		return a.prepareSpeedLabExternalPath(q, nil)
	},
		start: a.startSpeedLabExternalPath, stop: a.speedLabStopRuntime, restart: a.speedLabRestartPlan, network: openDesktopExternalComparisonNetwork}
}

type desktopComparisonCheckpoint struct {
	command *exec.Cmd
	state   state
	context context.Context
	path    speedLabPathIdentity
}

type desktopComparisonTransaction struct {
	a          *app
	operation  *desktopExternalComparisonOperation
	cohort     *desktopExternalComparisonCohort
	store      *desktopComparisonStoreOwner
	network    desktopExternalComparisonNetwork
	runtime    desktopExternalComparisonRuntime
	original   speedLabTemporarySnapshot
	baseline   speedLabPathIdentity
	checkpoint desktopComparisonCheckpoint
	currentID  string
	committed  bool
	winner     *speedLabRestorePlan
	history    *desktopComparisonHistoryReceipt
}

func (a *app) runDesktopExternalComparison(ctx context.Context, operation *desktopExternalComparisonOperation) {
	defer close(operation.done)
	defer operation.cancel()
	err := a.runDesktopExternalComparisonWith(ctx, operation, a.desktopComparisonRuntime())
	operation.finish(ctx, err)
}

func (operation *desktopExternalComparisonOperation) finish(ctx context.Context, err error) {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	operation.view.Complete = true
	operation.view.CurrentID, operation.view.Progress = "", ""
	if err != nil {
		if operation.view.Committed {
			operation.view.Stage = "connected-with-warning"
			operation.view.Warning += " The winner selection was committed; later verification or cleanup needs attention."
		} else {
			operation.view.Stage, operation.view.Failure = "failed", "External comparison did not complete; no winner was adopted."
			if ctx.Err() != nil {
				operation.view.Stage, operation.view.Failure = "cancelled", "Cancellation was requested; check the captured cleanup and restoration state below."
			}
			operation.view.WinnerID = ""
		}
		// An event reported while joining the final native observer invalidates
		// the comparison metrics too. A committed selection remains truthful,
		// but its old scores cannot become current after that cohort ended.
		for i := range operation.view.Rows {
			operation.view.Rows[i].Benchmark = nil
			if operation.view.Rows[i].Status == "complete" {
				operation.view.Rows[i].Status, operation.view.Rows[i].Failure = "invalid", "The complete comparison cohort was invalidated; no score is retained"
			}
		}
	} else if operation.view.Committed {
		operation.view.Stage = "connected"
	} else {
		operation.view.Stage = "complete"
	}
}

func (a *app) runDesktopExternalComparisonWith(ctx context.Context, operation *desktopExternalComparisonOperation, runtime desktopExternalComparisonRuntime) (failure error) {
	if ctx == nil || ctx.Err() != nil || operation == nil || runtime.prepare == nil || runtime.start == nil || runtime.stop == nil || runtime.restart == nil || runtime.network == nil {
		return errors.New("external comparison has no complete owned runtime")
	}
	finishRun, err := beginSpeedLabRun(a)
	if err != nil {
		return err
	}
	defer finishRun()
	releaseMTU, err := a.holdDesktopMTUForMeasurement(ctx)
	if err != nil {
		return err
	}
	defer releaseMTU()
	_, original, finishTemporary, err := a.beginSpeedLabTemporaryOperation()
	if err != nil {
		return err
	}
	defer finishTemporary()
	finishPersistence, err := beginSpeedLabTemporaryPersistenceGuard(a)
	if err != nil {
		return err
	}
	defer finishPersistence()
	cohort, err := captureDesktopExternalComparisonCohort(a, operation.request.Cohort)
	if err != nil {
		return err
	}
	defer cohort.close()
	if !reflect.DeepEqual(cohort.profiles, original.Profiles) {
		return errors.New("external comparison source changed while acquiring its transaction")
	}
	store, err := captureDesktopComparisonStore(a, original.Profiles)
	if err != nil {
		return err
	}
	defer clear(store.raw)
	transaction := &desktopComparisonTransaction{a: a, operation: operation, cohort: cohort, store: store, runtime: runtime, original: original, currentID: original.Profiles.SelectedID,
		checkpoint: desktopComparisonCheckpoint{command: original.Runtime, state: original.State, context: original.Owner.current}}
	if original.State.Connected {
		transaction.baseline, _, err = captureSpeedLabIdentity(a)
		if err != nil || transaction.baseline.Command != original.Runtime {
			return errors.Join(err, errors.New("external comparison original connection changed"))
		}
		transaction.checkpoint.path = transaction.baseline
	}
	transaction.network, err = runtime.network(ctx, a, transaction.baseline)
	if err != nil {
		if transaction.network != nil {
			err = errors.Join(err, operation.retainNetworkCleanup(transaction.network))
		}
		return err
	}
	a.mu.Lock()
	original.Owner.cohortNetwork = transaction.network
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		original.Owner.cohortNetwork = nil
		a.mu.Unlock()
		failure = errors.Join(failure, operation.retainNetworkCleanup(transaction.network))
		if transaction.history != nil {
			if failure != nil {
				failure = errors.Join(failure, transaction.history.rollback())
			}
			transaction.history.clear()
		}
		if transaction.winner != nil {
			clearSpeedLabRestorePlan(*transaction.winner)
		}
		if transaction.original.Plan.native != original.Plan.native || transaction.original.Plan.external != original.Plan.external || transaction.original.Plan.linux != original.Plan.linux || transaction.original.Plan.tor != original.Plan.tor {
			clearSpeedLabRestorePlan(transaction.original.Plan)
		}
	}()
	// Batch cancellation cancels the current test child. Disconnect owns the
	// parent intent, so its cancellation also forbids the original reconnect.
	stopDisconnect := context.AfterFunc(original.Owner.intent, operation.cancel)
	defer stopDisconnect()
	cancelJoined := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		a.mu.Lock()
		cancel := original.Owner.cancelTest
		owned := a.speedLabOwnerCurrentLocked(original.Owner)
		a.mu.Unlock()
		if owned {
			cancel()
		}
		close(cancelJoined)
	})
	defer func() {
		if !stopCancellation() {
			<-cancelJoined
		}
	}()
	defer func() {
		if !transaction.committed {
			failure = errors.Join(failure, transaction.restore())
		}
	}()
	operation.mu.Lock()
	operation.view.Restored, operation.view.Drained = true, true
	for _, candidate := range cohort.candidates {
		operation.view.Rows = append(operation.view.Rows, desktopExternalComparisonRow{ID: candidate.ID, Name: candidate.Name, Protocol: candidate.Protocol,
			EntryID: candidate.EntryID, EntryName: candidate.EntryName, EntryMode: candidate.EntryMode, SourceToken: candidate.SourceToken, Status: "queued"})
	}
	operation.mu.Unlock()
	winnerIndex := -1
	best := 0.0
	for index, candidate := range cohort.candidates {
		if err := transaction.current(ctx, transaction.currentID); err != nil {
			return err
		}
		if candidate.Failure != "" {
			transaction.failedCandidate(index, candidate.Failure)
			continue
		}
		if err := a.guardDesktopExternalComparisonPath(candidate.request, transaction.original); err != nil {
			transaction.failedCandidate(index, "The current retained protection cannot transfer to this saved external path")
			continue
		}
		trial, err := transaction.beginTrial(ctx)
		if err != nil {
			return err
		}
		operation.stage("preparing", candidate.ID)
		prepared, err := runtime.prepare(candidate.request)
		if err == nil && (prepared == nil || prepared.native == nil && prepared.tor == nil) {
			err = errors.New("saved external path has no owned native latency runtime")
		}
		if err == nil {
			err = transaction.current(trial, transaction.currentID)
		}
		if err != nil {
			if prepared != nil {
				prepared.releaseUnused()
			}
			transaction.failedCandidate(index, "The saved path could not complete native preflight; the original connection was retained")
			if err := transaction.current(ctx, transaction.currentID); err != nil {
				return err
			}
			continue
		}
		before := transaction.checkpoint.path
		if err := transaction.network.BeforeTransition(trial, before); err != nil {
			prepared.releaseUnused()
			return err
		}
		operation.stage("proving", candidate.ID)
		operation.mu.Lock()
		operation.view.Restored, operation.view.Drained = false, false
		operation.mu.Unlock()
		if err = a.speedLabSuspendPreviousWith(transaction.original, false, runtime.stop); err == nil {
			q := candidate.request
			q.preparedExternal = prepared
			_, err = runtime.start(q)
		}
		prepared.releaseUnused()
		transaction.currentID = candidate.ID
		var path speedLabPathIdentity
		if err == nil {
			path, _, err = captureSpeedLabIdentity(a)
			if err == nil && path.RouterID != candidate.ID {
				err = errors.New("external trial proved another node")
			}
		}
		transitionErr := transaction.network.AfterTransition(trial, path)
		if err == nil {
			err = transitionErr
		}
		var result hopmeasure.Status
		var plan speedLabRestorePlan
		var measuredIdentity desktopDNSRuntimeIdentity
		if err == nil {
			operation.stage("measuring", candidate.ID)
			result, err = a.measureDesktopComparisonLatency(trial, original.Owner, path, func() error { return transaction.current(trial, candidate.ID) }, operation.measuring)
		}
		if err == nil {
			// The winning restoration capture is made before this exact process
			// is stopped, after all 50 native workers and sockets have drained.
			var captured speedLabTemporarySnapshot
			captured, err = a.speedLabSnapshotTemporary()
			plan = captured.Plan
			if err == nil && (captured.Runtime != path.Command || plan.external == nil && plan.tor == nil || plan.request.Execution != path.Execution) {
				err = errors.New("external trial restoration capture differs from its measured execution")
			}
			if err == nil {
				err = validateSpeedLabIdentity(a, path)
			}
			if err == nil {
				launch := path.External
				if path.Tor != nil {
					launch = path.Tor
				}
				measuredIdentity, err = capturedDesktopLatencyRuntime(launch)
			}
		}
		restoreErr := transaction.restore()
		if restoreErr != nil {
			clearSpeedLabRestorePlan(plan)
			return errors.Join(err, restoreErr)
		}
		if err := transaction.current(ctx, transaction.currentID); err != nil {
			clearSpeedLabRestorePlan(plan)
			return err
		}
		if err != nil {
			clearSpeedLabRestorePlan(plan)
			transaction.failedCandidate(index, "The saved path did not produce a complete, current 50-response measurement; no score")
			continue
		}
		benchmark := result.Results[0].Benchmark
		if !validDesktopComparisonBenchmark(benchmark) {
			clearSpeedLabRestorePlan(plan)
			return errors.New("native external result has no valid common metric")
		}
		operation.mu.Lock()
		row := &operation.view.Rows[index]
		row.Status, row.Benchmark, row.MeasuredAt = "complete", cloneDesktopComparisonBenchmark(benchmark), time.Now().UnixMilli()
		row.SourceSHA256, row.ConfigSHA256, row.NetworkSHA256 = measuredIdentity.source, measuredIdentity.config, transaction.network.Identity()
		row.Execution = path.Execution
		operation.mu.Unlock()
		if winnerIndex < 0 || benchmark.TrimmedMean < best || benchmark.TrimmedMean == best && candidate.ID < cohort.candidates[winnerIndex].ID {
			if transaction.winner != nil {
				clearSpeedLabRestorePlan(*transaction.winner)
			}
			transaction.winner, winnerIndex, best = &plan, index, benchmark.TrimmedMean
		} else {
			clearSpeedLabRestorePlan(plan)
		}
	}
	if winnerIndex < 0 {
		return errors.New("no external candidate produced all 50 required responses")
	}
	if err := transaction.current(ctx, transaction.currentID); err != nil {
		return err
	}
	operation.mu.Lock()
	operation.view.WinnerID = cohort.candidates[winnerIndex].ID
	operation.mu.Unlock()
	if operation.request.ConnectFastest {
		if err := transaction.adopt(ctx, cohort.candidates[winnerIndex]); err != nil {
			return err
		}
	}
	rows := operation.snapshot().Rows
	transaction.history, err = saveDesktopExternalComparisonHistory(a, rows, func() error { return transaction.current(ctx, transaction.currentID) })
	if err != nil {
		operation.warn("The comparison completed, but its separate external-path history could not be saved; previous statistics were preserved.")
	}
	return transaction.current(ctx, transaction.currentID)
}

// Both retained protection architectures must admit an ordinary external
// successor before preparation or Stop. The existing Windows slot and Linux
// session have separate authority; neither may be bypassed by a batch wrapper.
func (a *app) guardDesktopExternalComparisonPath(request speedLabRequest, original speedLabTemporarySnapshot) error {
	if err := a.guardDesktopOwnedNodeTransition(nil); err != nil {
		return err
	}
	return a.guardDesktopOwnedNodeTemporary(request, original)
}

// Tor Compare owns separate native processes for Local and Server. Capture
// every actually proved transient before its workspace is closed, so the
// enclosing batch can authenticate those route effects as well as its winner.
func (a *app) recordDesktopComparisonTransient(ctx context.Context, launch *desktopNodeLaunch) error {
	raw, exists := speedLabTemporaryOwners.Load(a)
	if !exists {
		return nil
	}
	owner, ok := raw.(*speedLabTemporaryOwner)
	a.mu.Lock()
	if !ok || !a.speedLabOwnerCurrentLocked(owner) || a.cmd != owner.runtime || launch == nil || a.cmd != launch.command {
		a.mu.Unlock()
		return errors.New("Tor transient lost its exact external comparison owner")
	}
	network := owner.cohortNetwork
	a.mu.Unlock()
	if network == nil {
		return nil
	}
	return network.RecordTransient(ctx, launch)
}

func (t *desktopComparisonTransaction) failedCandidate(index int, message string) {
	t.operation.mu.Lock()
	row := &t.operation.view.Rows[index]
	row.Status, row.Failure, row.Benchmark = "invalid", message, nil
	t.operation.mu.Unlock()
}

func (t *desktopComparisonTransaction) current(ctx context.Context, selected string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.a.speedLabCheckOwner(t.original.Owner); err != nil {
		return err
	}
	if err := t.cohort.current(t.a, selected); err != nil {
		return err
	}
	if err := t.store.current(); err != nil {
		return err
	}
	return t.network.Current()
}

func (t *desktopComparisonTransaction) beginTrial(ctx context.Context) (context.Context, error) {
	if err := t.current(ctx, t.original.Profiles.SelectedID); err != nil {
		return nil, err
	}
	if t.checkpoint.path.Command != nil {
		if err := validateSpeedLabIdentity(t.a, t.checkpoint.path); err != nil {
			return nil, err
		}
	}
	a, owner := t.a, t.original.Owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.speedLabOwnerCurrentLocked(owner) || a.cmd != t.checkpoint.command || a.state != t.checkpoint.state || owner.current != t.checkpoint.context || !reflect.DeepEqual(a.profiles, t.original.Profiles) || owner.intent.Err() != nil || ctx.Err() != nil {
		return nil, errors.New("external comparison cannot refresh a replaced original connection")
	}
	owner.cancelTest()
	// The existing Tor Local/Server selection owns up to eight minutes;
	// preserve that startup contract before the separate 100-second native50
	// operation. Concrete native startups retain their own tighter deadlines.
	trial, cancel := context.WithTimeout(owner.intent, 10*time.Minute)
	owner.test, owner.cancelTest, owner.current = trial, cancel, trial
	owner.mutated, owner.restored = false, false
	a.connectionContext = trial
	t.checkpoint.context = trial
	return trial, nil
}

func desktopComparisonSamePath(before, after speedLabPathIdentity) bool {
	if before.Command == nil {
		return after.Command == nil
	}
	if after.Command == nil || before.Command == after.Command || before.SessionID == after.SessionID || before.RouterID != after.RouterID || before.ProfileToken != after.ProfileToken ||
		before.EntryToken != after.EntryToken || before.Options != after.Options || before.Execution != after.Execution || before.Network != after.Network ||
		(before.External != nil) != (after.External != nil) || (before.Tor != nil) != (after.Tor != nil) || (before.Node != nil) != (after.Node != nil) || (before.Linux != nil) != (after.Linux != nil) || before.GraphOK != after.GraphOK {
		return false
	}
	if before.GraphOK {
		left, right := before.Graph, after.Graph
		left.Started, right.Started = time.Time{}, time.Time{}
		if left != right {
			return false
		}
	}
	return before.NodeSource == after.NodeSource && (before.External == nil || before.ExternalSession != after.ExternalSession) && (before.Tor == nil || before.TorSession != after.TorSession)
}

func (t *desktopComparisonTransaction) restore() error {
	a, owner := t.a, t.original.Owner
	if err := a.speedLabCheckOwner(owner); err != nil {
		return err
	}
	a.mu.Lock()
	mutated, restored := owner.mutated, owner.restored
	a.mu.Unlock()
	if !mutated || restored {
		return nil
	}
	t.operation.stage("restoring", t.original.State.RouterID)
	a.mu.Lock()
	expected := cloneRouterProfileStore(t.original.Profiles)
	expected.SelectedID = a.profiles.SelectedID
	memoryCurrent := (a.profiles.SelectedID == t.currentID || a.profiles.SelectedID == t.original.Profiles.SelectedID) && reflect.DeepEqual(a.profiles, expected)
	a.mu.Unlock()
	if !memoryCurrent {
		stopErr := t.runtime.stop(true)
		return a.speedLabRestoreFailed(owner, "newer private node decisions were preserved; captured temporary path was retired", errors.Join(errors.New("saved node state changed"), stopErr))
	}
	if err := t.store.current(); err != nil {
		// A foreign private store is user state, not a failed test result to
		// overwrite. Retire only this temporary runtime and retain protection.
		stopErr := t.runtime.stop(true)
		return a.speedLabRestoreFailed(owner, "original private selection changed; captured temporary path was retired", errors.Join(err, stopErr))
	}
	var before speedLabPathIdentity
	if path, _, err := captureSpeedLabIdentity(a); err == nil && path.Command == owner.runtime {
		before = path
	}
	// A retired comparison witness cannot authorize scores, but it must not
	// prevent the original Speed Lab owner from draining/restoring its path.
	_ = t.network.BeforeTransition(owner.intent, before)
	var next desktopComparisonCheckpoint
	var nextPlan speedLabRestorePlan
	actions := speedLabRestoreActions{stop: t.runtime.stop, restart: t.runtime.restart, persist: t.store.write, network: physicalNetworkIdentity,
		restored: func(command *exec.Cmd, st state) error {
			if err := a.speedLabCheckOwner(owner); err != nil {
				return err
			}
			next = desktopComparisonCheckpoint{command: command, state: st, context: owner.current}
			if command != nil {
				path, _, err := captureSpeedLabIdentity(a)
				if err != nil || path.Command != command || !desktopComparisonSamePath(t.baseline, path) {
					return errors.Join(err, errors.New("restoration did not retain the original proved path and execution"))
				}
				captured, err := a.speedLabSnapshotTemporary()
				nextPlan = captured.Plan
				if err != nil || captured.Runtime != command || captured.State != st || !reflect.DeepEqual(captured.Profiles, t.original.Profiles) {
					return errors.Join(err, errors.New("restoration capture changed at its terminal boundary"))
				}
				if err := validateSpeedLabIdentity(a, path); err != nil {
					return err
				}
				next.path = path
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if !a.speedLabOwnerCurrentLocked(owner) || a.cmd != command || a.state != st || owner.current != next.context {
				return errors.New("restored owner was replaced before continuation capture")
			}
			return nil
		}}
	err := a.speedLabRestoreWith(t.original, actions)
	transitionErr := t.network.AfterTransition(owner.intent, next.path)
	if err != nil {
		clearSpeedLabRestorePlan(nextPlan)
		return err
	}
	if next.context == nil {
		clearSpeedLabRestorePlan(nextPlan)
		return errors.New("restoration did not return its own terminal checkpoint")
	}
	clearSpeedLabRestorePlan(t.original.Plan)
	t.original.Plan, t.original.Runtime, t.checkpoint, t.currentID = nextPlan, next.command, next, t.original.Profiles.SelectedID
	t.operation.mu.Lock()
	t.operation.view.Restored = next.state.Connected == t.original.State.Connected
	t.operation.view.Drained = true
	t.operation.mu.Unlock()
	return transitionErr
}

func (t *desktopComparisonTransaction) adopt(ctx context.Context, candidate desktopExternalComparisonCandidate) error {
	if t.winner == nil || t.winner.request.Execution != "local" && t.winner.request.Execution != "server" {
		return errors.New("external winner has no retained proved execution")
	}
	trial, err := t.beginTrial(ctx)
	if err != nil {
		return err
	}
	if err := t.network.BeforeTransition(trial, t.checkpoint.path); err != nil {
		return err
	}
	t.operation.stage("reproving-winner", candidate.ID)
	t.operation.mu.Lock()
	t.operation.view.Restored, t.operation.view.Drained = false, false
	t.operation.mu.Unlock()
	if err := t.a.speedLabSuspendPreviousWith(t.original, false, t.runtime.stop); err != nil {
		return err
	}
	if err := t.runtime.restart(*t.winner); err != nil {
		_ = t.network.AfterTransition(trial, speedLabPathIdentity{})
		return err
	}
	t.currentID = candidate.ID
	path, _, err := captureSpeedLabIdentity(t.a)
	if err == nil && (path.RouterID != candidate.ID || path.Execution != t.winner.request.Execution || path.External == nil && path.Tor == nil) {
		err = errors.New("fresh winner proof changed its captured source or execution")
	}
	if transitionErr := t.network.AfterTransition(trial, path); err == nil {
		err = transitionErr
	}
	if err != nil {
		return err
	}
	if err := t.current(ctx, candidate.ID); err != nil {
		return err
	}
	if err := verifySpeedLabPath(trial, t.a, path); err != nil {
		return err
	}
	if err := validateSpeedLabIdentity(t.a, path); err != nil {
		return err
	}
	if err := t.current(ctx, candidate.ID); err != nil {
		return err
	}
	// Save one whole final selection with exactly one usage credit per distinct
	// node in the adopted path. Temporary candidates/restorations never count.
	a, owner := t.a, t.original.Owner
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock() // existing tracker -> app order; retain the exact proof ID through rename
	a.mu.Lock()
	if tracker.session == nil || tracker.session.ID != path.SessionID || !tracker.session.Connected || tracker.session.PathProof != "passed" ||
		!a.speedLabOwnerCurrentLocked(owner) || a.cmd != path.Command || a.cmd != owner.runtime || mtuStateSnapshotToken(a.state) != path.StateToken || a.profiles.SelectedID != candidate.ID || owner.current != trial || trial.Err() != nil || ctx.Err() != nil {
		a.mu.Unlock()
		tracker.mu.Unlock()
		return errors.New("winner changed after fresh proof and before selection save")
	}
	updated := cloneRouterProfileStore(t.original.Profiles)
	updated.SelectedID = candidate.ID
	usedAt := time.Now().UTC().Format(time.RFC3339)
	for i := range updated.Profiles {
		p := &updated.Profiles[i]
		if p.ID == candidate.ID || candidate.EntryID != "" && p.ID == candidate.EntryID {
			p.UseCount = min(max(0, p.UseCount), int(^uint(0)>>1)-1) + 1
			p.LastUsedAt = usedAt
		}
	}
	check := func() error {
		if ctx.Err() != nil || trial.Err() != nil || !a.speedLabOwnerCurrentLocked(owner) || a.cmd != path.Command || a.cmd != owner.runtime || mtuStateSnapshotToken(a.state) != path.StateToken || owner.current != trial {
			return errors.New("winner owner changed before durable adoption")
		}
		if err := t.cohort.currentLocked(a, candidate.ID); err != nil {
			return err
		}
		if err := t.cohort.sourcesCurrent(); err != nil {
			return err
		}
		return t.network.Current()
	}
	if err = t.store.writeChecked(updated, check); err != nil && !desktopComparisonStoreCommitted(err) {
		a.mu.Unlock()
		tracker.mu.Unlock()
		return err
	}
	// A successful atomic rename is the commit boundary, including a later
	// uncertain readback. Never restore the old choice over this committed one.
	a.profiles = updated
	base, runtimeMode := a.state.Base, a.state.RuntimeMode
	launch := path.External
	if path.Tor != nil {
		launch = path.Tor
	}
	captureDesktopMTUBaselineLocked(a, launch)
	t.committed = true
	owner.restored = true
	t.operation.mu.Lock()
	t.operation.view.Committed, t.operation.view.Restored, t.operation.view.Drained = true, false, true
	t.operation.mu.Unlock()
	a.mu.Unlock()
	tracker.mu.Unlock()
	if err != nil {
		return err
	}
	if err := t.current(ctx, candidate.ID); err != nil {
		return err
	}
	// Startup Last is a separate non-authoritative memory write. A failure is
	// visible while the freshly proved, durably selected tunnel stays active.
	selection := startupSelection{RouterID: candidate.ID, RuntimeMode: runtimeMode, LogicalMode: "external-node", Base: base,
		ProfileToken: startupExternalProfileToken(candidate.profile), UpdatedAt: time.Now().UTC(), External: &startupExternalSelection{Protocol: candidate.Protocol,
			Direct: candidate.EntryID == "", EntryID: candidate.EntryID, EntryMode: candidate.EntryMode, SourceToken: candidate.entrySource, Execution: path.Execution}}
	if candidate.EntryID != "" {
		selection.External.EntryToken = startupExternalProfileToken(candidate.entry)
	}
	if saveErr := a.saveStartupSelection(selection); saveErr != nil {
		t.operation.warn("The proved winner is connected and selected, but startup Last could not be updated.")
	}
	return nil
}
