package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

// These tests run the shipping SMART loop, captured restoration, Stop, and
// private-file admission. Only native process/Job, kernel, and path execution
// boundaries are modeled; they do not establish native Windows networking.
type desktopNodeSmartFixture struct {
	a         *app
	profile   common.RouterProfile
	original  *desktopOwnedNodeTestFixture
	kernel    *desktopNodeProtectionFixture
	operation context.Context
	cancel    context.CancelFunc
	processes []*desktopOwnedNodeMonitorProcess
	launches  []*desktopNodeLaunch
}

func newDesktopNodeSmartFixture(t *testing.T, simplify ...string) *desktopNodeSmartFixture {
	t.Helper()
	profile, files := viaEntryBaseFixture(t, "awg2-strong")
	profile.KillSwitch, profile.KillSwitchPolicy = true, "always"
	// The live value may differ from the saved default only under Auto. These
	// native fixture entry points do not schedule an automatic measurement.
	profile.MTUPolicy, profile.ManualMTU = "auto", 0
	original, _, err := compileDesktopNode(context.Background(), profile, "awg2-strong", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithCancel(context.Background())
	kernel := &desktopNodeProtectionFixture{}
	a := &app{connectionContext: operation, connectionCancel: cancel,
		nodeProtection: &desktopNodeProtectionSlot{backend: kernel.backend()}}
	first := desktopOwnedNodeTestCapture(t, a, kernel, profile, original, "awg2-strong", "1", 0)
	a.mu.Lock()
	a.cmd = nil
	a.mu.Unlock()
	if err := a.publishDesktopOwnedNodeStart(first.launch, "starting", "awg2"); err != nil {
		t.Fatal(err)
	}
	if err := first.start(t, operation, nil); err != nil {
		t.Fatal(err)
	}
	f := &desktopNodeSmartFixture{a: a, profile: profile, original: first, kernel: kernel, operation: operation, cancel: cancel}
	f.retainProcess(first)
	a.mu.Lock()
	a.state.Connected, a.state.Phase = true, "connected"
	a.modes = []common.Mode{
		{ID: "awg2-strong", AutoEligible: true, Layers: []string{"amneziawg2", "strong-obfuscation"}, SmartSimplify: append([]string(nil), simplify...)},
		{ID: "awg2-fast", AutoEligible: true, Layers: []string{"amneziawg2", "light-obfuscation"}},
		{ID: "wg", AutoEligible: true, Layers: []string{"wireguard"}},
	}
	a.mu.Unlock()
	sessionTrackers.Store(a, &sessionTracker{a: a})
	t.Cleanup(func() {
		cancelPendingStartupPolicy(a)
		cancel()
		for i := len(f.processes) - 1; i >= 0; i-- {
			f.processes[i].closeErr = nil
			_ = f.processes[i].Close(context.Background())
		}
		for _, launch := range f.launches {
			_ = stopDesktopOwnedNodeMonitor(context.Background(), launch)
		}
		desktopNodeOwners.Delete(a)
		sessionTrackers.Delete(a)
		strategyLocks.Delete(a)
		mtuSuspensions.Delete(a)
	})
	return f
}

func (f *desktopNodeSmartFixture) retainProcess(owner *desktopOwnedNodeTestFixture) {
	process := &desktopOwnedNodeMonitorProcess{desktopOwnedNodeTestProcess: owner.process, exited: make(chan struct{})}
	owner.launch.workspaceMu.Lock()
	owner.launch.ownedNode.process = process
	owner.launch.workspaceMu.Unlock()
	f.processes = append(f.processes, process)
	f.launches = append(f.launches, owner.launch)
}

func (f *desktopNodeSmartFixture) runtime(t *testing.T) smartStrategyRuntime {
	t.Helper()
	return smartStrategyRuntime{
		first: func(a *app, profile common.RouterProfile, result *strategyResult) (common.Mode, error) {
			if a != f.a || desktopOwnedNodeProfileToken(profile) != desktopOwnedNodeProfileToken(f.profile) {
				t.Fatal("SMART first path changed its captured application or profile")
			}
			if _, err := a.readDesktopOwnedNodeReady(f.original.launch, false); err != nil {
				return common.Mode{}, err
			}
			result.Attempts = append(result.Attempts, strategyAttempt{Mode: "awg2-strong", Action: "candidate", Success: true})
			return a.mode("awg2-strong")
		},
		check: func(*app, common.Mode) (bool, string) { return true, "" },
		restore: func(*app, speedLabRestorePlan) error {
			return errors.New("fixture did not authorize a restoration execution")
		},
	}
}

func (f *desktopNodeSmartFixture) run(runtime smartStrategyRuntime) (strategyResult, error) {
	f.a.operationMu.Lock()
	defer f.a.operationMu.Unlock()
	return f.a.runSmartStrategyWith(runtime)
}

func (f *desktopNodeSmartFixture) stage(t *testing.T, launch *desktopNodeLaunch, connected bool) *desktopOwnedNodeTestFixture {
	t.Helper()
	if f.a.cmd != nil {
		t.Fatal("SMART attempted to stage over an unjoined command")
	}
	directory := filepath.Join(launch.root, "smart-"+launch.mtuSession)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	for name, body := range map[string][]byte{"sing-box.json": launch.config, "capture.json": launch.metadata} {
		if err := writeDesktopRuntimeFile(launch, name, body, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := stageDesktopOwnedNodeInputs(f.a, launch); err != nil {
		t.Fatal(err)
	}
	var err error
	launch.command, err = desktopOwnedNodeDescriptor(launch, filepath.Join(launch.root, "package"), []string{"CAPTURED_SMART_FIXTURE=1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.a.publishDesktopOwnedNodeStart(launch, "starting", "awg2"); err != nil {
		t.Fatal(err)
	}
	owner := &desktopOwnedNodeTestFixture{a: f.a, launch: launch, profile: f.profile,
		original: launch.ownedNode.policy.OriginalProfile(), kernel: f.kernel,
		process: &desktopOwnedNodeTestProcess{started: true, join: func() { f.kernel.locked = false }}}
	if err := owner.start(t, f.operation, nil); err != nil {
		t.Fatal(err)
	}
	f.retainProcess(owner)
	f.a.mu.Lock()
	f.a.state.Connected = connected
	if connected {
		f.a.state.Phase = "connected"
	}
	f.a.mu.Unlock()
	return owner
}

func (f *desktopNodeSmartFixture) trial(t *testing.T, session string) *desktopOwnedNodeTestFixture {
	t.Helper()
	_, files := viaEntryBaseFixture(t, "awg2-fast")
	original, _, err := compileDesktopNode(f.operation, f.profile, "awg2-fast", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopOwnedNodeLaunch(f.profile, original, "awg2-fast", f.original.launch.root,
		f.original.launch.endpoint, f.original.launch.ownedNode.network, strings.Repeat(session, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	return f.stage(t, launch, false)
}

func desktopNodeSmartAssertCurrent(t *testing.T, f *desktopNodeSmartFixture, originalSource []byte) {
	t.Helper()
	if f.a.cmd != f.original.launch.command || !f.a.state.Connected || f.a.state.Phase != "connected" ||
		f.a.state.RuntimeMode != "awg2-strong" || f.original.process.closed || f.original.process.closes != 0 ||
		!bytes.Equal(f.original.launch.ownedNode.source, originalSource) {
		t.Fatal("preflight failure replaced, retired, or falsely presented the proved original runtime")
	}
	if _, err := f.a.readDesktopOwnedNodeReady(f.original.launch, false); err != nil {
		t.Fatal("retained original no longer passes its real captured readiness check", err)
	}
}

func TestDesktopNodeSmartPreflightFailuresRetainExactRuntime(t *testing.T) {
	f := newDesktopNodeSmartFixture(t, "awg2-fast", "wg")
	source := append([]byte(nil), f.original.launch.ownedNode.source...)
	prepared, reads := f.kernel.prepared, f.kernel.reads
	calls, restores := 0, 0
	runtime := f.runtime(t)
	runtime.check = func(a *app, mode common.Mode) (bool, string) {
		if calls != 0 {
			desktopNodeSmartAssertCurrent(t, f, source)
		}
		return true, ""
	}
	runtime.start = func(a *app, id string, hold bool, transition *modeAttemptTransition) error {
		calls++
		if a != f.a || !hold || transition == nil || transition.StopBegun || id != []string{"awg2-fast", "wg"}[calls-1] {
			t.Fatal("SMART preflight lost its exact trial boundary")
		}
		return errors.New("captured candidate preflight rejected before Stop")
	}
	runtime.restore = func(*app, speedLabRestorePlan) error { restores++; return errors.New("unexpected restart") }
	result, err := f.run(runtime)
	if err != nil || !result.OK || result.RuntimeMode != "awg2-strong" || calls != 2 || restores != 0 || result.RestoredMode != "" {
		t.Fatal("SMART restarted the valid original after a preflight-only failure", result, err, calls, restores)
	}
	desktopNodeSmartAssertCurrent(t, f, source)
	retained := 0
	for _, attempt := range result.Attempts {
		if attempt.Action == "retain" && attempt.Success {
			retained++
		}
	}
	if retained != 2 || f.kernel.prepared != prepared || f.kernel.reads != reads || f.kernel.releases != 0 {
		t.Fatal("preflight retention performed a native transition or misreported its result")
	}
}

func TestDesktopNodeSmartRealPreflightLeavesStopBoundaryUnset(t *testing.T) {
	const candidate = "fixture-unavailable"
	f := newDesktopNodeSmartFixture(t, candidate)
	f.a.modes = append(f.a.modes, common.Mode{ID: candidate, AutoEligible: true, Layers: []string{"wireguard"},
		CheckCommand: []string{filepath.Join(t.TempDir(), "missing-captured-check")}})
	source := append([]byte(nil), f.original.launch.ownedNode.source...)
	calls := 0
	runtime := f.runtime(t)
	runtime.start = func(a *app, id string, hold bool, transition *modeAttemptTransition) error {
		calls++
		err := a.startModeAttempt(id, hold, transition)
		if err == nil || transition == nil || transition.StopBegun {
			t.Fatal("actual startModeAttempt marked Stop before its real preflight rejection", err)
		}
		return err
	}
	result, err := f.run(runtime)
	if err != nil || !result.OK || calls != 1 || result.RuntimeMode != "awg2-strong" {
		t.Fatal("real preflight rejection did not retain the proved original", err)
	}
	desktopNodeSmartAssertCurrent(t, f, source)
}

func TestDesktopNodeSmartPreflightCannotRetainReplacementSlot(t *testing.T) {
	f := newDesktopNodeSmartFixture(t, "awg2-fast")
	target := copyDesktopNodeProtectionTarget(f.kernel.target)
	target.Capture.SessionID = strings.Repeat("9", 32)
	replacementKernel := &desktopNodeProtectionFixture{target: target}
	replacement := &desktopNodeProtectionSlot{backend: replacementKernel.backend(), known: true, target: copyDesktopNodeProtectionTarget(target)}
	var expected state
	starts, restores := 0, 0
	runtime := f.runtime(t)
	runtime.start = func(a *app, _ string, _ bool, transition *modeAttemptTransition) error {
		starts++
		if transition == nil || transition.StopBegun {
			t.Fatal("replacement fixture reached Stop before its preflight failure")
		}
		a.mu.Lock()
		a.nodeProtection = replacement
		// Keep command, mode and profile stable: only independent slot authority
		// can reject a false retain/winner decision in this case.
		a.state.Phase, a.state.LastError = "replacement-owned-presentation", "replacement-status-must-survive"
		expected = a.state
		a.mu.Unlock()
		return errors.New("old candidate preflight completed after slot replacement")
	}
	runtime.restore = func(*app, speedLabRestorePlan) error { restores++; return errors.New("unexpected replacement restore") }
	result, err := f.run(runtime)
	if err == nil || result.OK || starts != 1 || restores != 0 || f.a.nodeProtection != replacement || f.a.state != expected ||
		f.a.cmd != f.original.launch.command || f.original.process.closes != 0 || f.original.launch.ownedNode.retired ||
		f.kernel.releases != 0 || replacementKernel.releases != 0 || !reflect.DeepEqual(replacement.target, target) {
		t.Fatal("SMART retained, stopped, or overwrote a replacement protection owner after preflight", result, err)
	}
	if _, err := f.original.launch.directoryRoot.Lstat("stop.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old SMART preflight wrote Stop into an unowned replacement transaction", err)
	}
	for _, attempt := range result.Attempts {
		if attempt.Success && (attempt.Action == "retain" || attempt.Action == "restore") {
			t.Fatal("SMART reported a retained or restored path under replacement protection")
		}
	}
}

type desktopNodeRetainPublicationProcess struct {
	desktopNodeProcess
	checks int
	change func()
}

func (process *desktopNodeRetainPublicationProcess) Alive() error {
	if err := process.desktopNodeProcess.Alive(); err != nil {
		return err
	}
	process.checks++
	// This second liveness return is the last native boundary of readiness.
	// The final presentation check must still reject what changed after it.
	if process.checks == 2 {
		process.change()
	}
	return nil
}

func TestDesktopNodeSmartRetainRechecksPublicationOwner(t *testing.T) {
	for _, change := range []string{"cancel", "native-owner"} {
		t.Run(change, func(t *testing.T) {
			f := newDesktopNodeSmartFixture(t)
			f.a.operationMu.Lock()
			defer f.a.operationMu.Unlock()
			saved, err := f.a.captureSmartDesktopNode(f.operation, f.profile)
			if err != nil || saved == nil {
				t.Fatal("fixture could not capture the actual proved SMART predecessor", err)
			}
			replacement := &desktopNodeLaunch{command: f.original.launch.command}
			var expected state
			process := &desktopNodeRetainPublicationProcess{desktopNodeProcess: desktopOwnedNodeProcess(f.original.launch)}
			process.change = func() {
				if change == "cancel" {
					f.cancel()
				} else {
					desktopNodeOwners.Store(f.a, replacement)
				}
				f.a.mu.Lock()
				f.a.state.Connected, f.a.state.Phase, f.a.state.LastError = false, "replacement-pending", "replacement retained"
				expected = f.a.state
				f.a.mu.Unlock()
			}
			f.original.launch.workspaceMu.Lock()
			f.original.launch.ownedNode.process = process
			f.original.launch.workspaceMu.Unlock()
			err = f.a.retainSmartDesktopNode(saved)
			if err == nil || process.checks != 2 || f.a.state != expected || f.original.process.closes != 0 {
				t.Fatal("SMART retention published after its exact request or native owner changed", err, process.checks)
			}
			if change == "native-owner" {
				current, _ := desktopNodeOwners.Load(f.a)
				if current != replacement || f.a.cmd != replacement.command {
					t.Fatal("SMART retention overwrote a same-command replacement native owner")
				}
			}
		})
	}
}

func TestDesktopNodeSmartTrialRestoresCapturedGraphAndLiveMTU(t *testing.T) {
	f := newDesktopNodeSmartFixture(t, "awg2-fast")
	live, err := readDesktopNodeMTU(f.original.launch)
	if err != nil {
		t.Fatal(err)
	}
	live.MTU, live.Reader, live.Index = 1372, 2, live.Index+1
	desktopOwnedNodeTestWrite(t, f.original.launch, "node-mtu-status.json", live)
	originalGraph := f.original.original.Config()
	originalMetadata := f.original.original.Metadata()
	var trial, restored *desktopOwnedNodeTestFixture
	var latest *mobiletor.DesktopWindowsProtectionTarget
	starts, restores := 0, 0
	runtime := f.runtime(t)
	runtime.start = func(a *app, id string, hold bool, transition *modeAttemptTransition) error {
		starts++
		if starts != 1 || id != "awg2-fast" || transition == nil || !hold {
			t.Fatal("SMART retried an uncaptured original mode instead of its restore plan")
		}
		transition.StopBegun = true
		f.original.retirement(t)
		if err := a.stopModeWithIntent(true); err != nil {
			t.Fatal(err)
		}
		trial = f.trial(t, "2")
		latest = copyDesktopNodeProtectionTarget(f.kernel.target)
		trial.retirement(t)
		return errors.New("candidate path proof failed after native transition")
	}
	runtime.restore = func(a *app, plan speedLabRestorePlan) error {
		restores++
		if trial == nil || !trial.process.closed || f.kernel.locked || a.cmd != nil || plan.native == nil ||
			!reflect.DeepEqual(f.kernel.target, latest) || plan.native.ownedNode.policy.Metadata().RestoredMTU != 1372 ||
			plan.native.ownedNode.policy.OriginalProfile().Config() != originalGraph || plan.native.ownedNode.policy.OriginalProfile().Metadata() != originalMetadata ||
			plan.native.mtuSession == f.original.launch.mtuSession || plan.native.mtuSession == trial.launch.mtuSession {
			t.Fatal("SMART restoration lost the joined latest target, live MTU, or captured original graph")
		}
		restored = f.stage(t, plan.native, true)
		if !reflect.DeepEqual(restored.launch.ownedNode.attempt.transfer.Predecessor, latest) {
			t.Fatal("SMART restoration reused a stale predecessor instead of the joined trial target")
		}
		return nil
	}
	result, err := f.run(runtime)
	if err != nil || !result.OK || result.RuntimeMode != "awg2-strong" || result.RestoredMode != "awg2-strong" || starts != 1 || restores != 1 ||
		restored == nil || f.a.cmd != restored.launch.command || !f.a.state.Connected || f.a.state.Phase != "connected" ||
		!f.original.process.closed || !trial.process.closed || restored.process.closed || f.kernel.prepared != 3 {
		t.Fatal("SMART did not complete A to B to captured A-prime", result, err)
	}
	next, err := f.a.captureDesktopOwnedNodeRestore(restored.launch, f.profile)
	if err != nil || next == nil {
		t.Fatal("SMART plan cleanup erased the active restored source", err)
	}
	clearSpeedLabRestorePlan(speedLabRestorePlan{native: next})
}

func TestDesktopNodeSmartFailedTrialJoinRetainsPendingOwner(t *testing.T) {
	f := newDesktopNodeSmartFixture(t, "awg2-fast")
	var trial *desktopOwnedNodeTestFixture
	restores := 0
	runtime := f.runtime(t)
	runtime.start = func(a *app, _ string, _ bool, transition *modeAttemptTransition) error {
		transition.StopBegun = true
		f.original.retirement(t)
		if err := a.stopModeWithIntent(true); err != nil {
			t.Fatal(err)
		}
		trial = f.trial(t, "2")
		trial.retirement(t)
		trial.process.closeErr = errors.New("captured trial descendants have not joined")
		return errors.New("candidate path proof failed")
	}
	runtime.restore = func(*app, speedLabRestorePlan) error { restores++; return nil }
	result, err := f.run(runtime)
	current, _ := desktopNodeOwners.Load(f.a)
	if err == nil || result.OK || restores != 0 || trial == nil || current != trial.launch || trial.process.closed ||
		!f.kernel.locked || f.a.nodeProtection.active != trial.launch.ownedNode.attempt || f.a.state.Connected || f.a.state.Phase != "failed" {
		t.Fatal("SMART discarded the failed trial or restored across an unjoined native owner", result, err)
	}
	if _, err := os.Lstat(trial.launch.directory); err != nil {
		t.Fatal("failed SMART join discarded its private cleanup workspace", err)
	}
}

func TestDesktopNodeSmartCancelledStartupJoinsDespiteConflictingConnect(t *testing.T) {
	f := newDesktopNodeSmartFixture(t, "awg2-fast")
	startupPolicyCancels.Store(f.a, context.CancelFunc(f.cancel))
	f.original.retirement(t)
	var conflict error
	runtime := f.runtime(t)
	runtime.start = func(a *app, _ string, _ bool, transition *modeAttemptTransition) error {
		if transition.StopBegun {
			t.Fatal("fixture cancellation unexpectedly reached Stop")
		}
		_, finish, err := a.beginConnectionOperation()
		conflict = err
		if finish != nil {
			finish()
		}
		if err == nil || f.operation.Err() == nil {
			t.Fatal("conflicting explicit Connect did not cancel the startup operation")
		}
		return errConnectionOperationCancelled
	}
	result, err := f.run(runtime)
	if conflict == nil || !errors.Is(err, errConnectionOperationCancelled) || result.OK || !f.original.process.closed || f.kernel.locked ||
		f.a.cmd != nil || f.a.state.Connected || f.a.state.Phase != "off" || f.a.nodeProtection.active != nil {
		t.Fatal("cancelled startup left its exact native child alive after explicit Connect conflicted", result, err)
	}
	if _, exists := desktopNodeOwners.Load(f.a); exists {
		t.Fatal("cancelled startup retained a completed runtime owner")
	}
	if _, exists := startupPolicyCancels.Load(f.a); exists {
		t.Fatal("explicit Connect did not retire its startup cancellation entry")
	}
}

func TestDesktopNodeSmartCancelledFallbackPreservesReplacement(t *testing.T) {
	for _, replacement := range []string{"operation", "runtime-operation", "command", "slot"} {
		t.Run(replacement, func(t *testing.T) {
			f := newDesktopNodeSmartFixture(t)
			other, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch replacement {
			case "operation":
				f.a.connectionContext = other
			case "runtime-operation":
				f.original.launch.ownedNode.operation = other
			case "command":
				f.a.cmd = &exec.Cmd{Path: "replacement-command"}
			case "slot":
				f.a.nodeProtection = &desktopNodeProtectionSlot{}
			}
			before, command, slot := f.a.state, f.a.cmd, f.a.nodeProtection
			f.cancel()
			err := f.a.finalizeCancelledFallbackFor("SMART AUTO", f.operation)
			current, _ := desktopNodeOwners.Load(f.a)
			if !errors.Is(err, errConnectionOperationCancelled) || f.a.state != before || f.a.cmd != command || f.a.nodeProtection != slot ||
				current != f.original.launch || f.original.process.closes != 0 || f.kernel.releases != 0 || f.original.launch.ownedNode.retired {
				t.Fatal("cancelled fallback changed a replacement owner or its presentation", replacement, err)
			}
		})
	}
}

func TestDesktopNodeSmartCancelledFallbackRetainsFailedJoin(t *testing.T) {
	for _, failure := range []string{"child-join", "native-read"} {
		t.Run(failure, func(t *testing.T) {
			f := newDesktopNodeSmartFixture(t)
			f.original.retirement(t)
			if failure == "child-join" {
				f.original.process.closeErr = errors.New("captured child Job has not joined")
			} else {
				f.kernel.readFail = true
			}
			f.cancel()
			err := f.a.finalizeCancelledFallbackFor("SMART AUTO", f.operation)
			current, _ := desktopNodeOwners.Load(f.a)
			if !errors.Is(err, errConnectionOperationCancelled) || current != f.original.launch || f.a.nodeProtection.active != f.original.launch.ownedNode.attempt ||
				f.a.state.Connected || f.a.state.Phase != "failed" || f.original.launch.ownedNode.retired || f.kernel.releases != 0 {
				t.Fatal("cancelled fallback falsely completed unproved native cleanup", failure, err)
			}
			if failure == "child-join" && f.original.process.closed {
				t.Fatal("failed child join was reported as completed")
			}
			if _, err := os.Lstat(f.original.launch.directory); err != nil {
				t.Fatal("pending cancellation discarded its private cleanup workspace", err)
			}
			f.original.process.closeErr, f.kernel.readFail = nil, false
			if err := f.a.finalizeCancelledFallbackFor("SMART AUTO", f.operation); !errors.Is(err, errConnectionOperationCancelled) || f.a.state.Phase != "off" {
				t.Fatal("matching cancelled owner could not retry its exact retained cleanup", err)
			}
			if _, exists := desktopNodeOwners.Load(f.a); exists || !f.original.process.closed || f.a.nodeProtection.active != nil {
				t.Fatal("successful cancellation retry left its prior owner pending")
			}
		})
	}
}

func TestDesktopNodeSmartCompletedOperationDoesNotRetireLiveConnection(t *testing.T) {
	f := newDesktopNodeSmartFixture(t)
	f.cancel()
	f.a.connectionContext = nil
	f.a.connectionCancel = nil
	if err := f.processes[0].Alive(); err != nil {
		t.Fatal("successful connection lifetime was tied to its completed operation context", err)
	}
	if _, err := f.a.readDesktopOwnedNodeReady(f.original.launch, false); err != nil {
		t.Fatal("completed Connect invalidated its independently owned live runtime", err)
	}
	if !f.a.state.Connected || f.a.state.Phase != "connected" || f.original.process.closes != 0 {
		t.Fatal("completed operation changed the live connection")
	}
}
