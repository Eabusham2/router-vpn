package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// The native subprocess exchanges real, captured Tor IPC records. Its transfer
// bytes and interface values are synthetic fixtures, not physical Tor or TUN
// measurements. The controller, saved profile, hold and restore transaction run
// unchanged on either side of the explicit process-launch boundary.
func speedLabTorMeasuredMTUFixture(t *testing.T, automatic bool) (*app, *desktopNodeLaunch, desktopMTURecord) {
	t.Helper()
	a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-winner")
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	a.profiles.SchemaVersion = common.RouterProfileSchemaVersion
	launch.tor.network, launch.tor.networkIdentity = physicalNetworkIdentity(), nil
	a.state.LogicalMode, a.state.Base = "external-node", "tor"
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "speed-lab-measured-tor", Connected: true, Phase: "connected", PathProof: "passed", RouterID: launch.profileID}})
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var result desktopMTURecord
	if automatic {
		a.startDesktopExternalAutomaticMTU(launch)
		result = desktopMTUWaitRecord(t, launch, func(record desktopMTURecord) bool {
			owner := desktopMeasurementMTUSession(launch)
			owner.mu.Lock()
			defer owner.mu.Unlock()
			return record.Status.Measured && record.Status.Complete && owner.active == "" && owner.automatic
		})
	} else {
		var err error
		result, err = a.runDesktopExternalMTU(ctx, launch, true)
		if err != nil {
			t.Fatal("Tor fixture could not earn its measured MTU before Speed Lab", err)
		}
	}
	if result.Status.EffectiveMTU != 1380 || result.Status.Source != "measured-tor-system-tun-transfer" || result.MTUReadback == nil || desktopTorSavedMTU(t, a).EffectiveMTU != 1380 {
		t.Fatal("Speed Lab started without a committed actual-reader measurement")
	}
	// This is the same hold taken before the shipping Speed Lab snapshot. It
	// remains held across the previous stop, temporary test and new connection.
	release, err := a.holdDesktopMTUForMeasurement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.mu.Lock()
		a.state.Connected = false
		a.mu.Unlock()
		release()
	})
	return a, launch, result
}

type speedLabTorMTURestoreFixture struct {
	a        *app
	snapshot speedLabTemporarySnapshot
	restored *desktopNodeLaunch
	starts   int
	stops    int
	record   desktopMTURecord
	path     desktopPathRecord
}

func newSpeedLabTorMTURestoreFixture(t *testing.T, a *app) *speedLabTorMTURestoreFixture {
	t.Helper()
	_, snapshot, finish, err := a.beginSpeedLabTemporaryOperation()
	if err != nil {
		t.Fatal("measured Tor path could not capture a temporary restore plan", err)
	}
	t.Cleanup(finish)
	snapshot.Owner.mutated = true
	snapshot.Owner.cancelTest() // A cancelled test keeps the separate restore intent.
	return &speedLabTorMTURestoreFixture{a: a, snapshot: snapshot}
}

func (fixture *speedLabTorMTURestoreFixture) stop(bool) error {
	a := fixture.a
	fixture.stops++
	if raw, exists := desktopNodeOwners.Load(a); exists {
		launch, ok := raw.(*desktopNodeLaunch)
		if !ok || launch == nil || launch.tor == nil || launch.external != nil {
			return errors.New("test stop lost its captured Tor child")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
			return err
		}
		if err := stopDesktopTorRuntime(a, launch, launch.command); err != nil {
			return err
		}
		desktopNodeOwners.CompareAndDelete(a, launch)
	}
	return speedLabFakeStop(a, fixture.snapshot.Owner)(true)
}

func (fixture *speedLabTorMTURestoreFixture) actions(t *testing.T, kind string) speedLabRestoreActions {
	t.Helper()
	a := fixture.a
	return speedLabRestoreActions{stop: fixture.stop, persist: a.speedLabWriteStore, network: physicalNetworkIdentity, restart: func(plan speedLabRestorePlan) error {
		fixture.starts++
		profile, err := a.speedLabTorRestoreProfile(plan)
		if err != nil {
			return err
		}
		policy, err := speedLabTorPolicy(profile)
		if err != nil {
			return err
		}
		prepared, err := stageDesktopTorInputs(t.TempDir(), policy, profile, installFakeExecutable(t, t.TempDir(), "tor"), installFakeExecutable(t, t.TempDir(), "sing-box-routervpn"))
		if err != nil {
			return err
		}
		launch := prepared.Launch
		fixture.restored = launch
		launch.tor.network, launch.tor.started = physicalNetworkIdentity(), time.Now()
		expected, err := json.Marshal(launch.tor.expected)
		if err != nil {
			return err
		}
		command := exec.Command(os.Args[0], "-test.run=^TestDesktopTorProcessFixture$")
		command.Env = append(os.Environ(), "ROUTERVPN_TOR_TEST_CHILD="+kind, "ROUTERVPN_TOR_TEST_DIRECTORY="+launch.directory, "ROUTERVPN_TOR_TEST_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "GORACE=atexit_sleep_ms=0")
		command.Stdout, command.Stderr = io.Discard, io.Discard
		launch.command = command
		if err := command.Start(); err != nil {
			return err
		}
		t.Cleanup(func() {
			_ = command.Process.Kill()
			<-desktopNodeProcessDone(launch)
			_ = launch.directoryRoot.Close()
		})
		a.mu.Lock()
		a.cmd = command
		a.mu.Unlock()
		desktopNodeOwners.Store(a, launch)
		if err := a.speedLabOwnRuntime(command); err != nil {
			return err
		}
		if _, err := a.waitDesktopTorProof(a.connectionOperationContextOrBackground(), launch); err != nil {
			return err
		}
		a.mu.Lock()
		a.state = fixture.snapshot.State
		captureDesktopMTUBaselineLocked(a, launch)
		a.mu.Unlock()
		tracker := sessionTrackerFor(a)
		tracker.mu.Lock()
		tracker.session.ID = "fresh-measured-tor-restore"
		tracker.mu.Unlock()
		// Use the shipping restoration helper after the newly staged child has
		// proved its own configured reader, exactly as speedLabRestartPlan does.
		err = a.restoreSpeedLabTorMTU(plan)
		fixture.record, _ = readDesktopMTURecord(launch)
		fixture.path, _ = readDesktopPathRecord(launch)
		if err != nil {
			return err
		}
		identity, _, err := captureSpeedLabIdentity(a)
		if err != nil {
			return err
		}
		return verifySpeedLabPath(a.connectionOperationContextOrBackground(), a, identity)
	}}
}

func TestSpeedLabTorMTUMeasuredReaderRestoresAcrossCancelledTest(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		name := "retest"
		if automatic {
			name = "completed-auto"
		}
		t.Run(name, func(t *testing.T) {
			a, previous, measured := speedLabTorMeasuredMTUFixture(t, automatic)
			fixture := newSpeedLabTorMTURestoreFixture(t, a)
			saved := fixture.snapshot.Plan.tor
			// Both a completed initial Auto and a proved explicit Retest satisfy
			// this connection's Auto work. Restoration must retain that fact.
			if saved == nil || saved.mtu != 1380 || !saved.automaticMTU || fixture.snapshot.Plan.request.Execution != "local" || fixture.snapshot.Plan.external != nil || fixture.snapshot.Plan.request.EntryID != "" {
				t.Fatal("restore snapshot lost its measured Tor reader or selected local execution")
			}
			capturedRaw, err := readDesktopRuntimeFile(previous, "tor-profile.json", 4<<20)
			var captured common.RouterProfile
			if err != nil || json.Unmarshal(capturedRaw, &captured) != nil || captured.EffectiveMTU != 1350 || previous.tor.expected.ConfiguredMTU != 1280 || fixture.snapshot.Plan.profile.EffectiveMTU != 1380 {
				t.Fatal("fixture did not distinguish history, configured interface and measured reader", err)
			}
			actions := fixture.actions(t, "tor-mtu-restore")
			if err := a.speedLabRestoreWith(fixture.snapshot, actions); err != nil {
				t.Fatal("cancelled Speed Lab did not restore the measured Tor interface", err)
			}
			restored := fixture.restored
			if fixture.starts != 1 || restored == nil || restored == previous || restored.external != nil || restored.tor.expected.SessionID == previous.tor.expected.SessionID || !desktopNodeProcessExited(previous) || !fixture.snapshot.Owner.restored || !a.state.Connected {
				t.Fatal("restore reused the old Tor owner or failed to earn a new connection")
			}
			record := fixture.record
			proof, err := a.readDesktopTorProof(restored)
			if err != nil || proof.MTUReadback == nil || record.MTUReadback == nil || *proof.MTUReadback != *record.MTUReadback || proof.EffectiveMTU != 1380 || record.RestoredMTU != 1380 || record.Status.Source != "restored-captured-system-tun" || !record.Status.Restored || record.Status.Measured || record.Status.Request == measured.Status.Request || record.Session == measured.Session {
				t.Fatal("restoration substituted history or an old session for a freshly proved reader", err)
			}
			if fixture.path.Generation != 1 || !fixture.path.Verified || fixture.path.Session != restored.tor.expected.SessionID {
				t.Fatal("restored reader did not obtain its own fresh Tor path proof")
			}
			owner := desktopMeasurementMTUSession(restored)
			owner.mu.Lock()
			retainedAutomatic, pendingRestore := owner.automatic, owner.restoreMTU
			owner.mu.Unlock()
			if !retainedAutomatic || pendingRestore != 0 || restored.tor.expected.ConfiguredMTU != 1280 || !reflect.DeepEqual(a.profiles, fixture.snapshot.Profiles) {
				t.Fatal("restoration changed saved Auto, completed automatic work or the complete profile")
			}
			body, err := os.ReadFile(a.cfg.ProfilesFile)
			var durable common.RouterProfileStore
			if err != nil || json.Unmarshal(body, &durable) != nil || !reflect.DeepEqual(durable, fixture.snapshot.Profiles) {
				t.Fatal("restored Tor changed the durable requested policy or measurement history", err)
			}
			if err := a.speedLabRestoreWith(fixture.snapshot, actions); err != nil || fixture.starts != 1 {
				t.Fatal("repeat restore replaced its already-proved measured Tor reader", err)
			}
			if err := fixture.stop(true); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(restored.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("restored native child did not join and clean its owned workspace", err)
			}
		})
	}
}

func TestSpeedLabTorMTUCaptureUsesLiveReaderInsteadOfSavedHistory(t *testing.T) {
	a, launch, _ := speedLabTorMeasuredMTUFixture(t, false)
	a.mu.Lock()
	a.profiles.Profiles[0].EffectiveMTU = 1440 // Historical metadata cannot authorize a reader.
	a.profiles.Profiles[0].EffectiveMTUSource = "older-saved-history"
	a.mu.Unlock()
	snapshot, err := a.speedLabSnapshotTemporary()
	if err != nil || snapshot.Plan.tor == nil || snapshot.Plan.tor.mtu != 1380 || snapshot.Plan.profile.EffectiveMTU != 1440 {
		t.Fatal("Speed Lab used saved history as the live Tor restoration MTU", err)
	}
	if err := a.desktopTorCurrent(launch); err != nil {
		t.Fatal("derived measurement history invalidated the exact Tor credentials/device source", err)
	}
}

func TestSpeedLabTorMTUFailedFreshRestoreProofCannotReportRestored(t *testing.T) {
	a, previous, _ := speedLabTorMeasuredMTUFixture(t, false)
	fixture := newSpeedLabTorMTURestoreFixture(t, a)
	err := a.speedLabRestoreWith(fixture.snapshot, fixture.actions(t, "tor-mtu-path-fail-1"))
	if err == nil || fixture.starts != 1 || fixture.snapshot.Owner.restored || a.state.Connected || a.state.Phase != "failed" || fixture.restored == nil {
		t.Fatal("failed fresh restored-path proof reported a successful Tor restoration", err)
	}
	if fixture.path.Generation != 1 || fixture.path.Verified || !fixture.record.Status.Restored || fixture.record.Status.Source != "restored-unmeasured" || fixture.record.Status.EffectiveMTU != 1280 {
		t.Fatal("failure did not reach the intended path proof and exact native rollback", fixture.path, fixture.record.Status)
	}
	if !desktopNodeProcessExited(previous) || !desktopNodeProcessExited(fixture.restored) || !reflect.DeepEqual(a.profiles, fixture.snapshot.Profiles) {
		t.Fatal("failed restore retained a child or overwrote saved Tor settings")
	}
}

func TestSpeedLabTorMTURestoreCannotTouchReplacementOwner(t *testing.T) {
	a, previous, _ := speedLabTorMeasuredMTUFixture(t, false)
	fixture := newSpeedLabTorMTURestoreFixture(t, a)
	_, replacement, _ := desktopTorRunningFixture(t, "proof")
	a.mu.Lock()
	a.cmd = replacement.command
	a.mu.Unlock()
	desktopNodeOwners.Store(a, replacement)
	err := a.speedLabRestoreWith(fixture.snapshot, fixture.actions(t, "tor-mtu-restore"))
	if err == nil || fixture.starts != 0 || fixture.stops != 0 || fixture.snapshot.Owner.restored || a.cmd != replacement.command || desktopNodeProcessExited(previous) || desktopNodeProcessExited(replacement) {
		t.Fatal("stale Speed Lab restore mutated its replacement Tor child", err)
	}
	for _, name := range []string{"mtu-request.json", "mtu-cancel.json", "stop.json"} {
		if _, err := os.Stat(filepath.Join(replacement.directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("retired restoration wrote control to its replacement owner", name, err)
		}
	}
}

func TestSpeedLabTorMTUShippingRestoreCallsReadbackBeforeAcceptance(t *testing.T) {
	// Runtime tests above exercise the process boundary and actual transaction.
	// Retain the shipping dispatch edge so a later refactor cannot silently
	// omit the tested MTU restoration while reporting the initial Tor proof.
	source := sourceFunctionForTest(t, "speed_lab_transaction.go", "func (a *app) speedLabRestartPlanWithTorRuntime")
	start := strings.Index(source, "case plan.tor != nil:")
	end := strings.Index(source, "case plan.external != nil:")
	if start < 0 || end <= start {
		t.Fatal("shipping restart no longer selects the owned Tor restore branch")
	}
	branch := source[start:end]
	if !strings.Contains(branch, "a.startSpeedLabTorRestoreWithRuntime(plan, torDriver)") {
		t.Fatal("shipping Tor restart bypasses the retained runtime")
	}
	branch = sourceFunctionForTest(t, "speed_lab_tor_path.go", "func (a *app) startSpeedLabTorRestoreWithRuntime")
	launch := strings.Index(branch, "a.startPreparedSpeedLabTorPath(plan.request, profile, prepared)")
	readback := strings.Index(branch, "return a.restoreSpeedLabTorMTU(plan)")
	if launch < 0 || readback <= launch || !strings.Contains(branch[launch:readback], "if err != nil") {
		t.Fatal("shipping Tor restart omitted measured-MTU restoration or bypassed launch failure")
	}
}
