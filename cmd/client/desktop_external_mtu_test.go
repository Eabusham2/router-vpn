package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// The isolated child exercises the production filesystem/controller protocol.
// Its explicit synthetic transfer is IPC test data, not a network measurement.
func desktopMTUChildFixture(kind, directory string, expected mobilemultihop.ExternalProofResult, write func(string, any)) func() {
	record := desktopMTURecord{Schema: 1, Session: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, Requested: true, Status: mobilemtu.Status{Phase: "idle", EffectiveMTU: 1280, Source: "configured-unmeasured", Candidates: []mobilemtu.Candidate{}}}
	write("mtu-status.json", record)
	active := ""
	read := func(name string, value any) bool {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		return err == nil && decodeRelayControlJSON(raw, value) == nil
	}
	remove := func() {
		for _, name := range []string{"mtu-request.json", "mtu-commit.json", "mtu-cancel.json"} {
			_ = os.Remove(filepath.Join(directory, name))
		}
	}
	return func() {
		if !strings.HasPrefix(kind, "mtu-") {
			return
		}
		var request desktopMTURequest
		if active == "" && read("mtu-request.json", &request) && request.Schema == 1 && request.Session == expected.SessionID && request.SourceSHA256 == expected.SourceSHA256 && request.ConfigSHA256 == expected.ConfigSHA256 && request.Generation == record.Generation+1 {
			active, record.Generation = request.Request, request.Generation
			record.Status = mobilemtu.Status{Request: active, Running: true, Phase: "measuring", OriginalMTU: record.Status.EffectiveMTU, EffectiveMTU: record.Status.EffectiveMTU, Source: "unmeasured", PathKey: strings.Repeat("b", 64), Candidates: []mobilemtu.Candidate{}}
			if kind != "mtu-hold" {
				record.Status.Candidates = []mobilemtu.Candidate{desktopMTUCandidateFixture(1380)}
				record.WaitingCommit, record.PreparedMTU, record.PreparedPathKey = true, 1380, record.Status.PathKey
			}
			if request.RestoreMTU > 0 {
				record.WaitingCommit, record.PreparedMTU, record.PreparedPathKey = false, 0, ""
				record.RestoredMTU = request.RestoreMTU
				record.Status.Candidates = []mobilemtu.Candidate{desktopMTUCandidateFixture(request.RestoreMTU)}
				record.Status.Running, record.Status.Complete, record.Status.Restored = false, true, true
				record.Status.Source, record.Status.Phase, record.Status.EffectiveMTU = "restored-captured-system-tun", "restored-captured-mtu", request.RestoreMTU
				remove()
			}
		}
		var cancel, commit desktopMTUControl
		if record.Status.Request != "" && read("mtu-cancel.json", &cancel) && cancel.Request == record.Status.Request && cancel.Generation == record.Generation && cancel.Session == expected.SessionID {
			record.WaitingCommit, record.PreparedMTU, record.PreparedPathKey = false, 0, ""
			record.Status.Running, record.Status.Complete, record.Status.Measured, record.Status.Restored = false, true, false, true
			record.Status.Source, record.Status.Phase, record.Status.EffectiveMTU = "restored-unmeasured", "restored", record.Status.OriginalMTU
			remove()
		} else if active != "" && kind != "mtu-commit-hold" && read("mtu-commit.json", &commit) && commit.Request == active && commit.Generation == record.Generation && commit.Session == expected.SessionID && commit.PathKey == record.PreparedPathKey && commit.MTU == record.PreparedMTU {
			record.Status.Running, record.Status.Complete, record.Status.Measured = false, true, true
			record.Status.Source, record.Status.Phase, record.Status.EffectiveMTU = "measured-public-system-tun-transfer", "complete", record.PreparedMTU
			record.WaitingCommit, record.PreparedMTU, record.PreparedPathKey = false, 0, ""
			remove()
		}
		write("mtu-status.json", record)
		if record.Status.Complete {
			active = ""
		}
	}
}

func desktopMTUCandidateFixture(mtu int) mobilemtu.Candidate {
	return mobilemtu.Candidate{MTU: mtu, Working: true, MedianRTT: 12.5, LatencyKind: "https-response", Download: &hopmeasure.Transfer{Bytes: 256 << 10, Seconds: .25, Mbps: 8.388608}, Upload: &hopmeasure.Transfer{Bytes: 256 << 10, Seconds: .5, Mbps: 4.194304}}
}

func desktopMTUControllerFixture(t *testing.T, kind string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, launch := desktopExternalRunningFixture(t, kind)
	a.cfg.ProfilesFile = filepath.Join(launch.root, "profiles.json")
	profile := common.CloneRouterProfile(launch.external.profile)
	profile.EffectiveMTU, profile.EffectiveMTUSource = 1350, "historical-fixture"
	profile.EffectiveMTUPathKey = strings.Repeat("a", 64)
	profile.EffectiveMTUTestedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	a.profiles = common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	a.state = state{Connected: true, Phase: "connected", Mode: "hysteria2", RuntimeMode: "hysteria2", RouterID: profile.ID}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := a.waitDesktopExternalProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	if err := a.persistProfilesLocked(); err != nil {
		a.mu.Unlock()
		t.Fatal(err)
	}
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	return a, launch
}

func desktopMTUWaitRecord(t *testing.T, launch *desktopNodeLaunch, condition func(desktopMTURecord) bool) desktopMTURecord {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		record, err := readDesktopMTURecord(launch)
		if err == nil && condition(record) {
			return record
		}
		select {
		case <-deadline.C:
			t.Fatal("owned native MTU record did not arrive", err, record.Status.Phase)
		case <-ticker.C:
		}
	}
}

func TestDesktopExternalMTUActualChildCommitAndProvenance(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-winner")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := a.runDesktopExternalMTU(ctx, launch, true)
	if err != nil || result.Status.EffectiveMTU != 1380 || !result.Status.Measured {
		t.Fatal("real child IPC did not adopt its exact committed result", err)
	}
	a.mu.Lock()
	profile := common.CloneRouterProfile(a.profiles.Profiles[0])
	a.mu.Unlock()
	if profile.EffectiveMTU != 1380 || profile.EffectiveMTUSource != "measured-public-system-tun-transfer" || profile.EffectiveMTUProfileFingerprint != launch.external.mtu.profileToken || profile.EffectiveMTUPathKey != strings.Repeat("b", 64) || profile.EffectiveUnderlayPMTU != 0 || profile.EffectiveMTUSuccessRatio != 0 || profile.DNSHost != launch.external.profile.DNSHost || profile.External.Hysteria2.Password != launch.external.profile.External.Hysteria2.Password {
		t.Fatal("commit lost captured identity, policy, or measurement labeling")
	}
	var persisted common.RouterProfileStore
	raw, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil || json.Unmarshal(raw, &persisted) != nil || persisted.Profiles[0].EffectiveMTU != 1380 {
		t.Fatal("success returned before durable persistence", err)
	}
	if launch.external.execution != "local" {
		t.Fatal("MTU change reran or changed execution selection")
	}
	second, err := a.runDesktopExternalMTU(ctx, launch, true)
	if err != nil || second.Generation != 2 || second.Status.Request == result.Status.Request || !second.Status.Measured {
		t.Fatal("next Retest did not own a new bounded generation", err)
	}
}

func TestDesktopExternalMTUFailedDurableWriteRollsBackLiveWinner(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-winner")
	if err := os.Remove(a.cfg.ProfilesFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.cfg.ProfilesFile, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.runDesktopExternalMTU(ctx, launch, true); err == nil {
		t.Fatal("failed durable write reported successful adoption")
	}
	result := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Complete && r.Status.Restored })
	if result.Status.Measured || result.Status.EffectiveMTU != 1280 || a.profiles.Profiles[0].EffectiveMTU != 1350 {
		t.Fatal("failed save retained a provisional winner")
	}
	if _, err := readDesktopRuntimeFile(launch, "mtu-commit.json", 4096); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed persistence committed", err)
	}
}

func TestDesktopExternalMTUCancelDrainsAndRestoresDurableState(t *testing.T) {
	for _, kind := range []string{"mtu-hold", "mtu-commit-hold"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopMTUControllerFixture(t, kind)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := a.runDesktopExternalMTU(ctx, launch, true); done <- err }()
			desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Running })
			if kind == "mtu-commit-hold" {
				deadline := time.Now().Add(4 * time.Second)
				for {
					if _, err := readDesktopRuntimeFile(launch, "mtu-commit.json", 4096); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("provisional winner was never durably committed")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancel returned success", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not drain native acknowledgement")
			}
			result := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Complete && r.Status.Restored })
			if result.Status.EffectiveMTU != 1280 {
				t.Fatal("live pre-test MTU not restored")
			}
			a.mu.Lock()
			profile := common.CloneRouterProfile(a.profiles.Profiles[0])
			a.mu.Unlock()
			if profile.EffectiveMTU != 1350 || profile.EffectiveMTUSource != "historical-fixture" {
				t.Fatal("canceled provisional value remained saved")
			}
		})
	}
}

func TestDesktopExternalMTURetiredProfileAndSpeedLabNeverAdopt(t *testing.T) {
	for _, change := range []string{"dns", "credential", "speed-lab"} {
		t.Run(change, func(t *testing.T) {
			a, launch := desktopMTUControllerFixture(t, "mtu-hold")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := a.runDesktopExternalMTU(ctx, launch, true); done <- err }()
			desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Running })
			a.mu.Lock()
			switch change {
			case "dns":
				a.profiles.Profiles[0].DNSHost = "203.0.113.54"
			case "credential":
				a.profiles.Profiles[0].External.Hysteria2.Password = "replacement-owner-secret"
			case "speed-lab":
				speedLabTemporaryOwners.Store(a, &speedLabTemporaryOwner{})
			}
			a.mu.Unlock()
			t.Cleanup(func() { speedLabTemporaryOwners.Delete(a) })
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("retired path reported success")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("retired MTU worker did not drain")
			}
			if _, err := readDesktopRuntimeFile(launch, "mtu-commit.json", 4096); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("retired request committed", err)
			}
			a.mu.Lock()
			mtu := a.profiles.Profiles[0].EffectiveMTU
			a.mu.Unlock()
			if mtu != 1350 {
				t.Fatal("retired MTU result persisted")
			}
		})
	}
}

func TestDesktopExternalMTURestoresCapturedValueWithoutCompare(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-restore")
	launch.external.mtu.restoreMTU = 1400
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.restoreDesktopCapturedMTU(ctx, launch); err != nil {
		t.Fatal(err)
	}
	value, err := captureDesktopMTURestore(launch)
	if err != nil || value != 1400 || launch.external.execution != "local" || launch.external.mtu.restoreMTU != 0 {
		t.Fatal("captured MTU or proved winner was not restored", value, err)
	}
	if a.profiles.Profiles[0].EffectiveMTU != 1350 {
		t.Fatal("temporary restoration changed durable profile")
	}
	a.state.Mode = "external-node"
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "mtu-restored-fixture-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: a.state.RouterID}})
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	snapshot := speedLabTemporarySnapshot{State: a.state, Runtime: launch.command, Profiles: cloneRouterProfileStore(a.profiles)}
	plan, err := a.speedLabCaptureRestorePlan(snapshot)
	if err != nil || plan.external == nil || plan.external.mtu != 1400 || plan.external.execution != "local" || plan.request.EntryMode != "" {
		t.Fatal("Speed Lab captured historical MTU or changed the proved direct winner", err)
	}
	exit, err := standardExitFromExternalProfile(plan.external.profile)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := compileSpeedLabExternalRestore(plan.external, exit)
	if err != nil || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1400 || restored.external.selection != "local" || restored.external.session == launch.external.session {
		t.Fatal("Speed Lab restart lost exact live readback or reused its old owner", err)
	}
}

func TestDesktopExternalMTURecordsRejectWrongMeasurementLabels(t *testing.T) {
	good := desktopMTURecord{WaitingCommit: true, PreparedMTU: 1380, PreparedPathKey: strings.Repeat("b", 64), Status: mobilemtu.Status{Request: strings.Repeat("c", 32), Running: true, OriginalMTU: 1280, EffectiveMTU: 1280, PathKey: strings.Repeat("b", 64), Candidates: []mobilemtu.Candidate{desktopMTUCandidateFixture(1380)}}}
	if err := validateDesktopMTURecord(good); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"icmp", "throughput", "bytes", "loss", "wrong-path", "nonhex", "no-transfer", "invalid-mtu", "invented-success"} {
		t.Run(mutation, func(t *testing.T) {
			raw, _ := json.Marshal(good)
			var bad desktopMTURecord
			_ = json.Unmarshal(raw, &bad)
			switch mutation {
			case "icmp":
				bad.Status.Candidates[0].LatencyKind = "icmp"
			case "throughput":
				bad.Status.Candidates[0].Download.Mbps *= 2
			case "bytes":
				bad.Status.Candidates[0].Upload.Bytes = 1
			case "loss":
				bad.Status.Candidates[0].PacketsSent = 50
			case "wrong-path":
				bad.PreparedPathKey = strings.Repeat("a", 64)
			case "nonhex":
				bad.PreparedPathKey, bad.Status.PathKey = strings.Repeat("z", 64), strings.Repeat("z", 64)
			case "no-transfer":
				bad.Status.Candidates[0].Upload = nil
			case "invalid-mtu":
				bad.Status.Candidates[0].MTU = 1200
			case "invented-success":
				bad.Status.Measured = true
			}
			if validateDesktopMTURecord(bad) == nil {
				t.Fatal("incorrect native evidence accepted")
			}
		})
	}
}

func TestDesktopExternalMTUCancelAPIRequiresExactActiveRequest(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := a.runDesktopExternalMTU(ctx, launch, true); done <- err }()
	record := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Running })
	for _, id := range []string{strings.Repeat("f", 32), record.Status.Request} {
		response := httptest.NewRecorder()
		a.cancelDesktopMTURoute(response, httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", strings.NewReader(`{"request_id":"`+id+`"}`)))
		if id == record.Status.Request && response.Code != http.StatusOK || id != record.Status.Request && response.Code != http.StatusConflict {
			t.Fatal("cancel API lost request ownership", response.Code)
		}
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("API cancel did not cancel exact context", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("API cancellation did not drain")
	}
}

func TestDesktopExternalMTUSpeedLabHoldDrainsAutoBeforeSnapshot(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	lock := mtuRetestLockFor(a)
	lock.Lock()
	owner := launch.external.mtu
	owner.mu.Lock()
	owner.automatic = true
	owner.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := a.runDesktopExternalMTU(context.Background(), launch, false)
		lock.Unlock()
		done <- err
	}()
	desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Running })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := a.holdDesktopMTUForMeasurement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("Speed Lab did not cancel exact Auto worker", err)
	}
	value, err := captureDesktopMTURestore(launch)
	if err != nil || value != 1280 {
		t.Fatal("Speed Lab captured a provisional MTU", value, err)
	}
	owner.mu.Lock()
	resume := !owner.automatic && owner.active == ""
	owner.mu.Unlock()
	if !resume {
		t.Fatal("interrupted automatic policy cannot resume after measurement")
	}
	if lock.TryLock() {
		lock.Unlock()
		t.Fatal("Speed Lab lost MTU ownership before completion")
	}
	// No replacement work is launched by this fixture after its final release.
	a.mu.Lock()
	a.state.Connected = false
	a.state.Phase = "off"
	a.mu.Unlock()
}
