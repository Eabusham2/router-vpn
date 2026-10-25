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
	"router-vpn/internal/mobiletor"
)

func speedLabTorCurrentFixture(t *testing.T) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, launch, _ := desktopTorRunningFixture(t, "proof")
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	a.cfg.ProfilesFile = filepath.Join(root, "profiles.json")
	a.profiles.SchemaVersion = common.RouterProfileSchemaVersion
	launch.tor.network, launch.tor.networkIdentity = physicalNetworkIdentity(), nil
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	a.state.Connected, a.state.Phase, a.state.LogicalMode, a.state.Base = true, "connected", "external-node", "tor"
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "speed-lab-tor-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: launch.profileID}})
	t.Cleanup(func() { sessionTrackers.Delete(a); speedLabTemporaryOwners.Delete(a) })
	return a, launch
}

func TestSpeedLabTorCapturesActualRegisteredNativeOwner(t *testing.T) {
	a, launch := speedLabTorCurrentFixture(t)
	identity, path, err := captureSpeedLabIdentity(a)
	if err != nil {
		t.Fatal("proved Tor owner was rejected as an ordinary external graph", err)
	}
	if identity.Tor != launch || identity.External != nil || identity.TorSession != launch.tor.expected.SessionID || identity.Execution != "local" || identity.EntryToken != "" || identity.GraphOK {
		t.Fatal("Tor identity borrowed an ordinary graph, entry or execution", identity)
	}
	if path.Topology != "external" || path.ExternalProtocol != "tor-bridge" || path.Execution != "local" || path.EntryID != "" || path.ExitID != launch.profileID || !path.StartedAt.Equal(launch.tor.started) {
		t.Fatal("Tor measurement path is not the proved native owner", path)
	}
	if _, err := waitForSpeedLabConnectedIdentity(a, time.Second); err != nil {
		t.Fatal("successful temporary Tor proof never became measurable", err)
	}
	if err := verifySpeedLabPath(context.Background(), a, identity); err != nil {
		t.Fatal("Tor verification used ordinary external proof", err)
	}
}

func TestSpeedLabTorRejectsRetiredOrMixedProofOwners(t *testing.T) {
	for _, kind := range []string{"owner", "missing-owner", "command", "session", "execution", "profile", "network", "proof", "mixed", "exited"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := speedLabTorCurrentFixture(t)
			identity, _, err := captureSpeedLabIdentity(a)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "owner":
				desktopNodeOwners.Store(a, &desktopNodeLaunch{command: &exec.Cmd{}, profileID: launch.profileID, tor: launch.tor})
			case "missing-owner":
				desktopNodeOwners.Delete(a)
			case "command":
				a.cmd = &exec.Cmd{}
			case "session":
				identity.TorSession = strings.Repeat("f", 32)
			case "execution":
				identity.Execution = "server"
			case "profile":
				a.profiles.Profiles[0].DNSPort++
			case "network":
				launch.tor.networkIdentity = func() string { return "replacement-network" }
			case "proof":
				launch.tor.mu.Lock()
				launch.tor.expected.DNS.Address = "203.0.113.53"
				launch.tor.mu.Unlock()
			case "mixed":
				identity.External = launch
			case "exited":
				if err := launch.command.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				<-desktopNodeProcessDone(launch)
			}
			if err := validateSpeedLabIdentity(a, identity); err == nil {
				t.Fatal("retired or incompatible Tor measurement admitted", kind)
			}
			if kind != "session" && kind != "execution" && kind != "mixed" {
				if _, _, err := captureSpeedLabIdentity(a); err == nil {
					t.Fatal("a fresh capture accepted the invalid Tor owner", kind)
				}
			}
		})
	}
}

func TestSpeedLabTorRestoreCapturesOnlyProvedPolicyDigests(t *testing.T) {
	a, launch := speedLabTorCurrentFixture(t)
	// Adoption metadata may change without changing the proved private policy.
	a.profiles.Profiles[0].UseCount++
	a.profiles.Profiles[0].Name = "Selected Tor path"
	snapshot, err := a.speedLabSnapshotTemporary()
	if err != nil {
		t.Fatal("registered Tor connection could not be retained for restoration", err)
	}
	plan := snapshot.Plan
	if plan.tor == nil || plan.external != nil || plan.native != nil || plan.multihop != nil || plan.request.Topology != "external" || plan.request.Execution != "local" || plan.request.EntryID != "" || plan.request.EntryMode != "" {
		t.Fatal("Tor restore repeated an ordinary graph selector", plan.request)
	}
	profile, err := a.speedLabTorRestoreProfile(plan)
	if err != nil || !reflect.DeepEqual(profile, snapshot.Profiles.Profiles[0]) {
		t.Fatal("Tor restore lost complete saved settings", err)
	}
	policy, err := speedLabTorPolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	tor := installFakeExecutable(t, t.TempDir(), "tor")
	native := installFakeExecutable(t, t.TempDir(), "sing-box-routervpn")
	prepared, err := stageDesktopTorInputs(t.TempDir(), policy, profile, tor, native)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Launch.directoryRoot.Close()
	defer func() {
		if err := cleanupDesktopTorLaunch(prepared.Launch); err != nil {
			t.Error(err)
		}
	}()
	priorRaw, err := readDesktopRuntimeFile(launch, "tor-capture.json", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	freshRaw, err := readDesktopRuntimeFile(prepared.Launch, "tor-capture.json", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var prior, fresh mobiletor.DesktopBridgeCapture
	if json.Unmarshal(priorRaw, &prior) != nil || json.Unmarshal(freshRaw, &fresh) != nil || fresh.SessionID == prior.SessionID || fresh.IsolationSecret == prior.IsolationSecret || fresh.SessionID == "" || fresh.IsolationSecret == "" {
		t.Fatal("Tor restore reused a retired session or isolation credential")
	}
	oldProof, err := readDesktopRuntimeFile(launch, "proof.json", 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Launch.tor.started = time.Now()
	if _, err := validateDesktopTorProof(oldProof, prepared.Launch.tor, time.Now()); err == nil {
		t.Fatal("old Tor/DNS proof admitted the restored session")
	}
	if profile.DNSHost != "9.9.9.9" || profile.DNSPort != 5353 || prepared.Launch.tor.expected.DNS != launch.tor.expected.DNS || prepared.Launch.tor.expected.ConfiguredMTU != launch.tor.expected.ConfiguredMTU || prepared.Launch.tor.expected.IPv6Mode != launch.tor.expected.IPv6Mode || prepared.Launch.tor.expected.HomeLANAccess != launch.tor.expected.HomeLANAccess || prepared.Launch.tor.expected.KillSwitchPolicy != launch.tor.expected.KillSwitchPolicy {
		t.Fatal("fresh Tor restore substituted selected DNS or device policy")
	}
	profile.External.TorBridge.Bridges[0] = "changed clone"
	if reflect.DeepEqual(profile.External, plan.profile.External) {
		t.Fatal("restore profile shares mutable private transport credentials")
	}
}

func TestSpeedLabTorRestoreRejectsChangedCapturedSource(t *testing.T) {
	for _, kind := range []string{"missing", "bytes", "replacement", "link"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := speedLabTorCurrentFixture(t)
			path := filepath.Join(launch.directory, "tor-profile.json")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "bytes":
				err = os.WriteFile(path, append(original, ' '), 0600)
			default:
				err = os.Rename(path, path+".original")
				if err == nil && kind == "replacement" {
					err = os.WriteFile(path, original, 0600)
				} else if err == nil && kind == "link" {
					err = os.Symlink(path+".original", path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.speedLabSnapshotTemporary(); err == nil {
				t.Fatal("Tor restore trusted replaced or modified private source", kind)
			}
		})
	}
}

func TestSpeedLabTorRestoreRejectsChangedSelectionBeforeLaunch(t *testing.T) {
	a, _ := speedLabTorCurrentFixture(t)
	snapshot, err := a.speedLabSnapshotTemporary()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"profile", "saved-profile", "policy", "network", "server", "entry", "mode", "mixed"} {
		t.Run(kind, func(t *testing.T) {
			plan := snapshot.Plan
			plan.profile = cloneRouterProfile(plan.profile)
			saved := *plan.tor
			plan.tor = &saved
			a.profiles = cloneRouterProfileStore(snapshot.Profiles)
			switch kind {
			case "profile":
				a.profiles.Profiles[0].ManualMTU++
			case "saved-profile":
				plan.profile.External.TorBridge.Bridges[0] = "replacement-bridge"
			case "policy":
				plan.tor.policyToken = strings.Repeat("0", 64)
			case "network":
				plan.tor.network = "old-network"
			case "server":
				plan.request.Execution = "server"
			case "entry":
				plan.request.EntryID = "another-entry"
			case "mode":
				plan.request.Topology = "router"
			case "mixed":
				plan.external = &speedLabExternalRestore{}
			}
			if _, err := a.speedLabTorRestoreProfile(plan); err == nil {
				t.Fatal("changed Tor restore was admitted", kind)
			}
			if err := a.speedLabRestartPlan(plan); err == nil {
				t.Fatal("shipping restart bypassed the retained Tor selection", kind)
			}
		})
	}
}

// Use actual native-controller child receipts at the runtime boundary. This
// fixture never starts Tor or a TUN; it exercises the unchanged restore
// transaction with fresh staging, process ownership, proof and checked drain.
func TestSpeedLabTorCancelledTestRestoresFreshOwnedSession(t *testing.T) {
	a, previous := speedLabTorCurrentFixture(t)
	_, snapshot, finish, err := a.beginSpeedLabTemporaryOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	snapshot.Owner.mutated = true
	snapshot.Owner.cancelTest()
	var restored *desktopNodeLaunch
	var starts int
	stop := func(bool) error {
		if raw, exists := desktopNodeOwners.Load(a); exists {
			launch := raw.(*desktopNodeLaunch)
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
		return speedLabFakeStop(a, snapshot.Owner)(true)
	}
	actions := speedLabRestoreActions{stop: stop, persist: a.speedLabWriteStore, network: physicalNetworkIdentity, restart: func(plan speedLabRestorePlan) error {
		starts++
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
		restored = prepared.Launch
		restored.tor.network, restored.tor.started = physicalNetworkIdentity(), time.Now()
		expected, _ := json.Marshal(restored.tor.expected)
		command := exec.Command(os.Args[0], "-test.run=^TestDesktopTorProcessFixture$")
		command.Env = append(os.Environ(), "ROUTERVPN_TOR_TEST_CHILD=proof", "ROUTERVPN_TOR_TEST_DIRECTORY="+restored.directory, "ROUTERVPN_TOR_TEST_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "GORACE=atexit_sleep_ms=0")
		command.Stdout, command.Stderr = io.Discard, io.Discard
		restored.command = command
		if err := command.Start(); err != nil {
			return err
		}
		t.Cleanup(func() {
			_ = command.Process.Kill()
			<-desktopNodeProcessDone(restored)
			_ = restored.directoryRoot.Close()
		})
		a.cmd = command
		desktopNodeOwners.Store(a, restored)
		if err := a.speedLabOwnRuntime(command); err != nil {
			return err
		}
		if _, err := a.waitDesktopTorProof(a.connectionOperationContextOrBackground(), restored); err != nil {
			return err
		}
		a.state = snapshot.State
		tracker := sessionTrackerFor(a)
		tracker.mu.Lock()
		tracker.session.ID = "fresh-tor-restore-session"
		tracker.mu.Unlock()
		identity, _, err := captureSpeedLabIdentity(a)
		if err != nil {
			return err
		}
		return verifySpeedLabPath(a.connectionOperationContextOrBackground(), a, identity)
	}}
	if err := a.speedLabRestoreWith(snapshot, actions); err != nil {
		t.Fatal(err)
	}
	if starts != 1 || restored == nil || restored == previous || restored.tor.expected.SessionID == previous.tor.expected.SessionID || !snapshot.Owner.restored || !desktopNodeProcessExited(previous) || !a.state.Connected || !reflect.DeepEqual(a.profiles, snapshot.Profiles) {
		t.Fatal("cancelled temporary test failed to restore a fresh proved Tor owner")
	}
	if err := a.speedLabRestoreWith(snapshot, actions); err != nil || starts != 1 {
		t.Fatal("repeat restoration replaced the already-proved Tor owner", err)
	}
	body, err := os.ReadFile(a.cfg.ProfilesFile)
	var durable common.RouterProfileStore
	if err != nil || json.Unmarshal(body, &durable) != nil || !reflect.DeepEqual(durable, snapshot.Profiles) {
		t.Fatal("Tor restore did not retain the complete private profile store", err)
	}
	if err := stop(true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(restored.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restored test owner did not drain its private workspace", err)
	}
}
