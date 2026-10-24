package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func speedLabRestorationFixture(t *testing.T, connected bool) (*app, speedLabTemporarySnapshot, func()) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	profile := common.RouterProfile{ID: "active-node", Name: "Active", NodeKind: "router-vpn", Endpoint: "203.0.113.7", APIToken: "private-active-token", DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "10.2.0.53", DNSPort: 5353, MTUPolicy: "manual", ManualMTU: 1377, IPv6Mode: "on", HomeLANAccess: true, HomeLANCIDRs: []string{"192.168.50.0/24"}, CustomLayers: []string{"wg", "shadowsocks"}}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json")}, profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion, SelectedID: "other-node", Profiles: []common.RouterProfile{profile, {ID: "other-node", Name: "Selected", NodeKind: "router-vpn", Endpoint: "203.0.113.9", APIToken: "private-other-token"}}}, state: state{Mode: "off", Phase: "off", RouterID: "other-node", DAITA: true, Jumbo: true, Socks: true}}
	for i := range a.profiles.Profiles {
		if err := common.NormalizeRouterProfile(&a.profiles.Profiles[i]); err != nil {
			t.Fatal(err)
		}
	}
	if connected {
		a.state.Connected, a.state.Phase, a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode, a.state.Base, a.state.RouterID = true, "connected", "wg", "smart-auto", "wg", "wg", profile.ID
		a.cmd = &exec.Cmd{}
	}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "captured-original-session", Connected: connected, Phase: a.state.Phase, PathProof: "passed", RouterID: a.state.RouterID}}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a); desktopNodeOwners.Delete(a); speedLabTemporaryOwners.Delete(a) })
	_, snapshot, finish, err := a.beginSpeedLabTemporaryOperation()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(finish)
	return a, snapshot, finish
}

func speedLabFakeTemporaryRuntime(a *app, snapshot speedLabTemporarySnapshot) *exec.Cmd {
	command := &exec.Cmd{}
	a.mu.Lock()
	a.cmd = command
	a.state = state{Connected: true, Mode: "hysteria2", RuntimeMode: "hysteria2", RouterID: "other-node", Phase: "connected"}
	a.profiles.SelectedID = "active-node"
	a.profiles.Profiles[0].APIToken = "temporary-credential"
	a.profiles.Profiles[0].DNSHost = "203.0.113.53"
	a.profiles.Profiles[0].HomeLANCIDRs[0] = "10.0.0.0/8"
	snapshot.Owner.runtime, snapshot.Owner.mutated = command, true
	a.mu.Unlock()
	return command
}

func speedLabFakeStop(a *app, owner *speedLabTemporaryOwner) func(bool) error {
	return func(bool) error {
		a.mu.Lock()
		a.cmd, owner.runtime = nil, nil
		a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
		a.mu.Unlock()
		return nil
	}
}

func TestSpeedLabSnapshotKeepsEntirePriorConnectedState(t *testing.T) {
	a, snapshot, _ := speedLabRestorationFixture(t, true)
	if !snapshot.State.Connected || snapshot.State.LogicalMode != "smart-auto" || snapshot.State.RouterID != "active-node" || snapshot.Profiles.SelectedID != "other-node" || snapshot.Runtime != a.cmd {
		t.Fatalf("capture replaced the live path with a disconnected selection: %#v", snapshot.State)
	}
	if snapshot.Plan.request.Mode != "wg" || snapshot.Plan.request.NodeID != "active-node" {
		t.Fatal("restore plan would repeat AUTO or substitute the selected node")
	}
	a.profiles.Profiles[0].HomeLANCIDRs[0] = "10.0.0.0/8"
	a.profiles.Profiles[0].CustomLayers[0] = "tor"
	if snapshot.Profiles.Profiles[0].HomeLANCIDRs[0] != "192.168.50.0/24" || snapshot.Plan.profile.CustomLayers[0] != "wg" {
		t.Fatal("restore capture shares mutable profile settings")
	}
}

func TestSpeedLabInvalidExternalPreflightPreservesExistingVPN(t *testing.T) {
	a, snapshot, finish := speedLabRestorationFixture(t, true)
	finish()
	before, store, command := a.state, cloneRouterProfileStore(a.profiles), a.cmd
	request := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil)
	_, _, _, err := a.speedLabTemporary(request, speedLabRequest{Scope: "temporary", Topology: "external", NodeID: "missing-node"}, speedLabDuration{Mode: "auto"}, time.Second, time.Second)
	if err == nil || a.cmd != command || a.state != before || !reflect.DeepEqual(a.profiles, store) || !snapshot.State.Connected {
		t.Fatalf("invalid external request disturbed the previous proved connection: %v %#v", err, a.state)
	}
}

func TestSpeedLabAlreadyCancelledRequestNeverSuspendsExistingVPN(t *testing.T) {
	a, _, finish := speedLabRestorationFixture(t, true)
	finish()
	before, command := a.state, a.cmd
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil).WithContext(ctx)
	_, _, _, err := a.speedLabTemporary(request, speedLabRequest{Scope: "temporary", Topology: "system-direct"}, speedLabDuration{Mode: "auto"}, time.Second, time.Second)
	if !errors.Is(err, context.Canceled) || a.state != before || a.cmd != command {
		t.Fatalf("cancelled test suspended the original connection: %v %#v", err, a.state)
	}
}

func TestSpeedLabPostLaunchCheckNeverClaimsAReplacementProcess(t *testing.T) {
	a, snapshot, _ := speedLabRestorationFixture(t, true)
	owned := speedLabFakeTemporaryRuntime(a, snapshot)
	replacement := &exec.Cmd{}
	a.cmd = replacement
	if err := a.speedLabCheckLaunchedRuntime(); err == nil || snapshot.Owner.runtime != owned || a.cmd != replacement {
		t.Fatal("late strategy completion adopted the replacement runtime")
	}
	a.cmd = nil
	if err := a.speedLabCheckLaunchedRuntime(); err != nil || snapshot.Owner.runtime != nil {
		t.Fatal("successfully retired candidate ownership could not be released")
	}
}

func TestSpeedLabHTTPTestCancellationRestoresWholeProvedConnection(t *testing.T) {
	a, snapshot, finish := speedLabRestorationFixture(t, true)
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil).WithContext(requestCtx)
	_, release, err := a.speedLabRequestContext(request, snapshot.Owner.test)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	speedLabFakeTemporaryRuntime(a, snapshot)
	cancelRequest()
	select {
	case <-snapshot.Owner.test.Done():
	case <-time.After(time.Second):
		t.Fatal("HTTP cancellation did not stop the test")
	}
	if snapshot.Owner.intent.Err() != nil {
		t.Fatal("HTTP cancellation became a Disconnect intent")
	}
	var starts, stops int
	restoredCommand := &exec.Cmd{}
	actions := speedLabRestoreActions{
		stop: func(hold bool) error {
			stops++
			if !hold {
				t.Error("VPN restoration released transition protection")
			}
			return speedLabFakeStop(a, snapshot.Owner)(hold)
		},
		restart: func(plan speedLabRestorePlan) error {
			starts++
			if a.connectionOperationContextOrBackground().Err() != nil || plan.request.Mode != "wg" || plan.request.NodeID != "active-node" {
				t.Fatal("cancelled measurement context or AUTO selector reused for restore")
			}
			if a.profiles.SelectedID != "active-node" || !reflect.DeepEqual(a.profiles.Profiles, snapshot.Profiles.Profiles) {
				t.Fatal("restore did not use complete captured settings and credentials")
			}
			a.mu.Lock()
			a.cmd = restoredCommand
			a.state.Connected, a.state.Phase, a.state.RouterID = true, "connected", "active-node"
			a.mu.Unlock()
			return a.speedLabOwnRuntime(restoredCommand)
		}, persist: a.speedLabWriteStore, network: func() string { return snapshot.Owner.network },
	}
	if err := a.speedLabRestoreWith(snapshot, actions); err != nil {
		t.Fatal(err)
	}
	if starts != 1 || stops != 1 || a.cmd != restoredCommand || a.state != snapshot.State || !reflect.DeepEqual(a.profiles, snapshot.Profiles) {
		t.Fatalf("full restoration failed: starts=%d stops=%d state=%#v", starts, stops, a.state)
	}
	data, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	var durable common.RouterProfileStore
	if json.Unmarshal(data, &durable) != nil || !reflect.DeepEqual(durable, snapshot.Profiles) {
		t.Fatal("durable node store differs from the pre-test capture")
	}
	if err := a.speedLabRestoreWith(snapshot, actions); err != nil || starts != 1 || stops != 1 {
		t.Fatal("duplicate rollback restarted an already-restored VPN")
	}
	finish()
	newOwner, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.mu.Lock()
	a.connectionContext, a.connectionCancel = newOwner, cancel
	a.mu.Unlock()
	release()
	cancelRequest()
	if newOwner.Err() != nil {
		t.Fatal("late Speed Lab cancellation reached the replacement session")
	}
}

func TestSpeedLabExplicitDisconnectSuppressesPriorReconnect(t *testing.T) {
	a, snapshot, _ := speedLabRestorationFixture(t, true)
	speedLabFakeTemporaryRuntime(a, snapshot)
	a.cancelConnectionOperation()
	stops := 0
	err := a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: func(hold bool) error {
		stops++
		if hold {
			t.Error("Disconnect retained a transition intended for reconnection")
		}
		return speedLabFakeStop(a, snapshot.Owner)(hold)
	}, restart: func(speedLabRestorePlan) error { t.Fatal("Disconnect restarted the old connection"); return nil }, persist: a.speedLabWriteStore, network: func() string { return snapshot.Owner.network }})
	if err != nil || stops != 1 || a.cmd != nil || a.state.Connected || a.state.Phase != "off" || !reflect.DeepEqual(a.profiles, snapshot.Profiles) {
		t.Fatalf("Disconnect rollback was not an exact off-state restoration: %v %#v", err, a.state)
	}
}

func TestSpeedLabStaleRestoreCannotStopOrOverwriteReplacement(t *testing.T) {
	for _, replace := range []string{"runtime", "operation", "owner"} {
		t.Run(replace, func(t *testing.T) {
			a, snapshot, _ := speedLabRestorationFixture(t, true)
			speedLabFakeTemporaryRuntime(a, snapshot)
			replacement := &exec.Cmd{}
			switch replace {
			case "runtime":
				a.cmd = replacement
			case "operation":
				other, cancel := context.WithCancel(context.Background())
				defer cancel()
				a.connectionContext, a.connectionCancel = other, cancel
			case "owner":
				speedLabTemporaryOwners.Store(a, &speedLabTemporaryOwner{})
			}
			before, store, command := a.state, cloneRouterProfileStore(a.profiles), a.cmd
			unexpected := func() { t.Fatal("stale restore crossed a runtime or persistence boundary") }
			err := a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: func(bool) error { unexpected(); return nil }, restart: func(speedLabRestorePlan) error { unexpected(); return nil }, persist: func(common.RouterProfileStore) error { unexpected(); return nil }, network: func() string { unexpected(); return "" }})
			if err == nil || a.state != before || a.cmd != command || !reflect.DeepEqual(a.profiles, store) {
				t.Fatal("retired temporary operation changed the replacement")
			}
		})
	}
}

func TestSpeedLabCleanupFailureRetainsOwnerAndNeverClaimsRestore(t *testing.T) {
	a, snapshot, _ := speedLabRestorationFixture(t, true)
	temporary := speedLabFakeTemporaryRuntime(a, snapshot)
	failed := errors.New("native lease cleanup pending")
	err := a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: func(bool) error { return failed }, restart: func(speedLabRestorePlan) error { t.Fatal("restore began before cleanup completed"); return nil }, persist: a.speedLabWriteStore, network: func() string { return snapshot.Owner.network }})
	if !errors.Is(err, failed) || a.cmd != temporary || snapshot.Owner.restored || a.profiles.Profiles[0].APIToken != "temporary-credential" {
		t.Fatalf("failed cleanup pretended to restore: %v", err)
	}
}

func TestSpeedLabReplacementDuringTeardownCannotReceiveOldStore(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			a, snapshot, _ := speedLabRestorationFixture(t, true)
			speedLabFakeTemporaryRuntime(a, snapshot)
			replacement := &exec.Cmd{}
			err := a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: func(bool) error {
				other, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				a.connectionContext, a.connectionCancel, a.cmd = other, cancel, replacement
				a.profiles.Profiles[0].APIToken = "replacement-credential"
				if fail {
					return errors.New("late old cleanup failure")
				}
				return nil
			}, restart: func(speedLabRestorePlan) error { t.Fatal("restarted over replacement"); return nil }, persist: func(common.RouterProfileStore) error { t.Fatal("wrote old store after ownership changed"); return nil }, network: func() string { return snapshot.Owner.network }})
			if err == nil || a.cmd != replacement || a.profiles.Profiles[0].APIToken != "replacement-credential" {
				t.Fatal("old teardown corrupted a replacement connection")
			}
		})
	}
}

func TestSpeedLabRestoreRequiresFreshProofAndNetwork(t *testing.T) {
	for _, failure := range []string{"network-before", "network-after", "unproved", "proof-error", "persist-error"} {
		t.Run(failure, func(t *testing.T) {
			a, snapshot, _ := speedLabRestorationFixture(t, true)
			speedLabFakeTemporaryRuntime(a, snapshot)
			starts, stops, writes := 0, 0, 0
			err := a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: func(hold bool) error { stops++; return speedLabFakeStop(a, snapshot.Owner)(hold) }, restart: func(plan speedLabRestorePlan) error {
				starts++
				a.cmd = &exec.Cmd{}
				if err := a.speedLabOwnRuntime(a.cmd); err != nil {
					return err
				}
				if failure == "proof-error" {
					return errors.New("selected DNS/node proof failed")
				}
				if failure != "unproved" {
					a.state.Connected, a.state.Phase, a.state.RouterID = true, "connected", snapshot.State.RouterID
				}
				return nil
			}, persist: func(store common.RouterProfileStore) error {
				writes++
				if failure == "persist-error" {
					return errors.New("durable store unavailable")
				}
				return a.speedLabWriteStore(store)
			}, network: func() string {
				if failure == "network-before" || failure == "network-after" && starts > 0 {
					return "replacement-network"
				}
				return snapshot.Owner.network
			}})
			if err == nil || a.state.Connected || snapshot.Owner.restored || a.state.Phase != "failed" {
				t.Fatalf("failed restore became Connected: %v %#v", err, a.state)
			}
			if failure == "network-before" || failure == "persist-error" {
				if starts != 0 {
					t.Fatal("invalid restore started a VPN")
				}
			} else if stops != 2 {
				t.Fatal("unproved restore runtime was not drained")
			}
			if a.cmd != nil {
				t.Fatal("failed restore retained an unproved process after successful cleanup")
			}
		})
	}
}

func TestSpeedLabDisconnectedRestoreAndPersistenceGuardAreExact(t *testing.T) {
	a, snapshot, _ := speedLabRestorationFixture(t, false)
	speedLabFakeTemporaryRuntime(a, snapshot)
	if err := a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: speedLabFakeStop(a, snapshot.Owner), restart: func(speedLabRestorePlan) error { t.Fatal("previous off state started a VPN"); return nil }, persist: a.speedLabWriteStore, network: func() string { return snapshot.Owner.network }}); err != nil {
		t.Fatal(err)
	}
	if a.state != snapshot.State || !reflect.DeepEqual(a.profiles, snapshot.Profiles) {
		t.Fatal("previous disconnected state or private store changed")
	}
	first, err := beginSpeedLabTemporaryPersistenceGuard(a)
	if err != nil {
		t.Fatal(err)
	}
	first()
	second, err := beginSpeedLabTemporaryPersistenceGuard(a)
	if err != nil {
		t.Fatal(err)
	}
	defer second()
	first()
	if !speedLabTemporaryPersistenceSuppressed(a) {
		t.Fatal("stale persistence cleanup removed a newer transaction guard")
	}
}

func TestSpeedLabCapturedExternalRestoreRetainsWinnerAndRenewsLeaseKeys(t *testing.T) {
	profile := desktopLayerProfile(t, "shadowsocks", common.StartLayerAES256GCMXOR)
	profile.MultihopExecution = "auto"
	wg := nativeWG{PrivateKey: testWGKey('a'), PublicKey: testWGKey('b'), Host: "203.0.113.10", Port: 51820, Addresses: []string{"10.77.0.2/32"}, AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1280}
	nodeID, err := nodeProofIDFromWGConfig([]byte("[Interface]\nPrivateKey = " + wg.PrivateKey + "\nAddress = 10.77.0.2/32\n[Peer]\nPublicKey = " + wg.PublicKey + "\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\n"))
	if err != nil {
		t.Fatal(err)
	}
	entry := common.RouterProfile{ID: "entry-node", NodeKind: "router-vpn", Endpoint: wg.Host, NodeProofID: nodeID, RouterAPI: "http://10.77.0.1:8787", APIToken: strings.Repeat("a", 32), AdGuardIPv4: "10.77.0.1", SocksHost: "10.77.0.1", SocksPort: 1080, SocksUsername: "entry-user", SocksPassword: "entry-secret"}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := buildNativeStandardExitConfig(profile, wg, exit)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := compileDesktopExternalGraph(graph, profile, entry, exit, false, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, chosen := range []string{"local", "server"} {
		t.Run(chosen, func(t *testing.T) {
			saved := &speedLabExternalRestore{source: append([]byte(nil), initial.external.source...), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(entry), execution: chosen, root: t.TempDir(), network: "captured-network"}
			restored, err := compileSpeedLabExternalRestore(saved, exit)
			if err != nil {
				t.Fatal(err)
			}
			var old, fresh map[string]any
			if json.Unmarshal(initial.external.capture, &old) != nil || json.Unmarshal(restored.external.capture, &fresh) != nil {
				t.Fatal("invalid captured execution")
			}
			oldExecution, freshExecution := old["execution"].(map[string]any), fresh["execution"].(map[string]any)
			if freshExecution["selection"] != chosen || fresh["profile"].(map[string]any)["multihop_execution"] != "auto" || restored.external.selection != chosen {
				t.Fatal("restoration repeated Compare or changed the saved preference")
			}
			oldRequest, freshRequest := oldExecution["request"].(map[string]any), freshExecution["request"].(map[string]any)
			for _, key := range []string{"session_id", "listener_username", "listener_password"} {
				if oldRequest[key] == freshRequest[key] {
					t.Fatalf("restoration reused prior lease %s", key)
				}
			}
			if !reflect.DeepEqual(fresh["profile"].(map[string]any)["external"], old["profile"].(map[string]any)["external"]) || !reflect.DeepEqual(fresh["entry"], old["entry"]) {
				t.Fatal("restore substituted saved external/entry credentials or layer")
			}
		})
	}
	for _, changed := range []string{"missing-proof", "explicit-choice", "other-exit", "malformed-source"} {
		t.Run(changed, func(t *testing.T) {
			saved := &speedLabExternalRestore{source: append([]byte(nil), initial.external.source...), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(entry), execution: "server"}
			switch changed {
			case "missing-proof":
				saved.execution = "auto"
			case "explicit-choice":
				saved.profile.MultihopExecution = "local"
			case "other-exit":
				saved.profile.ID = "another-node"
			case "malformed-source":
				saved.source = []byte(`{"inbounds":[]}`)
			}
			if _, err := compileSpeedLabExternalRestore(saved, exit); err == nil {
				t.Fatal("invalid restore receipt was accepted")
			}
		})
	}
}

func TestSpeedLabLocalExternalRestoreDoesNotInventRelayCredentials(t *testing.T) {
	for _, protocol := range []string{"socks5", "http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			profile := desktopLayerProfile(t, protocol, common.StartLayerAES256GCMXOR)
			profile.MultihopExecution = "local"
			profile.External.ResponseProbe = nil
			switch protocol {
			case "socks5":
				profile.External.SOCKS5.Username, profile.External.SOCKS5.Password = "", ""
			case "http-connect":
				profile.External.HTTPConnect.Username, profile.External.HTTPConnect.Password = "", ""
			case "https-connect":
				profile.External.HTTPSConnect.Username, profile.External.HTTPSConnect.Password = "", ""
			}
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			graph, err := buildDirectStandardExitConfig(profile, exit)
			if err != nil {
				t.Fatal(err)
			}
			original, err := compileDesktopExternalGraph(graph, profile, common.RouterProfile{}, exit, true, "")
			if err != nil {
				t.Fatal(err)
			}
			saved := &speedLabExternalRestore{source: append([]byte(nil), original.external.source...), profile: cloneRouterProfile(original.external.profile), direct: true, execution: "local", network: "original-network"}
			restored, err := compileSpeedLabExternalRestore(saved, exit)
			if err != nil {
				t.Fatal(err)
			}
			var capture map[string]any
			if json.Unmarshal(restored.external.capture, &capture) != nil {
				t.Fatal("invalid restore capture")
			}
			if _, exists := capture["execution"]; exists {
				t.Fatal("anonymous Local restore fabricated a server relay proposal")
			}
			if restored.external.selection != "local" || !restored.external.direct || restored.external.expected.EntryProven {
				t.Fatal("Local direct restore gained an unrelated Router/server owner")
			}
		})
	}
}
