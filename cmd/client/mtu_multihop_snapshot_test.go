package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

type retainedMultihopFixture struct {
	a         *app
	selection multihopSelection
	launch    *desktopNodeLaunch
	graph     activeMultihopGraph
	native    *nativeMultihopRuntime
	readback  desktopNodeMTURecord
}

func newRetainedMultihopFixture(t *testing.T, execution string) *retainedMultihopFixture {
	return newRetainedMultihopModeFixture(t, execution, "shadowsocks")
}

func newRetainedMultihopModeFixture(t *testing.T, execution, exitMode string) *retainedMultihopFixture {
	t.Helper()
	root, sel := nativeMultihopCapturedFixture(t, "awg2-strong", "aes-256-gcm+xor-whitening")
	sel.ExitMode = exitMode
	sel.Control.ID, sel.Control.StartLayer = "control", "off"
	sel.Control.MTUPolicy, sel.Control.ManualMTU, sel.Control.EffectiveMTU = "manual", 1500, 1500
	sel.Entry.MTUPolicy, sel.Entry.ManualMTU, sel.Entry.EffectiveMTU = "manual", 1500, 1500
	sel.Exit.MTUPolicy, sel.Exit.ManualMTU, sel.Exit.EffectiveMTU, sel.Exit.EffectiveUnderlayPMTU = "auto", 0, 1300, 1400
	sel.Control.MultihopEnabled, sel.Control.MultihopEntryID, sel.Control.MultihopExitID, sel.Control.MultihopExecution = true, sel.Entry.ID, sel.Exit.ID, "auto"
	var err error
	sel, err = captureNativeMultihopSelection(context.Background(), root, sel, []string{exitMode, "hysteria2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor *desktopExecutionDescriptor
	if execution == "server" {
		_, value := executionFixture()
		value.Lease.ExitMode, value.Lease.ExitStartLayer = sel.ExitMode, sel.Exit.StartLayer
		descriptor = &value
	}
	launch, err := compileRetainedNativeMultihopLaunch(sel, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ScriptsDir: filepath.Join(root, "modes")},
		profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: sel.Control.ID, Profiles: []common.RouterProfile{sel.Control, sel.Entry, sel.Exit}},
		state:    state{Connected: true, Phase: "connected", Mode: "multihop", LogicalMode: "multihop", RuntimeMode: sel.ExitMode, Base: sel.Base, RouterID: sel.Exit.ID}}
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	if err := stageOwnedNativeMultihopCommand(a, sel, launch); err != nil {
		t.Fatal(err)
	}
	a.cmd = launch.command
	desktopNodeOwners.Store(a, launch)
	setActiveMultihopGraph(a, sel)
	graph, _ := getActiveMultihopGraph(a)
	graph.Execution = execution
	activeMultihopGraphs.Store(a, graph)
	if err := bindNativeMultihopRuntime(a, launch, sel, physicalNetworkIdentity()); err != nil {
		t.Fatal(err)
	}
	raw, _ := nativeMultihopOwners.Load(a)
	owner := raw.(*nativeMultihopRuntime)
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "retained-multihop-session", RouterID: sel.Exit.ID, ActualMode: sel.ExitMode, ActualBase: sel.Base, Phase: "connected", Connected: true, PathProof: "passed", DNSProof: dnsProofState{Status: "passed"}}})
	if execution == "server" {
		request := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: sel.Entry.NodeProofID, ExitID: sel.Exit.ID, ExitMode: sel.ExitMode, ExitStartLayer: sel.Exit.StartLayer}
		relay := &desktopRelayOwner{app: a, command: launch.command, entry: sel.Entry, request: request, renewed: true, expected: multihoprelay.Lease{Request: request, NodeID: sel.Entry.NodeProofID, ExitNodeID: sel.Exit.NodeProofID, ExpiresAt: time.Now().Add(time.Minute)}}
		if mobilemultihop.NodeMultihopPacketExitMode(exitMode) {
			relay.localPacketPublic, relay.serverPacketPublic = sel.Native.localPacketPublic[exitMode], testWGKey('z')
			relay.request.ExpectedPacketPublicKey, relay.packetCapabilityReady = relay.serverPacketPublic, true
			if mobilemultihop.IsPQMode(exitMode) {
				relay.localPQIdentity, relay.serverPQIdentity = sel.Native.localPQIdentity[exitMode], strings.Repeat("e", 64)
				relay.request.ExpectedPQClientIdentity = relay.serverPQIdentity
			}
			relay.expected.Request = relay.request
		}
		desktopRelays.Store(a, relay)
	}
	f := &retainedMultihopFixture{a: a, selection: sel, launch: launch, graph: graph, native: owner,
		readback: desktopNodeMTURecord{Schema: 1, Session: launch.mtuSession, Config: launch.configSHA256, Path: strings.Repeat("d", 64), Reader: 2, Interface: "router-vpn", Index: 7, MTU: 1360}}
	if mobilemultihop.NodeMultihopPacketExitMode(exitMode) {
		f.readback.MTU = 1280
	}
	f.publish(t, f.readback)
	t.Cleanup(func() {
		sessionTrackers.Delete(a)
		desktopRelays.Delete(a)
		nativeMultihopOwners.Delete(a)
		desktopNodeOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
		activeDNSRuntimeIdentities.Delete(a)
		mtuRetestLocks.Delete(a)
		routerNodeAutomaticMTUs.Delete(a)
		_ = retireUnstartedNativeMultihop(launch)
	})
	return f
}

func (f *retainedMultihopFixture) publish(t *testing.T, r desktopNodeMTURecord) {
	t.Helper()
	fixture := &desktopNodeMTUFixture{launch: f.launch}
	if err := fixture.publish(r, false); err != nil {
		t.Fatal(err)
	}
}

func TestMTUMultihopSnapshotKeepsExitMeasurementSeparateFromEntryAndControl(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			f := newRetainedMultihopFixture(t, execution)
			snapshot, err := captureMTURetestSnapshot(f.a)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Profile.ID != "exit" || snapshot.SelectedID != "control" || snapshot.Multihop.Entry.ID != "entry" || snapshot.Multihop.Graph.Execution != execution || len(snapshot.Multihop.Token) != 64 {
				t.Fatal("measurement identities were conflated")
			}
			environment := strings.Join(mtuRetestEnvironment(f.launch.root, snapshot.Profile, snapshot.State, snapshot.Mode, snapshot), "\n")
			for _, want := range []string{"HOMEVPN_PROFILE_ID=exit", "HOMEVPN_MTU_GRAPH_SCOPE=multihop-exit-path", "HOMEVPN_MTU_CONTROL_PROFILE_ID=control", "HOMEVPN_MTU_PHYSICAL_ENTRY_ID=entry", "HOMEVPN_MTU_PHYSICAL_ENTRY_ENDPOINT=" + f.launch.endpoint, "HOMEVPN_MTU_GRAPH_TOKEN=" + snapshot.Multihop.Token} {
				if !strings.Contains(environment, want) {
					t.Fatal("missing captured path context", want)
				}
			}
			if strings.Contains(environment, "HOMEVPN_MTU_MAXIMUM=") {
				t.Fatal("unmeasured entry capacity was claimed as exit PMTU")
			}
			previous := cloneRouterProfileStore(f.a.profiles)
			updated, err := persistMTUMeasurement(f.a, snapshot, testMTUMeasurement())
			if err != nil {
				t.Fatal(err)
			}
			if updated.ID != "exit" || updated.EffectiveMTU != 1380 || updated.EffectiveMTUSource != "auto-throughput-multihop-exit-path" || updated.EffectiveUnderlayPMTU != 0 {
				t.Fatal("exit-path result has incorrect scope", updated.EffectiveMTUSource)
			}
			for _, id := range []string{"control", "entry"} {
				before, _ := profileByID(previous.Profiles, id)
				after, _ := profileByID(f.a.profiles.Profiles, id)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("exit measurement changed another node", id)
				}
			}
			if err := validateMTURetestSnapshot(f.a, snapshot); err != nil {
				t.Fatal("owned persistence invalidated current capture", err)
			}
			if err := restoreMTUMeasurementFields(f.a, snapshot); err != nil {
				t.Fatal(err)
			}
			after, _ := profileByID(f.a.profiles.Profiles, "exit")
			before, _ := profileByID(previous.Profiles, "exit")
			if mtuMeasurementFieldsDigest(after) != mtuMeasurementFieldsDigest(before) {
				t.Fatal("rollback lost exact exit measurement baseline")
			}
		})
	}
}

func TestMTUMultihopSnapshotRejectsEveryReplacedPathOwner(t *testing.T) {
	for _, change := range []string{"selected-control", "control-policy", "entry-credentials", "exit-DNS", "fixed-exit", "graph-start", "execution-winner", "entry-mode", "source", "command", "native-owner", "tun-owner", "network", "source-asset", "session", "relay-owner", "relay-expired", "relay-wrong-exit"} {
		t.Run(change, func(t *testing.T) {
			f := newRetainedMultihopFixture(t, "server")
			snapshot, err := captureMTURetestSnapshot(f.a)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "selected-control":
				f.a.profiles.SelectedID = "entry"
			case "control-policy":
				f.a.profiles.Profiles[0].HomeLANAccess = !f.a.profiles.Profiles[0].HomeLANAccess
			case "entry-credentials":
				f.a.profiles.Profiles[1].APIToken = "replacement-token"
			case "exit-DNS":
				f.a.profiles.Profiles[2].AdGuardIPv4 = "10.88.0.54"
			case "fixed-exit":
				f.a.profiles.Profiles[2].MTUPolicy = "manual"
			case "graph-start", "execution-winner", "entry-mode", "source":
				g := f.graph
				switch change {
				case "graph-start":
					g.Started = g.Started.Add(time.Nanosecond)
				case "execution-winner":
					g.Execution = "local"
				case "entry-mode":
					g.EntryMode = "awg2-fast"
				case "source":
					g.SourceSHA = strings.Repeat("f", 64)
				}
				activeMultihopGraphs.Store(f.a, g)
			case "command":
				f.a.cmd = &exec.Cmd{}
			case "native-owner":
				nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
			case "tun-owner":
				desktopNodeOwners.Store(f.a, &desktopNodeLaunch{})
			case "network":
				f.native.network = "replaced-network"
			case "source-asset":
				path := filepath.Join(f.launch.root, "generated", "entry", "awg2-strong", "awg.conf")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "session":
				sessionTrackerFor(f.a).session.ID = "replacement-session"
			case "relay-owner":
				desktopRelays.Store(f.a, &desktopRelayOwner{})
			case "relay-expired":
				raw, _ := desktopRelays.Load(f.a)
				raw.(*desktopRelayOwner).expected.ExpiresAt = time.Now().Add(-time.Second)
			case "relay-wrong-exit":
				raw, _ := desktopRelays.Load(f.a)
				raw.(*desktopRelayOwner).expected.ExitNodeID = strings.Repeat("e", 64)
			}
			if err := validateMTURetestSnapshot(f.a, snapshot); err == nil {
				t.Fatal("stale multihop capture accepted", change)
			}
			if _, err := persistMTUMeasurement(f.a, snapshot, testMTUMeasurement()); err == nil {
				t.Fatal("stale multihop result persisted", change)
			}
		})
	}
}

func TestMTUMultihopRollbackDoesNotReplaceNewerMeasurement(t *testing.T) {
	f := newRetainedMultihopFixture(t, "local")
	snapshot, err := captureMTURetestSnapshot(f.a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistMTUMeasurement(f.a, snapshot, testMTUMeasurement()); err != nil {
		t.Fatal(err)
	}
	f.a.profiles.Profiles[2].EffectiveMTU, f.a.profiles.Profiles[2].EffectiveMTUPathKey = 1400, "replacement-measurement"
	if err := restoreMTUMeasurementFields(f.a, snapshot); err == nil {
		t.Fatal("retired rollback replaced a newer saved measurement")
	}
	if f.a.profiles.Profiles[2].EffectiveMTU != 1400 {
		t.Fatal("replacement was mutated")
	}
}

func TestMTUMultihopNativeDNSFallbackUsesExactRetainedGraph(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux retained multihop fallback")
	}
	f := newRetainedMultihopFixture(t, "local")
	clearActiveDNSRuntimeConfig(f.a)
	got, owned, err := activeDNSRuntimeConfigFor(f.a, "exit", f.selection.ExitMode)
	if err != nil || !owned || got != filepath.Join(f.launch.directory, "sing-box.json") {
		t.Fatal("DNS fallback did not retain actual graph", got, owned, err)
	}
	f.a.cmd = &exec.Cmd{}
	if _, owned, err := activeDNSRuntimeConfigFor(f.a, "exit", f.selection.ExitMode); !owned || err == nil {
		t.Fatal("DNS fallback followed a replacement process")
	}
}

func TestMTUMultihopActualCapabilityDrainsOnlyCapturedTUNAfterWinnerChanges(t *testing.T) {
	f := newRetainedMultihopFixture(t, "server")
	snapshot, err := captureMTURetestSnapshot(f.a)
	if err != nil {
		t.Fatal(err)
	}
	child := &desktopNodeMTUFixture{launch: f.launch, base: f.readback}
	commands := startDesktopNodeMTUFixtureChild(t, child, nil)
	owner, err := captureMTULiveOwner(f.a, snapshot, mtuLiveSnapshot{Interface: f.readback.Interface, Family: 4, OriginalMTU: f.readback.MTU})
	if err != nil || owner == nil {
		t.Fatal("captured multihop capability failed", err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
		mtuLiveOwners.Delete(f.a)
	})
	code, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1380}`)
	if err != nil || code != http.StatusOK {
		t.Fatal("actual owned multihop mutation failed", code, err)
	}
	graph := f.graph
	graph.Execution = "local"
	activeMultihopGraphs.Store(f.a, graph)
	code, _, err = mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1400}`)
	if err != nil || code != http.StatusConflict {
		t.Fatal("retired capability followed another winner", code, err)
	}
	if err := owner.Commit(); err == nil {
		t.Fatal("retired graph committed a measurement")
	}
	if err := owner.Close(); err != nil {
		t.Fatal("old native lease could not drain safely", err)
	}
	r, err := readDesktopNodeMTU(f.launch)
	if err != nil || r.Active || !r.Restored || r.MTU != f.readback.MTU {
		t.Fatal("retired operation lost exact original MTU", r, err)
	}
	if got, _ := getActiveMultihopGraph(f.a); got != graph {
		t.Fatal("retired cleanup replaced graph selection")
	}
	for _, expected := range []string{"begin", "set", "rollback"} {
		select {
		case command := <-commands:
			if command.Action != expected {
				t.Fatal("wrong native action", command.Action, expected)
			}
		case <-time.After(time.Second):
			t.Fatal("captured native command did not drain", expected)
		}
	}
	select {
	case command := <-commands:
		t.Fatal("stale capability issued another native command", command.Action)
	default:
	}
}
