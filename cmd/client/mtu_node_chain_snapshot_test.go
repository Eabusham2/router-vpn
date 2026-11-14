package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"router-vpn/internal/common"
)

// This model exercises complete source construction and retained-object/state
// comparisons only. It has no created child, active native owner, OS interface
// or readiness proof, and cannot pass the full native Current boundary.
type mtuNodeChainComparisonFixture struct {
	a         *app
	selection multihopSelection
	launch    *desktopNodeLaunch
	native    *nativeMultihopRuntime
	snapshot  mtuRetestSnapshot
}

func newMTUNodeChainComparisonFixture(t *testing.T, count int, platform bool) *mtuNodeChainComparisonFixture {
	t.Helper()
	a, selection := desktopNodeChainHostSelectionFixture(t, count)
	sources, err := captureDesktopNodeChainSourcesLocked(a, selection)
	if err != nil {
		t.Fatal(err)
	}
	capture := &desktopNodeChainHostCapture{app: a, sources: sources, network: "original-mtu-comparison-network"}
	if platform {
		capture.platform = &desktopNodeChainPlatformCapture{}
	} else {
		capture.windows = &desktopNodeConnectionOwner{}
	}
	selection.Native.chain.host = capture
	target := "windows"
	if platform {
		target = "linux"
	}
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	launch.chain.capture = capture
	if platform {
		launch.chain.platform = &desktopNodeChainPlatformRuntime{}
	} else {
		launch.ownedNode = &desktopOwnedNodeRuntime{chain: launch.chain}
	}
	launch.command = &exec.Cmd{Path: "unstarted-ordered-mtu-comparison"}
	a.cmd = launch.command
	a.state = state{Connected: true, Phase: "connected", Mode: "multihop", LogicalMode: "multihop",
		RuntimeMode: selection.ExitMode, Base: selection.Base, RouterID: selection.Exit.ID}
	setActiveMultihopGraph(a, selection)
	graph, _ := getActiveMultihopGraph(a)
	owner := &nativeMultihopRuntime{launch: launch, selection: selection, graph: graph, network: capture.network}
	nativeMultihopOwners.Store(a, owner)
	if !platform {
		desktopNodeOwners.Store(a, launch)
	}
	path := &mtuMultihopSnapshot{Graph: graph, Control: cloneRouterProfile(selection.Control), Entry: cloneRouterProfile(selection.Entry),
		ControlToken: mtuProfileSnapshotToken(selection.Control), EntryToken: mtuProfileSnapshotToken(selection.Entry),
		PhysicalEntry: launch.endpoint, Native: owner, Command: launch.command}
	path.Chain, err = captureMTUNodeChainSnapshot(owner)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mtuRetestSnapshot{SessionID: "ordered-mtu-state-comparison", SelectedID: selection.Control.ID,
		ProfileToken: mtuProfileSnapshotToken(selection.Exit), StateToken: mtuStateSnapshotToken(a.state),
		Profile: cloneRouterProfile(selection.Exit), State: a.state, Mode: selection.ExitMode,
		Multihop: path, persistence: &mtuMeasurementPersistence{}}
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: snapshot.SessionID}})
	t.Cleanup(func() {
		sessionTrackers.Delete(a)
		nativeMultihopOwners.Delete(a)
		desktopNodeOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
		mtuLiveOwners.Delete(a)
	})
	return &mtuNodeChainComparisonFixture{a, selection, launch, owner, snapshot}
}

func TestMTUNodeChainSnapshotRetainsEveryOriginalMember(t *testing.T) {
	for _, count := range []int{2, 3, 4, 8} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			f := newMTUNodeChainComparisonFixture(t, count, false)
			if err := validateMTURetestSnapshotState(f.a, f.snapshot); err != nil {
				t.Fatal("complete ordered comparison lost its retained capture", err)
			}
			captured := f.snapshot.Multihop.Chain
			if captured.Native != f.selection.Native || captured.Chain != f.launch.chain ||
				captured.Sources != f.selection.Native.chain.host.sources || captured.Policy != f.launch.chain.policy ||
				captured.Source != f.selection.Native.source || captured.Network != f.native.network ||
				len(captured.Native.chain.members) != count || f.snapshot.Profile.ID != f.selection.Nodes[count-1].Profile.ID {
				t.Fatal("ordered MTU snapshot reduced the graph or replaced its original final member")
			}
			for index := range f.selection.Nodes {
				t.Run(string(rune('0'+index)), func(t *testing.T) {
					f.a.mu.Lock()
					catalogIndex := -1
					for i := range f.a.profiles.Profiles {
						if f.a.profiles.Profiles[i].ID == f.selection.Nodes[index].Profile.ID {
							catalogIndex = i
						}
					}
					if catalogIndex < 0 {
						f.a.mu.Unlock()
						t.Fatal("original ordered member is missing from its test catalog")
					}
					before := cloneRouterProfile(f.a.profiles.Profiles[catalogIndex])
					f.a.profiles.Profiles[catalogIndex].APIToken += "-replaced"
					f.a.mu.Unlock()
					err := validateMTURetestSnapshotState(f.a, f.snapshot)
					f.a.mu.Lock()
					f.a.profiles.Profiles[catalogIndex] = before
					f.a.mu.Unlock()
					if err == nil {
						t.Fatal("a changed middle or final member survived original MTU capture")
					}
				})
			}
		})
	}
}

func TestMTUNodeChainSnapshotRejectsRetainedOwnerReplacement(t *testing.T) {
	for _, fault := range []string{
		"runtime", "launch", "command", "chain", "native", "policy", "capture", "sources", "network",
		"capture-network", "source", "config", "session", "platform", "graph-order", "selected",
		"missing-windows", "foreign-windows", "missing-ordered-snapshot",
	} {
		t.Run(fault, func(t *testing.T) {
			f := newMTUNodeChainComparisonFixture(t, 4, false)
			captured := f.snapshot.Multihop.Chain
			switch fault {
			case "runtime":
				nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
			case "launch":
				f.native.launch = &desktopNodeLaunch{}
			case "command":
				f.a.cmd = &exec.Cmd{Path: "replacement"}
			case "chain":
				f.launch.chain = &desktopNodeChainLaunch{}
			case "native":
				f.native.selection.Native = &nativeMultihopCapture{}
			case "policy":
				f.launch.chain.policy = nil
			case "capture":
				f.launch.chain.capture = &desktopNodeChainHostCapture{}
			case "sources":
				captured.Capture.sources = &desktopNodeChainSources{}
			case "network":
				f.native.network += "-replacement"
			case "capture-network":
				captured.Capture.network += "-replacement"
			case "source":
				captured.Native.source += "-replacement"
			case "config":
				f.launch.configSHA256 += "-replacement"
			case "session":
				f.launch.mtuSession += "-replacement"
			case "platform":
				f.launch.chain.platform = &desktopNodeChainPlatformRuntime{}
			case "graph-order":
				graph := f.snapshot.Multihop.Graph
				graph.SourceSHA += "-reordered"
				activeMultihopGraphs.Store(f.a, graph)
			case "selected":
				f.a.profiles.SelectedID = f.selection.Entry.ID
			case "missing-windows":
				desktopNodeOwners.Delete(f.a)
			case "foreign-windows":
				desktopNodeOwners.Store(f.a, &desktopNodeLaunch{})
			case "missing-ordered-snapshot":
				f.snapshot.Multihop.Chain = nil
			}
			if err := validateMTURetestSnapshotState(f.a, f.snapshot); err == nil {
				t.Fatal("ordered MTU comparison accepted a substituted original owner", fault)
			}
		})
	}
}

func TestMTUNodeChainPlatformSnapshotKeepsSeparateRegistryAndRefusesFallback(t *testing.T) {
	f := newMTUNodeChainComparisonFixture(t, 3, true)
	if err := validateMTURetestSnapshotState(f.a, f.snapshot); err != nil {
		t.Fatal("ordered platform state required a second ordinary TUN registry", err)
	}
	desktopNodeOwners.Store(f.a, f.launch)
	if err := validateMTURetestSnapshotState(f.a, f.snapshot); err == nil {
		t.Fatal("ordered platform borrowed an ordinary process owner")
	}
	desktopNodeOwners.Delete(f.a)
	if _, err := captureMTUConnectionSnapshot(f.a, f.snapshot); err == nil ||
		!strings.Contains(err.Error(), "original platform host") {
		t.Fatal("missing actual platform capture fell through to an ambient route", err)
	}
	if owner, err := captureMTULiveOwner(f.a, f.snapshot,
		mtuLiveSnapshot{Interface: "router-vpn", Family: 4, OriginalMTU: 1280}); err == nil || owner != nil ||
		!strings.Contains(err.Error(), "original platform host") {
		t.Fatal("missing actual platform lease fell through to an ambient kernel writer", err)
	}
	if _, exists := mtuLiveOwners.Load(f.a); exists {
		t.Fatal("refused ordered platform created a replacement MTU owner")
	}
}

// Called from the existing three/four-node owned lifecycle fixture after its
// actual staged/start/proof path. Its OS/controller/child are explicit modeled
// boundaries; the public snapshot, source checks and owner capture are shipping
// functions. Reuse avoids repeating the expensive existing startup fixture.
func assertMTUNodeChainProvedCapture(t *testing.T, f *desktopNodeChainOwnedFixture) {
	t.Helper()
	a := f.a
	a.mu.Lock()
	before := a.state
	beforeProfiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	a.state.Connected, a.state.Phase = true, "connected"
	a.mu.Unlock()
	oldTracker, hadTracker := sessionTrackers.Load(a)
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{
		ID: "proved-ordered-mtu-session", RouterID: f.selection.Exit.ID, ActualMode: f.selection.ExitMode,
		ActualBase: f.selection.Base, Phase: "connected", Connected: true, PathProof: "passed"}})
	observe := f.capture.readNetwork
	var observations atomic.Int32
	f.capture.readNetwork = func(ctx context.Context) (string, error) {
		if _, bounded := ctx.Deadline(); !bounded {
			return "", errors.New("ordered MTU native observation lost its bounded context")
		}
		if !a.mu.TryLock() {
			return "", errors.New("ordered MTU native observation reentered app.mu")
		}
		a.mu.Unlock()
		observations.Add(1)
		return observe(ctx)
	}
	defer func() {
		f.capture.readNetwork = observe
		a.mu.Lock()
		a.state = before
		a.profiles.Profiles = beforeProfiles
		a.mu.Unlock()
		if hadTracker {
			sessionTrackers.Store(a, oldTracker)
		} else {
			sessionTrackers.Delete(a)
		}
	}()
	snapshot, err := captureMTURetestSnapshot(a)
	if err != nil {
		t.Fatal("proved complete graph failed public MTU snapshot", err)
	}
	if snapshot.Multihop == nil || snapshot.Multihop.Chain == nil ||
		snapshot.Multihop.Native.launch != f.launch || snapshot.Multihop.Chain.Native != f.selection.Native ||
		snapshot.Multihop.Chain.Policy != f.launch.chain.policy || snapshot.Multihop.Chain.SOCKSPolicy != f.launch.chain.socksPolicy || snapshot.Multihop.Chain.CONNECTPolicy != f.launch.chain.connectPolicy || snapshot.Profile.ID != f.selection.Exit.ID ||
		snapshot.SelectedID != f.selection.Control.ID || observations.Load() == 0 {
		t.Fatal("public MTU snapshot did not retain its original complete proof owner")
	}
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		t.Fatal("original ordered MTU snapshot changed during bounded revalidation", err)
	}
	if snapshot.Multihop.Chain.Platform != nil {
		t.Fatal("modeled Windows owner was relabeled as a platform host")
	}
	// The source/control identity survives only measurement-field updates.
	a.mu.Lock()
	control, _ := a.profileByIDLocked(snapshot.SelectedID)
	control.EffectiveMTU++
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == control.ID {
			a.profiles.Profiles[i] = common.CloneRouterProfile(control)
		}
	}
	a.mu.Unlock()
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		t.Fatal("measurement metadata replaced the original ordered source", err)
	}
	// Use a middle member's actual original asset, not only a profile token.
	// Restore it before returning so the existing retirement test is unchanged.
	if f.launch.chain.socksPolicy != nil {
		a.mu.Lock()
		original := common.CloneRouterProfile(a.profiles.Profiles[1])
		a.profiles.Profiles[1].External.SOCKS5.Password += "-foreign-restoration"
		a.mu.Unlock()
		err := validateMTURetestSnapshot(a, snapshot)
		a.mu.Lock()
		a.profiles.Profiles[1] = original
		a.mu.Unlock()
		if err == nil {
			t.Fatal("typed MTU restore adopted changed original SOCKS credential")
		}
		if err := validateMTURetestSnapshot(a, snapshot); err != nil {
			t.Fatal("original typed MTU source could not be restored", err)
		}
		return
	}
	if f.launch.chain.connectPolicy != nil {
		a.mu.Lock()
		original := common.CloneRouterProfile(a.profiles.Profiles[1])
		a.profiles.Profiles[1].External.HTTPSConnect.Password += "-foreign-restoration"
		a.mu.Unlock()
		err := validateMTURetestSnapshot(a, snapshot)
		a.mu.Lock()
		a.profiles.Profiles[1] = original
		a.mu.Unlock()
		if err == nil {
			t.Fatal("typed MTU restore adopted changed original CONNECT credential")
		}
		if err := validateMTURetestSnapshot(a, snapshot); err != nil {
			t.Fatal("original typed MTU source could not be restored", err)
		}
		return
	}
	path := filepath.Join(clientRoot(a), "generated", f.selection.Nodes[1].Profile.ID, "wg", "wg.conf")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte(nil), raw...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	staleErr := validateMTURetestSnapshot(a, snapshot)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if staleErr == nil {
		t.Fatal("public ordered MTU revalidation ignored a replaced middle private source")
	}
}
