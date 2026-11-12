//go:build linux || darwin

package main

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// Reuses the actual complete source compiler and original pointer comparisons.
// This fixture has no started native process, PF or TUN proof. Its structurally
// valid capture MUST fail the public Current boundary; installed-host tests
// separately exercise the successful public Performance route with real peers.
func orderedPerformancePlatformFixture(t *testing.T, count int) (*mtuNodeChainComparisonFixture, speedLabPathIdentity, *mtuNodeChainSnapshot) {
	t.Helper()
	f := newMTUNodeChainComparisonFixture(t, count, true)
	if runtime.GOOS != "linux" {
		launch, err := newDesktopNodeChainLaunch(f.selection, f.launch.mtuSession, runtime.GOOS)
		if err != nil {
			t.Fatal(err)
		}
		launch.chain.capture, launch.chain.platform = f.launch.chain.capture, f.launch.chain.platform
		launch.command = f.launch.command
		f.launch, f.native.launch = launch, launch
	}
	meta := f.launch.chain.policy.Metadata()
	f.launch.chain.ready = &mobilemultihop.DesktopNodeChainReadyRecord{
		Identity: mobilemultihop.NodeChainIdentity{EngineID: "unstarted-native-boundary", SessionID: meta.SessionID,
			NetworkID: f.native.network, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256},
		Generation: 1, Reader: 1, MTU: 1400,
	}
	tracker := &sessionTracker{a: f.a, session: &connectionSession{ID: "ordered-performance-platform-comparison", Connected: true,
		Phase: "connected", PathProof: "passed", RouterID: f.selection.Exit.ID}}
	sessionTrackers.Store(f.a, tracker)
	identity := speedLabPathIdentity{Tracker: tracker, SessionID: tracker.session.ID,
		StateToken: mtuStateSnapshotToken(f.a.state), RouterID: f.a.state.RouterID, Graph: f.native.graph,
		GraphOK: true, Ordered: f.native, Command: f.launch.command, Network: f.native.network}
	captured, err := captureMTUNodeChainSnapshot(f.native)
	if err != nil {
		t.Fatal(err)
	}
	return f, identity, captured
}

func TestOrderedPerformancePlatformRetainsCompleteOriginalAssociations(t *testing.T) {
	for _, count := range []int{2, 3, 4, 8} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			f, identity, captured := orderedPerformancePlatformFixture(t, count)
			f.a.mu.Lock()
			err := validateOrderedPerformanceOwnerLocked(f.a, identity, captured)
			f.a.mu.Unlock()
			if err != nil || captured.Native != f.selection.Native || captured.Capture != f.selection.Native.chain.host ||
				len(captured.Native.chain.members) != count || captured.Launch != f.launch {
				t.Fatal("protected original ordered associations required the ordinary owner registry", err)
			}
			if _, present := desktopNodeOwners.Load(f.a); present {
				t.Fatal("protected comparison borrowed the ordinary native registry")
			}
			// A complete saved graph and cached shape cannot replace native proof.
			_, token, nodes, err := captureOrderedPerformanceContext(context.Background(), f.a)
			if err == nil || token != "" || nodes != 0 {
				t.Fatal("unstarted protected owner fabricated public Performance preflight")
			}
		})
	}
}

func TestOrderedPerformancePlatformRejectsReplacementAfterObservation(t *testing.T) {
	f, identity, captured := orderedPerformancePlatformFixture(t, 4)
	check := func() error {
		f.a.mu.Lock()
		defer f.a.mu.Unlock()
		return validateOrderedPerformanceOwnerLocked(f.a, identity, captured)
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	faults := []string{"runtime", "launch", "command", "launch-command", "chain", "platform", "capture", "policy",
		"native", "native-host", "sources", "source", "network", "config", "session", "graph", "middle",
		"ordinary-conflict", "closed-state", "state-generation", "foreign-platform"}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			var restore func()
			switch fault {
			case "runtime":
				nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
				restore = func() { nativeMultihopOwners.Store(f.a, f.native) }
			case "launch":
				f.native.launch = &desktopNodeLaunch{}
				restore = func() { f.native.launch = f.launch }
			case "command":
				f.a.cmd = &exec.Cmd{}
				restore = func() { f.a.cmd = identity.Command }
			case "launch-command":
				f.launch.command = &exec.Cmd{}
				restore = func() { f.launch.command = identity.Command }
			case "chain":
				f.launch.chain = &desktopNodeChainLaunch{}
				restore = func() { f.launch.chain = captured.Chain }
			case "platform":
				f.launch.chain.platform = &desktopNodeChainPlatformRuntime{}
				restore = func() { f.launch.chain.platform = captured.Platform }
			case "capture":
				f.launch.chain.capture = &desktopNodeChainHostCapture{}
				restore = func() { f.launch.chain.capture = captured.Capture }
			case "policy":
				foreign, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(f.launch.chain.input)
				if err != nil || foreign == captured.Policy {
					t.Fatal("same-source policy fixture was not independent", err)
				}
				f.launch.chain.policy = foreign
				restore = func() { f.launch.chain.policy = captured.Policy }
			case "native":
				f.native.selection.Native = &nativeMultihopCapture{}
				restore = func() { f.native.selection.Native = captured.Native }
			case "native-host":
				captured.Native.chain.host = &desktopNodeChainHostCapture{}
				restore = func() { captured.Native.chain.host = captured.Capture }
			case "sources":
				captured.Capture.sources = &desktopNodeChainSources{}
				restore = func() { captured.Capture.sources = captured.Sources }
			case "source":
				captured.Native.source += "-replacement"
				restore = func() { captured.Native.source = captured.Source }
			case "network":
				f.native.network += "-replacement"
				restore = func() { f.native.network = captured.Network }
			case "config":
				f.launch.configSHA256 += "-replacement"
				restore = func() { f.launch.configSHA256 = captured.Config }
			case "session":
				f.launch.mtuSession += "-replacement"
				restore = func() { f.launch.mtuSession = captured.Session }
			case "graph":
				graph := identity.Graph
				graph.SourceSHA = strings.Repeat("e", 64)
				activeMultihopGraphs.Store(f.a, graph)
				restore = func() { activeMultihopGraphs.Store(f.a, identity.Graph) }
			case "middle":
				original := cloneRouterProfile(f.a.profiles.Profiles[1])
				f.a.profiles.Profiles[1].APIToken += "-replacement"
				restore = func() { f.a.profiles.Profiles[1] = original }
			case "ordinary-conflict":
				desktopNodeOwners.Store(f.a, f.launch)
				restore = func() { desktopNodeOwners.Delete(f.a) }
			case "closed-state":
				f.a.state.Connected = false
				restore = func() { f.a.state.Connected = true }
			case "state-generation":
				original := f.a.state
				f.a.state.DAITA = !f.a.state.DAITA
				restore = func() { f.a.state = original }
			case "foreign-platform":
				foreign, err := newDesktopNodeChainLaunch(f.selection, f.launch.mtuSession, "windows")
				if err != nil {
					t.Fatal(err)
				}
				original := captured.Policy
				captured.Policy, f.launch.chain.policy = foreign.chain.policy, foreign.chain.policy
				restore = func() { captured.Policy, f.launch.chain.policy = original, original }
			}
			defer restore()
			if err := check(); err == nil {
				t.Fatal("protected Performance accepted a replaced original association", fault)
			}
		})
		if err := check(); err != nil {
			t.Fatal("fault fixture did not restore its original captured owner", fault, err)
		}
	}
}

func TestOrderedPerformancePreservesOrdinaryRegistryRequirement(t *testing.T) {
	f := newMTUNodeChainComparisonFixture(t, 3, false)
	identity := speedLabPathIdentity{StateToken: mtuStateSnapshotToken(f.a.state), RouterID: f.a.state.RouterID,
		Graph: f.native.graph, Ordered: f.native, Command: f.launch.command, Network: f.native.network}
	check := func() error {
		f.a.mu.Lock()
		defer f.a.mu.Unlock()
		return validateOrderedPerformanceOwnerLocked(f.a, identity, nil)
	}
	if err := check(); err != nil {
		t.Fatal("original ordinary registry rejected", err)
	}
	desktopNodeOwners.Delete(f.a)
	if err := check(); err == nil {
		t.Fatal("ordinary Performance used protected-host exception without its registry")
	}
	desktopNodeOwners.Store(f.a, &desktopNodeLaunch{})
	if err := check(); err == nil {
		t.Fatal("ordinary Performance adopted a foreign native owner")
	}
}
