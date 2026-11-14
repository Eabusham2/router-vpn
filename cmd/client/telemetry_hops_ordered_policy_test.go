//go:build linux || darwin

package main

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func orderedPerformanceFamilySelection(t *testing.T, family string) (*app, multihopSelection) {
	t.Helper()
	if family == "ordinary" {
		return desktopNodeChainHostSelectionFixture(t, 3)
	}
	var a *app
	var nodes []common.MultihopNodeSelection
	if family == "socks5" {
		a, nodes = desktopSOCKSCaptureFixture(t, "wg", "password", "off")
	} else {
		a, nodes = desktopCONNECTCaptureFixture(t, "wg", "password", "off")
		if family == "http-connect" {
			middle := &a.profiles.Profiles[1]
			proxy := *middle.External.HTTPSConnect
			proxy.TLSServerName = ""
			middle.External.Protocol, middle.External.HTTPSConnect, middle.External.HTTPConnect = family, nil, &proxy
			nodes[1].Mode = family
			a.profiles.Profiles[2].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
		} else if family != "https-connect" {
			t.Fatal("unknown original Performance family")
		}
	}
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, selection
}

// Complete source and exact pointer comparisons only. This intentionally has
// no launched process, physical interface, or native Current/proof authority.
func orderedPerformanceFamilySnapshot(t *testing.T, family string) (*mtuNodeChainComparisonFixture, speedLabPathIdentity, *mtuNodeChainSnapshot) {
	t.Helper()
	a, selection := orderedPerformanceFamilySelection(t, family)
	sources, err := captureDesktopNodeChainSourcesLocked(a, selection)
	if err != nil {
		t.Fatal(err)
	}
	capture := &desktopNodeChainHostCapture{app: a, sources: sources, network: "original-family-performance-network", platform: &desktopNodeChainPlatformCapture{}}
	selection.Native.chain.host = capture
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	launch.chain.capture, launch.chain.platform = capture, &desktopNodeChainPlatformRuntime{}
	launch.command = &exec.Cmd{Path: "unstarted-original-family-performance"}
	a.cmd = launch.command
	a.state = state{Connected: true, Phase: "connected", Mode: "multihop", LogicalMode: "multihop", RuntimeMode: selection.ExitMode, Base: selection.Base, RouterID: selection.Exit.ID}
	setActiveMultihopGraph(a, selection)
	graph, _ := getActiveMultihopGraph(a)
	owner := &nativeMultihopRuntime{launch: launch, selection: selection, graph: graph, network: capture.network}
	nativeMultihopOwners.Store(a, owner)
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "original-family-performance-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: selection.Exit.ID}}
	sessionTrackers.Store(a, tracker)
	identity := speedLabPathIdentity{Tracker: tracker, SessionID: tracker.session.ID, StateToken: mtuStateSnapshotToken(a.state), RouterID: a.state.RouterID,
		Graph: graph, GraphOK: true, Ordered: owner, Command: launch.command, Network: owner.network}
	captured, err := captureMTUNodeChainSnapshot(owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sessionTrackers.Delete(a)
		nativeMultihopOwners.Delete(a)
		desktopNodeOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
	})
	return &mtuNodeChainComparisonFixture{a: a, selection: selection, launch: launch, native: owner}, identity, captured
}

func TestOrderedPerformanceTypedSnapshotRetainsOriginalFamilies(t *testing.T) {
	for _, family := range []string{"ordinary", "socks5", "http-connect", "https-connect"} {
		t.Run(family, func(t *testing.T) {
			f, identity, captured := orderedPerformanceFamilySnapshot(t, family)
			if got := orderedPerformanceSnapshotTarget(captured); got != runtime.GOOS {
				t.Fatal("retained Performance policy lost its original target", family, got)
			}
			f.a.mu.Lock()
			err := validateOrderedPerformanceOwnerLocked(f.a, identity, captured)
			f.a.mu.Unlock()
			if err != nil {
				t.Fatal("original concrete Performance family was refused", family, err)
			}
			if family != "ordinary" && captured.Policy != nil || family == "socks5" && captured.SOCKSPolicy == nil || strings.HasSuffix(family, "connect") && captured.CONNECTPolicy == nil {
				t.Fatal("typed Performance snapshot acquired ordinary authority")
			}
			// Retained source equality cannot replace the actual platform owner.
			if _, token, count, err := captureOrderedPerformanceContext(context.Background(), f.a); err == nil || token != "" || count != 0 {
				t.Fatal("unstarted typed source fabricated a public Performance capture")
			}
		})
	}
}

func TestOrderedPerformanceTypedSnapshotRejectsReplacedOwners(t *testing.T) {
	for _, family := range []string{"ordinary", "socks5", "http-connect", "https-connect"} {
		t.Run(family, func(t *testing.T) {
			f, identity, captured := orderedPerformanceFamilySnapshot(t, family)
			otherFamily := "ordinary"
			if family == "ordinary" {
				otherFamily = "socks5"
			}
			other, _, _ := orderedPerformanceFamilySnapshot(t, otherFamily)
			check := func() error {
				f.a.mu.Lock()
				defer f.a.mu.Unlock()
				return validateOrderedPerformanceOwnerLocked(f.a, identity, captured)
			}
			for _, fault := range []string{"missing-policy", "mixed-policy", "copied-policy", "snapshot-policy", "chain", "native-source", "network", "command", "registry", "middle", "foreign-target"} {
				t.Run(fault, func(t *testing.T) {
					chain := f.launch.chain
					policy, socks, connect := chain.policy, chain.socksPolicy, chain.connectPolicy
					defer func() {
						chain.policy, chain.socksPolicy, chain.connectPolicy = policy, socks, connect
						captured.Policy, captured.SOCKSPolicy, captured.CONNECTPolicy = policy, socks, connect
					}()
					switch fault {
					case "missing-policy":
						chain.policy, chain.socksPolicy, chain.connectPolicy = nil, nil, nil
						captured.Policy, captured.SOCKSPolicy, captured.CONNECTPolicy = nil, nil, nil
					case "mixed-policy":
						if family == "ordinary" {
							chain.socksPolicy, captured.SOCKSPolicy = other.launch.chain.socksPolicy, other.launch.chain.socksPolicy
						} else {
							chain.policy, captured.Policy = other.launch.chain.policy, other.launch.chain.policy
						}
					case "copied-policy":
						var err error
						if policy != nil {
							chain.policy, err = mobilemultihop.ParseDesktopNodeChainLaunchInput(chain.input)
							captured.Policy = chain.policy
						} else if socks != nil {
							chain.socksPolicy, err = mobilemultihop.ParseDesktopNodeChainSOCKSLaunchInput(chain.input)
							captured.SOCKSPolicy = chain.socksPolicy
						} else {
							chain.connectPolicy, err = mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(chain.input)
							captured.CONNECTPolicy = chain.connectPolicy
						}
						if err != nil {
							t.Fatal("copied source fixture did not parse", err)
						}
					case "snapshot-policy":
						captured.Policy, captured.SOCKSPolicy, captured.CONNECTPolicy = other.launch.chain.policy, other.launch.chain.socksPolicy, other.launch.chain.connectPolicy
					case "chain":
						captured.Chain = other.launch.chain
						defer func() { captured.Chain = chain }()
					case "native-source":
						original := chain.selection.Native
						chain.selection.Native = other.selection.Native
						defer func() { chain.selection.Native = original }()
					case "network":
						original := f.native.network
						f.native.network += "-replaced"
						defer func() { f.native.network = original }()
					case "command":
						f.a.cmd = &exec.Cmd{}
						defer func() { f.a.cmd = identity.Command }()
					case "registry":
						nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
						defer nativeMultihopOwners.Store(f.a, f.native)
					case "middle":
						original := common.CloneRouterProfile(f.a.profiles.Profiles[1])
						middle := &f.a.profiles.Profiles[1]
						switch family {
						case "ordinary":
							middle.APIToken += "-replaced"
						case "socks5":
							middle.External.SOCKS5.Password += "-replaced"
						case "http-connect":
							middle.External.HTTPConnect.Password += "-replaced"
						case "https-connect":
							middle.External.HTTPSConnect.Password += "-replaced"
						}
						defer func() { f.a.profiles.Profiles[1] = original }()
					case "foreign-target":
						foreign, err := newDesktopNodeChainLaunch(f.selection, f.launch.mtuSession, "windows")
						if err != nil {
							t.Fatal(err)
						}
						chain.policy, chain.socksPolicy, chain.connectPolicy = foreign.chain.policy, foreign.chain.socksPolicy, foreign.chain.connectPolicy
						captured.Policy, captured.SOCKSPolicy, captured.CONNECTPolicy = chain.policy, chain.socksPolicy, chain.connectPolicy
					}
					if err := check(); err == nil {
						t.Fatal("typed Performance accepted a replaced original owner", family, fault)
					}
				})
				if err := check(); err != nil {
					t.Fatal("original Performance owner was not restored", family, fault, err)
				}
			}
		})
	}
}
