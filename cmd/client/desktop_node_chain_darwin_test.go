//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The parent/session, source policy, workspace, stop capture and retirement
// code are shipping implementations. Only the installed PF command and an
// explicitly marked native process receipt are modeled here. Native child,
// PF/guardian, encrypted traffic and utun acceptance remain separate CI gates.
func desktopMacOSNodeChainRetirementFixture(t *testing.T) (*desktopMacOSNodeChainHost, *[]string) {
	return desktopMacOSNodeChainRetirementFixtureWith(t, func(t *testing.T) (*app, *desktopNodeLaunch) {
		return desktopNodeChainLaunchFixture(t, 3, "darwin")
	})
}

func desktopMacOSNodeChainRetirementFixtureWith(t *testing.T, makeLaunch func(*testing.T) (*app, *desktopNodeLaunch)) (*desktopMacOSNodeChainHost, *[]string) {
	t.Helper()
	p, s, c, _, _ := macOSParentFixture(t)
	a, launch := makeLaunch(t)
	a.localController = c
	operation, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a.connectionContext, a.connectionCancel = operation, cancel
	launch.command = &exec.Cmd{}
	a.cmd = launch.command
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode = "multihop", "multihop", launch.mode
	a.state.RouterID, a.state.Base = launch.policyProfileID, launch.chain.selection.Base
	parent := &desktopMacOSSessionCapture{app: a, controller: c, parent: p, session: s}
	meta := launch.chain.policyMetadata()
	runtime := &desktopNodeChainPlatformRuntime{registered: true}
	h := &desktopMacOSNodeChainHost{parent: parent, runtime: runtime, launch: launch, policy: launch.chain.policy, socksPolicy: launch.chain.socksPolicy, connectPolicy: launch.chain.connectPolicy,
		operation: operation, gate: make(chan struct{}, 1), entered: true, published: true, staged: true, baselineEntered: true,
		selection: desktopMacOSNodeChainSelection{Schema: 2, Family: launch.chain.macOSFamily(), ProfileID: meta.ProfileID,
			Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy}}
	runtime.host, launch.chain.platform = h, runtime
	h.gate <- struct{}{}
	h.baseline = &desktopMacOSNodeChainReceipt{Schema: 2, Capture: h.selection, Phase: "active", Token: "417",
		Baseline: desktopMacOSBaselineProof{Present: true, Rules: strings.Repeat("a", 64)}}
	s.nodeChain = runtime
	if err := s.Retain(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	graph, err := publishDesktopMultihopPlatformGraph(context.Background(), a, launch, launch.chain.selection, "local")
	if err != nil {
		t.Fatal(err)
	}
	h.bound = &nativeMultihopRuntime{launch: launch, selection: launch.chain.selection, graph: graph, network: "original-physical"}
	nativeMultihopOwners.Store(a, h.bound)
	t.Cleanup(func() {
		nativeMultihopOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
		activeDNSRuntimeIdentities.Delete(a)
		mtuLiveOwners.Delete(a)
	})
	directory := filepath.Join(t.TempDir(), "original-ordered")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	h.stageDirectory, h.stageInfo = directory, launch.directoryInfo
	if err := writeDesktopRuntimeFile(launch, launch.chain.sourceName(), []byte(launch.chain.input), false); err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(launch, "sing-box.json", launch.config, false); err != nil {
		t.Fatal(err)
	}
	actions := &[]string{}
	h.baselineRun = func(ctx context.Context, captured *desktopMacOSSessionCapture, selection desktopMacOSNodeChainSelection,
		action string, expected *desktopMacOSNodeChainReceipt, _ func()) (*desktopMacOSNodeChainReceipt, error) {
		if captured != parent || selection != h.selection || expected == nil || expected.Capture != selection ||
			expected.Token != "417" || !h.nativeRetired {
			return nil, errors.New("modeled PF boundary rejected changed original authority or unjoined child")
		}
		*actions = append(*actions, action)
		value := *expected
		switch action {
		case "retire":
			value.Phase = "held"
		case "release":
			value.Phase, value.Baseline = "retired", desktopMacOSBaselineProof{}
		default:
			return nil, errors.New("unexpected modeled PF action")
		}
		return &value, ctx.Err()
	}
	return h, actions
}

func TestDesktopMacOSNodeChainRetirementRequiresNativeAcknowledgment(t *testing.T) {
	h, actions := desktopMacOSNodeChainRetirementFixture(t)
	child := &desktopMacOSProcess{parent: h.parent, command: h.launch.command, gate: make(chan struct{}, 1), joined: make(chan struct{})}
	child.gate <- struct{}{}
	child.started.Store(true)
	close(child.joined) // Process exit alone supplies no authenticated PF cleanup.
	h.process = child
	if err := h.Close(context.Background()); err == nil {
		t.Fatal("exited child without its native ACK released ordered protection")
	}
	if h.nativeRetired || h.baselineRetired || h.workspaceRetired || h.closed || len(*actions) != 0 ||
		h.parent.session.nodeChain != h.runtime || h.parent.app.cmd != h.launch.command {
		t.Fatal("failed native cleanup discarded its original retained owner", *actions)
	}
	if _, err := os.Stat(h.launch.directory); err != nil {
		t.Fatal("unacknowledged native cleanup removed its private workspace", err)
	}
	// Explicit native-boundary receipt: the real Bootstrap.Stop test owns its
	// socket authentication; this fixture now exercises the original retry.
	child.nativeAcknowledged, child.nativeStopped = true, true
	if err := h.Close(context.Background()); err != nil {
		t.Fatal("same acknowledged original child could not complete cleanup", err)
	}
	if !h.closed || !reflect.DeepEqual(*actions, []string{"release"}) || h.parent.session.nodeChain != nil ||
		h.parent.app.cmd != nil {
		t.Fatal("joined original owner did not retire exactly once", *actions)
	}
}

func TestDesktopMacOSNodeChainRetirementRetryEscalatesHeldBaseline(t *testing.T) {
	h, actions := desktopMacOSNodeChainRetirementFixture(t)
	unknown := filepath.Join(h.launch.directory, "replacement-owner")
	if err := os.WriteFile(unknown, []byte("retain unknown owner"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.closeWithIntent(context.Background(), true); err == nil {
		t.Fatal("unknown private owner was discarded")
	}
	if h.closed || !h.nativeRetired || !h.baselineRetired || h.workspaceRetired || h.baseline.Phase != "held" ||
		!reflect.DeepEqual(*actions, []string{"retire"}) {
		t.Fatal("failed workspace retirement lost the original held PF receipt", *actions)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	stop, err := h.parent.app.captureDesktopRetainedStop()
	if err != nil || stop == nil {
		t.Fatal("Disconnect could not recapture the original pending ordered owner", err)
	}
	if err := stop.Retire(context.Background(), h.launch.command, true); err != nil {
		t.Fatal(err)
	}
	if !h.closed || h.baseline.Phase != "retired" || !reflect.DeepEqual(*actions, []string{"retire", "release"}) {
		t.Fatal("Disconnect did not release its exact held original baseline", *actions)
	}
}

func TestDesktopMacOSNodeChainRetirementNeverClearsReplacement(t *testing.T) {
	for _, fault := range []string{"command", "controller", "session-slot", "graph-owner", "graph-value", "dns"} {
		t.Run(fault, func(t *testing.T) {
			h, _ := desktopMacOSNodeChainRetirementFixture(t)
			a := h.parent.app
			originalCommand, originalController := a.cmd, a.localController
			originalOwner, originalGraph := h.bound, h.bound.graph
			replacementCommand := &exec.Cmd{}
			replacementController := &ownedDesktopController{}
			replacementSlot := &desktopNodeChainPlatformRuntime{}
			replacementOwner := &nativeMultihopRuntime{launch: &desktopNodeLaunch{}}
			replacementGraph := originalGraph
			replacementGraph.SourceSHA = strings.Repeat("e", 64)
			replacementDNS := activeDNSRuntimeIdentity{ProfileID: h.launch.policyProfileID, RuntimeID: h.launch.mode,
				Config: filepath.Join(filepath.Dir(h.launch.directory), "replacement", "sing-box.json")}
			switch fault {
			case "command":
				a.cmd = replacementCommand
			case "controller":
				a.localController = replacementController
			case "session-slot":
				h.parent.session.nodeChain = replacementSlot
			case "graph-owner":
				nativeMultihopOwners.Store(a, replacementOwner)
			case "graph-value":
				activeMultihopGraphs.Store(a, replacementGraph)
			case "dns":
				activeDNSRuntimeIdentities.Store(a, replacementDNS)
			}
			err := h.Close(context.Background())
			if fault == "dns" {
				if err != nil || !h.closed {
					t.Fatal("original cleanup failed with an independent DNS successor", err)
				}
				if actual, exists := activeDNSRuntimeIdentities.Load(a); !exists || actual != replacementDNS {
					t.Fatal("old ordered retirement erased the replacement DNS identity")
				}
				return
			}
			if err == nil || h.closed || !h.workspaceRetired {
				t.Fatal("old ordered retirement cleared replacement authority or lost completed cleanup progress", err)
			}
			switch fault {
			case "command":
				if a.cmd != replacementCommand {
					t.Fatal("replacement command cleared")
				}
			case "controller":
				if a.localController != replacementController {
					t.Fatal("replacement controller cleared")
				}
			case "session-slot":
				if h.parent.session.nodeChain != replacementSlot {
					t.Fatal("replacement session cleared")
				}
			case "graph-owner":
				if raw, _ := nativeMultihopOwners.Load(a); raw != replacementOwner {
					t.Fatal("replacement graph owner cleared")
				}
			case "graph-value":
				if graph, _ := getActiveMultihopGraph(a); graph != replacementGraph {
					t.Fatal("replacement graph cleared")
				}
			}
			a.cmd, a.localController, h.parent.session.nodeChain = originalCommand, originalController, h.runtime
			nativeMultihopOwners.Store(a, originalOwner)
			activeMultihopGraphs.Store(a, originalGraph)
			if err := h.Close(context.Background()); err != nil || !h.closed {
				t.Fatal("original exact cleanup could not retry without deleting its workspace twice", err)
			}
		})
	}
}

func TestDesktopMacOSNodeChainStopRetainsPartialAttemptBeforeGraphBind(t *testing.T) {
	h, actions := desktopMacOSNodeChainRetirementFixture(t)
	a := h.parent.app
	a.cmd, h.launch.command, h.bound, h.graph = nil, nil, nil, nil
	nativeMultihopOwners.Delete(a)
	activeMultihopGraphs.Delete(a)
	stop, err := a.captureDesktopRetainedStop()
	if err != nil || stop == nil {
		t.Fatal("partial ordered PF attempt fell through to ordinary cleanup", err)
	}
	if err := stop.Retire(context.Background(), nil, true); err != nil {
		t.Fatal("partial original ordered attempt could not drain", err)
	}
	if !h.closed || !reflect.DeepEqual(*actions, []string{"release"}) || h.parent.session.nodeChain != nil {
		t.Fatal("partial PF and workspace owner was discarded", *actions)
	}
}

func TestDesktopMacOSNodeChainStopCaptureRejectsReplacementAfterHold(t *testing.T) {
	for _, fault := range []string{"command", "operation", "session"} {
		t.Run(fault, func(t *testing.T) {
			h, actions := desktopMacOSNodeChainRetirementFixture(t)
			a := h.parent.app
			stop, err := a.captureDesktopRetainedStop()
			if err != nil || stop == nil {
				t.Fatal(err)
			}
			originalCommand, originalOperation := a.cmd, a.connectionContext
			switch fault {
			case "command":
				a.cmd = &exec.Cmd{}
			case "operation":
				replacement, cancel := context.WithCancel(context.Background())
				defer cancel()
				a.connectionContext = replacement
			case "session":
				h.parent.session.nodeChain = &desktopNodeChainPlatformRuntime{}
			}
			if err := stop.Retire(context.Background(), originalCommand, true); err == nil ||
				h.nativeRetired || len(*actions) != 0 {
				t.Fatal("captured Stop retargeted the owner that appeared during its MTU hold", err)
			}
			a.cmd, a.connectionContext, h.parent.session.nodeChain = originalCommand, originalOperation, h.runtime
			if err := stop.Retire(context.Background(), originalCommand, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopMacOSNodeChainStopMalformedOwnerCannotFallThrough(t *testing.T) {
	p, s, c, _, _ := macOSParentFixture(t)
	a := &app{localController: c}
	s.nodeChain = &desktopNodeChainPlatformRuntime{}
	if captured, err := a.captureDesktopRetainedStop(); err == nil || captured != nil {
		t.Fatal("malformed retained ordered owner fell through to ordinary Stop", err)
	}
	s.nodeChain = nil
	if captured, err := p.CaptureNodeChainStop(a); err != nil || captured != nil {
		t.Fatal("absent ordered owner changed ordinary Stop dispatch", err)
	}
}

func TestDesktopMacOSNodeChainRetirementPreservesBaselineFailureForRetry(t *testing.T) {
	h, actions := desktopMacOSNodeChainRetirementFixture(t)
	original := h.baselineRun
	h.baselineRun = func(context.Context, *desktopMacOSSessionCapture, desktopMacOSNodeChainSelection,
		string, *desktopMacOSNodeChainReceipt, func()) (*desktopMacOSNodeChainReceipt, error) {
		return nil, errors.New("original PF receipt still pending")
	}
	if err := h.Close(context.Background()); err == nil || !h.nativeRetired || h.baselineRetired || h.workspaceRetired || h.closed {
		t.Fatal("PF cleanup failure manufactured terminal retirement", err)
	}
	h.baselineRun = original
	if err := h.Close(context.Background()); err != nil || !reflect.DeepEqual(*actions, []string{"release"}) {
		t.Fatal("PF receipt could not retry with its original selection", err, *actions)
	}
}

func TestDesktopMacOSNodeChainKernelReaderRequiresOriginalUTUNRetirement(t *testing.T) {
	_, launch := desktopNodeChainLaunchFixture(t, 3, "darwin")
	previous, live, _ := desktopNodeChainReadyFixture(t, launch)
	previous.InterfaceName = "utun991"
	live.Interface, live.Index, live.Reader = "utun992", 92, previous.Reader+1
	link := net.Interface{Index: 92, Name: "utun992", MTU: live.MTU, Flags: net.FlagUp}
	if err := validateDesktopMacOSNodeChainInterface(live, &link); err != nil {
		t.Fatal(err)
	}
	if err := validateDesktopMacOSNodeChainReaderRetirement(&previous, live, []net.Interface{link}); err != nil {
		t.Fatal("actual advanced utun replacement was rejected", err)
	}
	for _, fault := range []string{"old-retained", "new-missing", "same-reader", "wrong-name", "wrong-index", "wrong-mtu", "down", "non-utun", "nil"} {
		t.Run(fault, func(t *testing.T) {
			record, actual := live, link
			inventory := []net.Interface{actual}
			switch fault {
			case "old-retained":
				inventory = append(inventory, net.Interface{Index: int(previous.InterfaceIndex), Name: previous.InterfaceName, MTU: previous.MTU})
			case "new-missing":
				inventory = nil
			case "same-reader":
				record.Reader = previous.Reader
			case "wrong-name":
				actual.Name = "utun993"
			case "wrong-index":
				actual.Index++
			case "wrong-mtu":
				actual.MTU++
			case "down":
				actual.Flags = 0
			case "non-utun":
				record.Interface, actual.Name = "en9", "en9"
			case "nil":
				if validateDesktopMacOSNodeChainInterface(record, nil) == nil {
					t.Fatal("missing native interface accepted")
				}
				return
			}
			if fault == "old-retained" || fault == "new-missing" || fault == "same-reader" {
				if validateDesktopMacOSNodeChainReaderRetirement(&previous, record, inventory) == nil {
					t.Fatal("decoded generation or missing original retirement replaced actual kernel proof")
				}
			} else if validateDesktopMacOSNodeChainInterface(record, &actual) == nil {
				t.Fatal("mismatched actual native utun supplied ordered readiness")
			}
		})
	}
}

func TestDesktopMacOSNodeChainMTUStopUsesOnlyPreHeldOriginalOwner(t *testing.T) {
	for _, fault := range []string{"acknowledged", "missing-native-ack", "missing-stopped", "replacement-lease", "replacement-command", "replacement-operation", "undrained", "busy-retest", "deadline"} {
		t.Run(fault, func(t *testing.T) {
			h, actions := desktopMacOSNodeChainRetirementFixture(t)
			a, command := h.parent.app, h.launch.command
			child := &desktopMacOSProcess{parent: h.parent, command: command, gate: make(chan struct{}, 1), joined: make(chan struct{})}
			child.gate <- struct{}{}
			child.started.Store(true)
			close(child.joined)
			child.nativeAcknowledged, child.nativeStopped = true, true // Explicit native receipt boundary.
			h.process = child
			native := &desktopNodeMTUOwner{launch: h.launch}
			outer := &mtuLiveOwner{a: a, command: command, kernel: native, stopped: true}
			mtuLiveOwners.Store(a, outer)
			if fault != "missing-stopped" {
				raw, err := json.Marshal(desktopExternalStop{Schema: 1, SessionID: h.launch.mtuSession, SourceSHA256: h.launch.configSHA256, Closed: true})
				if err != nil {
					t.Fatal(err)
				}
				if err := writeDesktopRuntimeFile(h.launch, "stopped.json", raw, false); err != nil {
					t.Fatal(err)
				}
			}
			holdErr := errors.New("original MTU cleanup is pending")
			originalOperation := a.connectionContext
			var unlock func()
			switch fault {
			case "missing-native-ack":
				child.nativeAcknowledged, child.nativeStopped = false, false
			case "replacement-lease":
				mtuLiveOwners.Store(a, &mtuLiveOwner{})
			case "replacement-command":
				a.cmd = &exec.Cmd{}
			case "replacement-operation":
				replacement, cancel := context.WithCancel(context.Background())
				defer cancel()
				a.connectionContext = replacement
			case "undrained":
				outer.stopped = false
			case "busy-retest":
				lock := mtuRetestLockFor(a)
				lock.Lock()
				unlock = lock.Unlock
			case "deadline":
				holdErr = context.DeadlineExceeded
			}
			handled, err := prepareDesktopPlatformMTUStop(context.Background(), a, command, originalOperation, outer, false, holdErr)
			if unlock != nil {
				unlock()
			}
			if !handled || fault == "acknowledged" && err != nil || fault != "acknowledged" && err == nil {
				t.Fatal("explicit MTU Stop changed its exact original authority", handled, err)
			}
			if len(*actions) != 0 || h.baselineRetired || h.workspaceRetired || h.closed || h.parent.session.nodeChain != h.runtime {
				t.Fatal("MTU fallback released PF, workspace or original Stop publication", *actions)
			}
			if fault == "acknowledged" && (!h.nativeRetired || a.cmd != command || a.state.Phase != "stopping") {
				t.Fatal("acknowledged original child did not retain the pre-held Stop identity")
			}
			// Complete only this fixture's retained original cleanup.
			a.cmd, a.connectionContext, outer.stopped = command, originalOperation, true
			mtuLiveOwners.Store(a, outer)
			child.nativeAcknowledged, child.nativeStopped = true, true
			if err := h.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopMacOSNodeChainStopRetriesEnteredBaselineWithoutReply(t *testing.T) {
	h, _ := desktopMacOSNodeChainRetirementFixture(t)
	h.baseline = nil // The helper entered its journal, but its reply was lost.
	actions := 0
	h.baselineRun = func(ctx context.Context, original *desktopMacOSSessionCapture, selection desktopMacOSNodeChainSelection,
		action string, expected *desktopMacOSNodeChainReceipt, _ func()) (*desktopMacOSNodeChainReceipt, error) {
		if original != h.parent || selection != h.selection || action != "release" || expected != nil || !h.nativeRetired {
			return nil, errors.New("partial baseline cleanup changed its captured authority")
		}
		actions++
		return &desktopMacOSNodeChainReceipt{Schema: 2, Capture: selection, Phase: "retired", Token: "417"}, ctx.Err()
	}
	h.parent.app.cmd, h.launch.command, h.bound, h.graph = nil, nil, nil, nil
	nativeMultihopOwners.Delete(h.parent.app)
	activeMultihopGraphs.Delete(h.parent.app)
	captured, err := h.parent.app.captureDesktopRetainedStop()
	if err != nil || captured == nil {
		t.Fatal(err)
	}
	if err := captured.Retire(context.Background(), nil, true); err != nil {
		t.Fatal("entered original baseline could not recover its own missing reply", err)
	}
	if actions != 1 || !h.closed || h.baseline == nil || h.baseline.Token != "417" {
		t.Fatal("partial baseline did not retain its exact original retry", actions)
	}
}

func TestDesktopMacOSNodeChainGraphCleanupPrecedesFailedNativeBind(t *testing.T) {
	for _, fault := range []string{"network-before-bind", "replacement-same-source-new-start", "replacement-source"} {
		t.Run(fault, func(t *testing.T) {
			h, _ := desktopMacOSNodeChainRetirementFixture(t)
			a, selection := h.parent.app, h.launch.chain.selection
			original := *h.graph
			h.bound = nil
			nativeMultihopOwners.Delete(a)
			observed := 0
			selection.Native.chain.host = &desktopNodeChainHostCapture{readNetwork: func(context.Context) (string, error) {
				observed++
				return "", errors.New("physical observation refused before native bind")
			}}
			if err := bindNativeMultihopRuntimeContext(context.Background(), a, h.launch, selection, "original-physical"); err == nil || observed != 1 {
				t.Fatal("fixture did not reach the original pre-adoption network refusal", err, observed)
			}
			if _, found := nativeMultihopOwners.Load(a); found {
				t.Fatal("failed native bind adopted an owner")
			}
			replacement := original
			if fault == "replacement-same-source-new-start" {
				replacement.Started = replacement.Started.Add(time.Nanosecond)
				activeMultihopGraphs.Store(a, replacement)
			} else if fault == "replacement-source" {
				replacement.SourceSHA = strings.Repeat("f", 64)
				activeMultihopGraphs.Store(a, replacement)
			}
			err := h.Close(context.Background())
			if fault == "network-before-bind" {
				if err != nil || !h.closed {
					t.Fatal("exact pre-bind graph could not retire", err)
				}
				if _, found := getActiveMultihopGraph(a); found {
					t.Fatal("original unbound graph was stranded")
				}
				return
			}
			if err == nil || h.closed || !h.workspaceRetired {
				t.Fatal("replacement graph was adopted for old cleanup", err)
			}
			if actual, found := getActiveMultihopGraph(a); !found || actual != replacement {
				t.Fatal("old cleanup erased the replacement graph")
			}
			activeMultihopGraphs.Store(a, original)
			if err := h.Close(context.Background()); err != nil {
				t.Fatal("exact original graph could not finish retry", err)
			}
		})
	}
}

func TestDesktopMacOSNodeChainGraphPublicationRejectsReplacementBeforeStore(t *testing.T) {
	for _, fault := range []string{"existing-graph", "changed-source", "server", "replacement-command", "replacement-operation", "replacement-session", "foreign-bound-owner", "pre-cancel", "cancel-during-parent-check"} {
		t.Run(fault, func(t *testing.T) {
			h, _ := desktopMacOSNodeChainRetirementFixture(t)
			a := h.parent.app
			original, command, operation := *h.graph, a.cmd, a.connectionContext
			h.graph, h.bound = nil, nil
			nativeMultihopOwners.Delete(a)
			activeMultihopGraphs.Delete(a)
			selection, execution := h.launch.chain.selection, "local"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			witness := h.parent.parent.witness.(*macOSParentTestWitness)
			switch fault {
			case "existing-graph":
				activeMultihopGraphs.Store(a, original)
			case "changed-source":
				selection.Control = cloneRouterProfile(selection.Control)
				selection.Control.APIToken = "replacement-original-control"
			case "server":
				execution = "server"
			case "replacement-command":
				a.cmd = &exec.Cmd{}
			case "replacement-operation":
				replacement, stop := context.WithCancel(context.Background())
				defer stop()
				a.connectionContext = replacement
			case "replacement-session":
				h.parent.session.nodeChain = &desktopNodeChainPlatformRuntime{}
			case "foreign-bound-owner":
				nativeMultihopOwners.Store(a, &nativeMultihopRuntime{launch: &desktopNodeLaunch{}})
			case "pre-cancel":
				cancel()
			case "cancel-during-parent-check":
				witness.read = cancel
			}
			if _, err := publishDesktopMultihopPlatformGraph(ctx, a, h.launch, selection, execution); err == nil || h.graph != nil {
				t.Fatal("ordered publication changed original authority before atomically retaining its receipt", err)
			}
			if actual, found := getActiveMultihopGraph(a); fault == "existing-graph" {
				if !found || actual != original {
					t.Fatal("refused publication erased an existing graph")
				}
			} else if found {
				t.Fatal("refused publication stranded a new unowned graph")
			}
			witness.read = nil
			a.cmd, a.connectionContext, h.parent.session.nodeChain = command, operation, h.runtime
			nativeMultihopOwners.Delete(a)
			activeMultihopGraphs.Delete(a)
			graph, err := publishDesktopMultihopPlatformGraph(context.Background(), a, h.launch, h.launch.chain.selection, "local")
			if err != nil || h.graph == nil || *h.graph != graph {
				t.Fatal("exact original publication could not retain its own receipt", err)
			}
			if err := h.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopMacOSNodeChainGraphPublicationRetainsCleanupAfterCancellation(t *testing.T) {
	h, _ := desktopMacOSNodeChainRetirementFixture(t)
	a := h.parent.app
	original := *h.graph
	h.bound = nil
	nativeMultihopOwners.Delete(a)
	// The exact graph was produced and retained by the actual atomic helper.
	// Cancel its original admission before any outer bind can adopt a runtime.
	a.connectionCancel()
	if h.operation.Err() == nil {
		t.Fatal("fixture did not revoke the original operation")
	}
	if err := h.Close(context.Background()); err != nil || !h.closed {
		t.Fatal("cancellation after publication stranded its original unbound graph", err)
	}
	if actual, found := getActiveMultihopGraph(a); found {
		t.Fatal("joined original graph survived canceled admission", actual, original)
	}
}

func TestDesktopMacOSNodeChainWorkspaceRetryKeepsCreationWitness(t *testing.T) {
	for _, fault := range []string{"failed-open", "closed-handle", "replacement", "missing", "symlink", "lost-witness"} {
		t.Run(fault, func(t *testing.T) {
			h, _ := desktopMacOSNodeChainRetirementFixture(t)
			originalInfo, originalPath := h.stageInfo, h.stageDirectory
			if err := h.launch.directoryRoot.Close(); err != nil {
				t.Fatal(err)
			}
			if fault != "closed-handle" {
				h.launch.directory, h.launch.directoryInfo, h.launch.directoryRoot = "", nil, nil
			}
			backup := originalPath + "-original"
			if fault == "replacement" || fault == "missing" || fault == "symlink" {
				if err := os.Rename(originalPath, backup); err != nil {
					t.Fatal(err)
				}
				if fault == "replacement" {
					if err := os.Mkdir(originalPath, 0700); err != nil {
						t.Fatal(err)
					}
				} else if fault == "symlink" {
					if err := os.Symlink(backup, originalPath); err != nil {
						t.Fatal(err)
					}
				}
			} else if fault == "lost-witness" {
				h.stageInfo = nil
			}
			err := h.Close(context.Background())
			if fault == "failed-open" || fault == "closed-handle" {
				if err != nil || !h.closed || !h.workspaceRetired {
					t.Fatal("original creation witness could not retry its failed workspace open", err)
				}
				return
			}
			if err == nil || h.closed || h.workspaceRetired || h.parent.session.nodeChain != h.runtime {
				t.Fatal("missing or replacement path manufactured joined workspace cleanup", err)
			}
			if fault == "replacement" || fault == "symlink" {
				if _, err := os.Lstat(originalPath); err != nil {
					t.Fatal("replacement was removed", err)
				}
				if err := os.Remove(originalPath); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "replacement" || fault == "missing" || fault == "symlink" {
				if err := os.Rename(backup, originalPath); err != nil {
					t.Fatal(err)
				}
			}
			h.stageInfo = originalInfo
			if err := h.Close(context.Background()); err != nil || !h.closed {
				t.Fatal("exact original directory could not finish retirement", err)
			}
		})
	}
}

type desktopMacOSNodeChainTestMTUBridge struct {
	native *desktopNodeMTUOwner
	host   *desktopMacOSNodeChainHost
	fail   bool
	calls  int
}

func (b *desktopMacOSNodeChainTestMTUBridge) nativeOwner() *desktopNodeMTUOwner { return b.native }
func (b *desktopMacOSNodeChainTestMTUBridge) closeRetiredLocked(ctx context.Context) error {
	b.calls++
	if !b.host.nativeRetired || b.host.baselineRetired || b.host.workspaceRetired {
		return errors.New("MTU bridge lost native-before-PF/workspace retirement order")
	}
	if b.fail {
		return errors.New("original MTU close still pending")
	}
	return b.native.CloseContext(ctx)
}

func TestDesktopMacOSNodeChainRetirementJoinsRetainedMTUBeforeWorkspace(t *testing.T) {
	h, actions := desktopMacOSNodeChainRetirementFixture(t)
	native := &desktopNodeMTUOwner{launch: h.launch}
	bridge := &desktopMacOSNodeChainTestMTUBridge{native: native, host: h, fail: true}
	h.mtu = bridge
	raw, err := json.Marshal(desktopExternalStop{Schema: 1, SessionID: h.launch.mtuSession, SourceSHA256: h.launch.configSHA256, Closed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(h.launch, "stopped.json", raw, false); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(context.Background()); err == nil || !h.nativeRetired || h.baselineRetired || h.workspaceRetired ||
		h.closed || h.mtu != bridge || bridge.calls != 1 || len(*actions) != 0 {
		t.Fatal("pending retained MTU owner was discarded or PF/workspace was released first", err)
	}
	bridge.fail = false
	if err := h.Close(context.Background()); err != nil {
		t.Fatal("original MTU owner could not join retry", err)
	}
	if bridge.calls != 2 || !native.closed || !native.runtimeRetired || !h.closed || !reflect.DeepEqual(*actions, []string{"release"}) {
		t.Fatal("exact stopped receipt did not settle the original retained MTU lease", bridge.calls, *actions)
	}
}
