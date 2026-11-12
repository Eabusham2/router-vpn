//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These fixtures use the actual ordered source compiler, captured parent,
// private workspace, snapshot comparisons, raw MTU owner and retirement code.
// The native process acknowledgement and PF boundary are explicit doubles;
// they do not establish actual utun/PF or encrypted-traffic acceptance.
func desktopMacOSMTUComparisonFixture(t *testing.T) (*desktopMacOSNodeMTUOwner, *[]string) {
	t.Helper()
	h, actions := desktopMacOSNodeChainRetirementFixture(t)
	a, selection := h.parent.app, h.launch.chain.selection
	a.state.Connected, a.state.Phase = true, "connected"
	sources, err := captureDesktopNodeChainSourcesLocked(a, selection)
	if err != nil {
		t.Fatal(err)
	}
	capture := &desktopNodeChainHostCapture{app: a, sources: sources, network: h.bound.network,
		platform: &desktopNodeChainPlatformCapture{parent: h.parent}}
	selection.Native.chain.host = capture
	h.runtime.capture, h.launch.chain.capture = capture, capture
	child := &desktopMacOSProcess{parent: h.parent, command: h.launch.command,
		gate: make(chan struct{}, 1), joined: make(chan struct{})}
	child.gate <- struct{}{}
	child.started.Store(true)
	h.process = child
	h.proved, h.activated = true, true // Comparison inputs only; full Current still refuses the unproved boundary.
	path := &mtuMultihopSnapshot{Graph: h.bound.graph, Control: cloneRouterProfile(selection.Control),
		Entry: cloneRouterProfile(selection.Entry), ControlToken: mtuProfileSnapshotToken(selection.Control),
		EntryToken: mtuProfileSnapshotToken(selection.Entry), PhysicalEntry: h.launch.endpoint,
		Native: h.bound, Command: h.launch.command}
	path.Chain, err = captureMTUNodeChainSnapshot(h.bound)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mtuRetestSnapshot{SessionID: "original-darwin-mtu-comparison", SelectedID: selection.Control.ID,
		ProfileToken: mtuProfileSnapshotToken(selection.Exit), StateToken: mtuStateSnapshotToken(a.state),
		Profile: cloneRouterProfile(selection.Exit), State: a.state, Mode: selection.ExitMode,
		Multihop: path, persistence: &mtuMeasurementPersistence{}}
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: snapshot.SessionID}})
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	record := desktopNodeMTURecord{Schema: 1, Session: h.launch.mtuSession, Config: h.launch.configSHA256,
		Path: strings.Repeat("c", 64), Reader: 1, Interface: "utun71", Index: 71, MTU: 1280, Heartbeat: time.Now().UnixMilli()}
	native := &desktopNodeMTUOwner{launch: h.launch, record: record, family: 4, originalMTU: record.MTU, lease: strings.Repeat("d", 32)}
	initial := desktopMacOSMTUState(record, 4)
	owner := &desktopMacOSNodeMTUOwner{host: h, parent: h.parent, session: h.parent.session, runtime: h.runtime, process: child, launch: h.launch,
		bound: h.bound, snapshot: snapshot, native: native, initial: record, initialState: initial,
		previous: initial, current: initial, admitted: true}
	native.verifyReaderChange = owner.verifyReaderChangeLocked
	h.mtu = owner
	if err := owner.originalLocked(); err != nil {
		t.Fatal("comparison fixture lost its actual retained source associations", err)
	}
	if err := validateDesktopMacOSMTUSnapshotLocked(h, snapshot); err != nil {
		t.Fatal("comparison fixture lost its actual captured application state", err)
	}
	return owner, actions
}

func TestDesktopMacOSMTUOriginalLeaseRejectsReplacement(t *testing.T) {
	for _, fault := range []string{
		"bridge", "parent", "parent-session", "runtime", "process", "launch", "bound", "runtime-host", "runtime-capture",
		"capture-parent", "chain", "platform", "policy", "native-selection", "native-host", "sources",
		"launch-capture", "source", "network", "capture-network", "process-parent", "process-command",
		"snapshot-command", "raw-launch", "session", "config", "path", "family", "original-mtu",
		"launch-session", "launch-config",
	} {
		t.Run(fault, func(t *testing.T) {
			owner, _ := desktopMacOSMTUComparisonFixture(t)
			h, captured := owner.host, owner.snapshot.Multihop.Chain
			switch fault {
			case "bridge":
				h.mtu = &desktopMacOSNodeMTUOwner{}
			case "parent":
				h.parent = &desktopMacOSSessionCapture{}
			case "parent-session":
				owner.parent.session = &desktopMacOSSession{}
			case "runtime":
				h.runtime = &desktopNodeChainPlatformRuntime{}
			case "process":
				h.process = &desktopMacOSProcess{}
			case "launch":
				h.launch = &desktopNodeLaunch{}
			case "bound":
				h.bound = &nativeMultihopRuntime{}
			case "runtime-host":
				owner.runtime.host = &desktopMacOSNodeChainHost{}
			case "runtime-capture":
				owner.runtime.capture = &desktopNodeChainHostCapture{}
			case "capture-parent":
				captured.Capture.platform.parent = &desktopMacOSSessionCapture{}
			case "chain":
				owner.launch.chain = &desktopNodeChainLaunch{}
			case "platform":
				owner.launch.chain.platform = &desktopNodeChainPlatformRuntime{}
			case "policy":
				h.policy = nil
			case "native-selection":
				owner.bound.selection.Native = &nativeMultihopCapture{}
			case "native-host":
				captured.Native.chain.host = &desktopNodeChainHostCapture{}
			case "sources":
				captured.Capture.sources = &desktopNodeChainSources{}
			case "launch-capture":
				owner.launch.chain.capture = &desktopNodeChainHostCapture{}
			case "source":
				captured.Native.source += "-replacement"
			case "network":
				owner.bound.network += "-replacement"
			case "capture-network":
				captured.Capture.network += "-replacement"
			case "process-parent":
				owner.process.parent = &desktopMacOSSessionCapture{}
			case "process-command":
				owner.process.command = &exec.Cmd{}
			case "snapshot-command":
				owner.snapshot.Multihop.Command = &exec.Cmd{}
			case "raw-launch":
				owner.native.launch = &desktopNodeLaunch{}
			case "session":
				owner.native.record.Session = strings.Repeat("e", 32)
			case "config":
				owner.native.record.Config = strings.Repeat("e", 64)
			case "path":
				owner.native.record.Path = strings.Repeat("e", 64)
			case "family":
				owner.native.family = 6
			case "original-mtu":
				owner.native.originalMTU++
			case "launch-session":
				owner.launch.mtuSession = strings.Repeat("e", 32)
			case "launch-config":
				owner.launch.configSHA256 = strings.Repeat("e", 64)
			}
			if err := owner.originalLocked(); err == nil {
				t.Fatal("replacement gained the original cleanup lease", fault)
			}
		})
	}
}

func TestDesktopMacOSMTUStateChangeCannotAuthorizeNewWork(t *testing.T) {
	for _, fault := range []string{"selected", "middle-profile", "session", "command", "graph", "registry", "connected", "policy", "proved", "activated", "retiring"} {
		t.Run(fault, func(t *testing.T) {
			owner, _ := desktopMacOSMTUComparisonFixture(t)
			h, a := owner.host, owner.parent.app
			release, err := claimDesktopMacOSMTUOperation(context.Background(), a, owner.launch.command)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			switch fault {
			case "selected":
				a.profiles.SelectedID = owner.snapshot.Multihop.Entry.ID
			case "middle-profile":
				middle := owner.bound.selection.Nodes[1].Profile.ID
				for i := range a.profiles.Profiles {
					if a.profiles.Profiles[i].ID == middle {
						a.profiles.Profiles[i].APIToken += "-replacement"
					}
				}
			case "session":
				sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "replacement"}})
			case "command":
				a.cmd = &exec.Cmd{}
			case "graph":
				graph := owner.snapshot.Multihop.Graph
				graph.SourceSHA = strings.Repeat("e", 64)
				activeMultihopGraphs.Store(a, graph)
			case "registry":
				nativeMultihopOwners.Store(a, &nativeMultihopRuntime{})
			case "connected":
				a.state.Connected = false
			case "policy":
				owner.snapshot.Profile.MTUPolicy = "manual"
			case "proved":
				h.proved = false
			case "activated":
				h.activated = false
			case "retiring":
				h.retiring = true
			}
			if validateDesktopMacOSMTUSnapshotLocked(h, owner.snapshot) == nil {
				t.Fatal("changed original state authorized a new MTU action", fault)
			}
			if err := owner.originalLocked(); err != nil {
				t.Fatal("a user/state change discarded the still-owned cleanup obligation", fault, err)
			}
		})
	}
}

func TestDesktopMacOSMTUOperationDefersOnlyOriginalMonitor(t *testing.T) {
	a := &app{}
	original := &exec.Cmd{Path: "original-mtu"}
	a.cmd = original
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release, err := claimDesktopMacOSMTUOperation(ctx, a, original)
	if err != nil {
		t.Fatal(err)
	}
	monitor, current := a.claimRuntimeMonitorOperation(original)
	if !current || monitor != nil {
		if monitor != nil {
			monitor()
		}
		release()
		t.Fatal("monitor acquired a connection transaction during the exact original MTU action")
	}
	if nested, err := claimDesktopMacOSMTUOperation(ctx, a, original); err == nil || nested != nil {
		if nested != nil {
			nested()
		}
		release()
		t.Fatal("nested active admission bypassed the original operation claim")
	}
	release()
	monitor, current = a.claimRuntimeMonitorOperation(original)
	if !current || monitor == nil {
		t.Fatal("completed MTU action leaked the operation claim")
	}
	monitor()
	for _, fault := range []string{"nil-app", "nil-command", "nil-caller", "cancelled", "replaced", "closing"} {
		t.Run(fault, func(t *testing.T) {
			appValue, command := a, original
			var caller context.Context = context.Background()
			a.cmd, a.closing = original, false
			switch fault {
			case "nil-app":
				appValue = nil
			case "nil-command":
				command = nil
			case "nil-caller":
				caller = nil
			case "cancelled":
				caller = ctx
				cancel()
			case "replaced":
				a.cmd = &exec.Cmd{Path: "replacement"}
			case "closing":
				a.closing = true
			}
			done, err := claimDesktopMacOSMTUOperation(caller, appValue, command)
			if err == nil || done != nil {
				if done != nil {
					done()
				}
				t.Fatal("invalid action acquired or retained the original operation", fault)
			}
			if !a.operationMu.TryLock() {
				t.Fatal("refusal leaked the operation guard", fault)
			}
			a.operationMu.Unlock()
		})
	}
}

func TestDesktopMacOSMTUUnprovedHostNeverBecomesAnAmbientWriter(t *testing.T) {
	for _, action := range []string{"capture", "open", "read", "change", "commit", "succession", "callback"} {
		t.Run(action, func(t *testing.T) {
			owner, _ := desktopMacOSMTUComparisonFixture(t)
			a := owner.parent.app
			var err error
			switch action {
			case "capture":
				var handled bool
				_, handled, err = captureDesktopPlatformMTUSnapshot(a, owner.snapshot)
				if !handled {
					t.Fatal("captured Darwin host escaped its typed dispatch")
				}
			case "open":
				owner.host.mtu = nil
				var handled bool
				_, handled, err = openDesktopPlatformMTUOwner(a, owner.snapshot,
					mtuLiveSnapshot{Interface: owner.initial.Interface, Family: 4, OriginalMTU: 1280, nodeRecord: &owner.initial},
					strings.Repeat("d", 32), owner.launch.command)
				if !handled {
					t.Fatal("captured Darwin lease fell through to a generic kernel writer")
				}
			case "read":
				_, err = owner.Read()
			case "change":
				_, err = owner.Change(owner.initialState, 1300)
			case "commit":
				err = owner.Commit()
			case "succession":
				err = owner.validateMTUInterfaceSuccession(owner.initialState, owner.current, owner.current, false)
			case "callback":
				next := owner.native.record
				next.Reader, next.Interface, next.Index, next.MTU = 2, "utun72", 72, 1300
				err = owner.verifyReaderChangeLocked(context.Background(), owner.native.record, next)
			}
			if err == nil {
				t.Fatal("comparison fixture claimed actual native/process/PF/utun proof", action)
			}
			if !a.operationMu.TryLock() {
				t.Fatal("failed native observation retained its operation claim", action)
			}
			a.operationMu.Unlock()
		})
	}
	if _, handled, err := captureDesktopPlatformMTUSnapshot(&app{}, mtuRetestSnapshot{}); handled || err != nil {
		t.Fatal("ordinary external/native families were captured by the ordered Darwin adapter")
	}
	if _, handled, err := openDesktopPlatformMTUOwner(&app{}, mtuRetestSnapshot{},
		mtuLiveSnapshot{nodeRecord: &desktopNodeMTURecord{}}, strings.Repeat("d", 32), &exec.Cmd{}); !handled || err == nil {
		t.Fatal("a lost captured native receipt fell through to an ambient writer")
	}
}

func writeDesktopMacOSMTUStoppedFixture(t *testing.T, owner *desktopMacOSNodeMTUOwner, fault string) {
	t.Helper()
	record := desktopExternalStop{Schema: 1, SessionID: owner.launch.mtuSession, SourceSHA256: owner.launch.configSHA256, Closed: true}
	switch fault {
	case "session":
		record.SessionID = strings.Repeat("e", 32)
	case "config":
		record.SourceSHA256 = strings.Repeat("e", 64)
	case "not-closed":
		record.Closed = false
	case "schema":
		record.Schema = 2
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	// This models only the original child publishing its native close receipt.
	// The shipping reader still verifies the exact private directory and bytes.
	if err := os.WriteFile(filepath.Join(owner.launch.directory, "stopped.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopMacOSMTURetiredCleanupRequiresExactJoinedNative(t *testing.T) {
	for _, fault := range []string{"missing-ack", "unjoined", "cancelled", "missing-stop", "session", "config", "not-closed", "schema"} {
		t.Run(fault, func(t *testing.T) {
			owner, actions := desktopMacOSMTUComparisonFixture(t)
			h, child := owner.host, owner.process
			child.nativeAcknowledged, child.nativeStopped = true, true
			if fault != "unjoined" {
				close(child.joined)
			}
			if fault == "missing-ack" {
				child.nativeAcknowledged, child.nativeStopped = false, false
			}
			if fault != "missing-stop" {
				writeDesktopMacOSMTUStoppedFixture(t, owner, fault)
			}
			// Stop already owns operationMu. Cleanup must not recursively claim it.
			h.parent.app.operationMu.Lock()
			caller, cancel := context.WithCancel(context.Background())
			if fault == "cancelled" {
				cancel()
			}
			err := h.Close(caller)
			cancel()
			h.parent.app.operationMu.Unlock()
			if err == nil || owner.closed || h.mtu != owner || h.closed || h.baselineRetired ||
				h.workspaceRetired || len(*actions) != 0 {
				t.Fatal("unproved/failed cleanup discarded the original native lease or protection", fault, err)
			}
			if _, err := os.Stat(owner.launch.directory); err != nil {
				t.Fatal("failed original cleanup removed its private workspace", err)
			}
			if _, restored := owner.CleanupRestored(); restored {
				t.Fatal("native retirement fabricated a numeric rollback receipt")
			}
			child.nativeAcknowledged, child.nativeStopped = true, true
			if fault == "unjoined" {
				close(child.joined)
			}
			writeDesktopMacOSMTUStoppedFixture(t, owner, "")
			h.parent.app.operationMu.Lock()
			err = h.Close(context.Background())
			h.parent.app.operationMu.Unlock()
			if err != nil || !owner.closed || !owner.retired || h.mtu != nil || !owner.native.runtimeRetired ||
				!h.closed || !reflect.DeepEqual(*actions, []string{"release"}) {
				t.Fatal("exact original joined cleanup could not retry", fault, err, *actions)
			}
			if _, restored := owner.CleanupRestored(); restored {
				t.Fatal("stopped native path was mislabeled as a live restored interface")
			}
			if owner.validateMTUInterfaceSuccession(owner.initialState, owner.current, owner.current, true) == nil {
				t.Fatal("stopped native path authorized a cleanup reader succession")
			}
		})
	}
}

func TestDesktopMacOSMTUReadbackAndPrivateBenchmarkIdentity(t *testing.T) {
	owner, _ := desktopMacOSMTUComparisonFixture(t)
	before, after := owner.initial, owner.initial
	after.Heartbeat++
	if !sameDesktopMacOSMTUReadback(before, after) {
		t.Fatal("heartbeat refresh changed the immutable reader receipt")
	}
	for _, fault := range []string{"reader", "interface", "index", "mtu", "session", "config", "path", "lease", "request", "generation", "active", "failure"} {
		t.Run(fault, func(t *testing.T) {
			after := before
			switch fault {
			case "reader":
				after.Reader++
			case "interface":
				after.Interface = "utun72"
			case "index":
				after.Index++
			case "mtu":
				after.MTU++
			case "session":
				after.Session = strings.Repeat("e", 32)
			case "config":
				after.Config = strings.Repeat("e", 64)
			case "path":
				after.Path = strings.Repeat("e", 64)
			case "lease":
				after.Lease = strings.Repeat("e", 32)
			case "request":
				after.Request = strings.Repeat("e", 32)
			case "generation":
				after.Generation++
			case "active":
				after.Active = !after.Active
			case "failure":
				after.Failure = "unproved"
			}
			if sameDesktopMacOSMTUReadback(before, after) {
				t.Fatal("readback ignored original native authority", fault)
			}
		})
	}
	for _, tc := range []struct {
		host   string
		family int
	}{
		{"", 4}, {"10.77.0.1", 4}, {"192.168.50.133", 4}, {"[fd00::1]", 6},
		{"localhost", 0}, {"dns.example.invalid", 0}, {"8.8.8.8", 0}, {"[2001:4860:4860::8888]", 0},
	} {
		name := tc.host
		if name == "" {
			name = "default"
		}
		t.Run("benchmark/"+name, func(t *testing.T) {
			snapshot := owner.snapshot
			snapshot.Profile.DAITAHost = tc.host
			family, err := desktopMacOSMTUFamily(snapshot)
			if tc.family == 0 && err == nil || tc.family != 0 && (err != nil || family != tc.family) {
				t.Fatal("benchmark capture changed literal private-family policy", family, err)
			}
		})
	}
}

func TestDesktopMacOSMTUClosedRollbackReceiptCannotBeRebound(t *testing.T) {
	// This is the closed receipt comparison boundary. Actual native rollback
	// and close proof are tested by the raw owner and installed host gates.
	// No native observation is supplied or accepted by this fixture.
	makeOwner := func() *desktopMacOSNodeMTUOwner {
		initial := mtuKernelState{Interface: "utun71", Family: 4, Index: 71, MTU: 1280, Identity: "original/path/1"}
		before := mtuKernelState{Interface: "utun72", Family: 4, Index: 72, MTU: 1300, Identity: "original/path/2"}
		restored := mtuKernelState{Interface: "utun73", Family: 4, Index: 73, MTU: 1280, Identity: "original/path/3"}
		host := &desktopMacOSNodeChainHost{gate: make(chan struct{}, 1)}
		host.gate <- struct{}{}
		return &desktopMacOSNodeMTUOwner{host: host, initialState: initial, cleanupPrevious: before,
			cleanup: restored, closed: true, restored: true}
	}
	for _, idempotent := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact-transition", true: "idempotent-current"}[idempotent], func(t *testing.T) {
			owner := makeOwner()
			previous := owner.cleanupPrevious
			if idempotent {
				previous = owner.cleanup
			}
			if err := owner.validateMTUInterfaceSuccession(owner.initialState, previous, owner.cleanup, true); err != nil {
				t.Fatal("stored exact closed rollback receipt was not reusable", idempotent, err)
			}
		})
	}
	for _, fault := range []string{
		"initial-interface", "initial-family", "initial-index", "initial-mtu", "initial-identity",
		"previous-interface", "previous-family", "previous-index", "previous-mtu", "previous-identity",
		"next-interface", "next-family", "next-index", "next-mtu", "next-identity",
		"not-closed", "not-restored", "retired", "active-use",
	} {
		t.Run(fault, func(t *testing.T) {
			owner := makeOwner()
			initial, previous, next, cleanup := owner.initialState, owner.cleanupPrevious, owner.cleanup, true
			switch fault {
			case "initial-interface":
				initial.Interface = "utun99"
			case "initial-family":
				initial.Family = 6
			case "initial-index":
				initial.Index++
			case "initial-mtu":
				initial.MTU++
			case "initial-identity":
				initial.Identity += "/replacement"
			case "previous-interface":
				previous.Interface = "utun99"
			case "previous-family":
				previous.Family = 6
			case "previous-index":
				previous.Index++
			case "previous-mtu":
				previous.MTU++
			case "previous-identity":
				previous.Identity += "/replacement"
			case "next-interface":
				next.Interface = "utun99"
			case "next-family":
				next.Family = 6
			case "next-index":
				next.Index++
			case "next-mtu":
				next.MTU++
			case "next-identity":
				next.Identity += "/replacement"
			case "not-closed":
				owner.closed = false
			case "not-restored":
				owner.restored = false
			case "retired":
				owner.retired = true
			case "active-use":
				cleanup = false
			}
			if err := owner.validateMTUInterfaceSuccession(initial, previous, next, cleanup); err == nil {
				t.Fatal("stored cleanup receipt was relinked or reused for active work", fault)
			}
		})
	}
}

func TestDesktopMacOSMTURetiredRetryKeepsPartialBeginAuthority(t *testing.T) {
	for _, localClosed := range []bool{false, true} {
		t.Run(map[bool]string{false: "entered-begin", true: "unpublished-begin"}[localClosed], func(t *testing.T) {
			owner, actions := desktopMacOSMTUComparisonFixture(t)
			child := owner.process
			child.nativeAcknowledged, child.nativeStopped = true, true
			close(child.joined)
			owner.admitted = false
			owner.native.closed = localClosed
			owner.native.verifyReaderChange = nil
			if err := owner.host.Close(context.Background()); err == nil || owner.closed ||
				owner.host.mtu != owner || len(*actions) != 0 {
				t.Fatal("partial begin was discharged without original native cleanup receipt", err)
			}
			writeDesktopMacOSMTUStoppedFixture(t, owner, "")
			if err := owner.host.Close(context.Background()); err != nil || !owner.closed || !owner.retired ||
				owner.host.mtu != nil || !reflect.DeepEqual(*actions, []string{"release"}) {
				t.Fatal("exact joined stop could not discharge the original partial begin", err)
			}
		})
	}
}
