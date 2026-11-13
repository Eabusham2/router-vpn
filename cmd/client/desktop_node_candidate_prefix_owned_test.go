//go:build linux || windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// These cases execute the actual saved admission, Windows parent, private
// command, typed readiness and protection-retirement paths. Only the original
// Windows controller, child, kernel and physical inventory are modeled. No
// modeled receipt here establishes real WFP/TUN or encrypted-path acceptance.
type desktopCandidatePrefixOwnedFixture struct {
	*desktopImportedOwnedFixture
	purpose      *orderedCandidatePreparation
	ready        mobilemultihop.DesktopNodeCandidatePreparationReadyRecord
	live         desktopNodeMTURecord
	startFailure error
}

func newDesktopCandidatePrefixOwnedFixture(t *testing.T, mode string, position int, configure ...func(*app)) *desktopCandidatePrefixOwnedFixture {
	t.Helper()
	a, q := orderedPreparationFixture(t, mode)
	for _, apply := range configure {
		apply(a)
	}
	q.Scope, q.Position = "saved-prefix-local", position
	f := &desktopCandidatePrefixOwnedFixture{desktopImportedOwnedFixture: &desktopImportedOwnedFixture{a: a, kernel: &desktopNodeProtectionFixture{}}}
	f.network.Store("original-prefix-physical-network")
	p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, f.readNetwork)
	if err != nil || p == nil || p.prefixPreparation == nil {
		t.Fatal("prefix Windows fixture did not use real closed saved admission", err)
	}
	f.purpose, f.operation, f.cancel, f.selection = p, p.operation, p.cancel, p.selection
	a.nodeProtection = &desktopNodeProtectionSlot{backend: f.kernel.backend()}
	root := clientRoot(a)
	packageRoot := filepath.Join(root, "captured-prefix-package")
	current := func(ctx context.Context) error {
		if f.controller.Load() {
			return errors.New("modeled original prefix controller replaced")
		}
		return ctx.Err()
	}
	a.nodeConnectionHost = &desktopNodeConnectionHost{
		capture: func(owner *app) (desktopOwnedNodePreparation, error) {
			if owner != a {
				return desktopOwnedNodePreparation{}, errors.New("foreign prefix application")
			}
			return desktopOwnedNodePreparation{packageRoot: packageRoot, dataRoot: root, lifetime: p.operation,
				current: func() error { return current(context.Background()) }, currentContext: current,
				protectionBackend: func() (desktopNodeProtectionBackend, error) { return f.kernel.backend(), current(context.Background()) }}, nil
		},
		verify: func(ctx context.Context, path string) (string, error) {
			if path != packageRoot {
				return "", errors.New("prefix substituted installed package")
			}
			return filepath.Join(packageRoot, "runtime", "native", nativeBinaryName()), current(ctx)
		},
		start: func(ctx context.Context, owner *app, launch *desktopNodeLaunch, arguments, environment []string, directory string) (desktopNodeProcess, error) {
			want, err := desktopOwnedNodeArguments(launch)
			if err != nil || owner != a || launch != f.launch || directory != launch.directory || launch.command.Process != nil ||
				!reflect.DeepEqual(arguments, want) || !reflect.DeepEqual(environment, launch.command.Env) || arguments[0] != "routervpn-node-candidate-prefix" {
				return nil, errors.New("prefix substituted original closed child command")
			}
			child, err := f.nativeStart(t)
			if err == nil {
				err = f.startFailure
			}
			return child, err
		},
	}
	capture, err := captureDesktopNodeChainHostContextWith(p.operation, a, p.selection, f.readNetwork)
	if err != nil {
		t.Fatal(err)
	}
	f.launch, err = prepareDesktopOwnedCandidatePrefixLaunch(p.operation, capture, p.selection, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	manifest := filepath.Join(root, "runtime", "native", "NATIVE-RUNTIME.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, process := range f.processes {
			process.mu.Lock()
			process.closeErr = nil
			process.mu.Unlock()
		}
		f.kernel.readFail, f.kernel.closeFail = false, false
		_ = p.finish()
		p.cancel()
		if f.launch.directoryRoot != nil {
			_ = f.launch.directoryRoot.Close()
		}
		desktopNodeOwners.Delete(a)
		nativeMultihopOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
		activeDNSRuntimeIdentities.Delete(a)
		speedLabTemporaryOwners.Delete(a)
		sessionTrackers.Delete(a)
	})
	return f
}

func (f *desktopCandidatePrefixOwnedFixture) nativeStart(t *testing.T) (*desktopImportedOwnedProcess, error) {
	t.Helper()
	launch, owned := f.launch, f.launch.ownedNode
	raw, err := readDesktopRuntimeFile(launch, "node-candidate-prefix-source.json", mobilemultihop.NodeChainInputLimit)
	if err != nil {
		return nil, err
	}
	policy, err := mobilemultihop.ParseDesktopNodeCandidatePreparationPolicy(string(raw))
	if err != nil || policy.Config() != launch.candidatePrefix.policy.Config() || !reflect.DeepEqual(policy.Metadata(), launch.candidatePrefix.policy.Metadata()) {
		return nil, errors.Join(err, errors.New("prefix child replay changed its captured policy"))
	}
	meta := policy.Metadata()
	handoff := desktopNodeHandoffRecord{Schema: 1, Kind: "routervpn-node-physical-handoff-v2", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: owned.attempt.digest,
		NetworkID: strings.Repeat("d", 32), Policy: meta.KillSwitchPolicy, BaselineSHA256: strings.Repeat("e", 64), Nonce: strings.Repeat("a", 64)}
	body, _ := json.Marshal(handoff)
	_, target, err := desktopNodeHandoff(body, launch)
	if err != nil {
		return nil, err
	}
	f.kernel.target, f.kernel.locked = copyDesktopNodeProtectionTarget(&target), true
	desktopOwnedNodeTestWrite(t, launch, "node-physical-handoff-ready.json", handoff)
	_, _, physical, err := policy.PhysicalReadValidated()
	if err != nil {
		return nil, err
	}
	f.ready = mobilemultihop.DesktopNodeCandidatePreparationReadyRecord{Schema: 1, Kind: "routervpn-node-candidate-prefix-ready-v1",
		SourceSHA256: meta.SourceSHA256, CaptureSHA256: meta.CaptureSHA256, TransferSHA256: owned.attempt.digest,
		Identity: mobilemultihop.NodeChainIdentity{EngineID: "original-prefix-engine", SessionID: meta.SessionID, NetworkID: "original-prefix-network",
			SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256}, Generation: 1, Reader: 1,
		InterfaceName: "router-vpn", InterfaceIndex: 91, MTU: physical.ConfiguredMTU, ObservedAt: time.Now().UnixMilli(), Prepared: true}
	for i, prefix := range meta.Prefixes {
		f.ready.Prefixes = append(f.ready.Prefixes, mobilemultihop.NodeChainPrefixProgress{Position: i, ProfileID: prefix.ProfileID, Proven: true, ResponseMS: 1})
	}
	network := desktopnetwork.DesktopNetworkReceipt{Schema: 1, TargetOS: runtime.GOOS, Incarnation: strings.Repeat("1", 32),
		Name: f.ready.InterfaceName, Index: f.ready.InterfaceIndex, MTU: f.ready.MTU, Addresses: []string{"172.19.0.1/30"}, Objects: []desktopnetwork.DesktopNetworkObject{}}
	if runtime.GOOS == "windows" {
		network.LUID = 910
	}
	receipt, err := desktopnetwork.CanonicalDesktopNetworkReceipt(network)
	if err != nil {
		return nil, err
	}
	f.live = desktopNodeMTURecord{Schema: 1, Session: meta.SessionID, Config: meta.ConfigSHA256, Path: strings.Repeat("c", 64),
		Reader: 1, Interface: f.ready.InterfaceName, Index: int(f.ready.InterfaceIndex), MTU: f.ready.MTU, Heartbeat: time.Now().UnixMilli(), NetworkReceipt: receipt}
	f.publishHeartbeat(t)
	process := &desktopImportedOwnedProcess{fixture: f.desktopImportedOwnedFixture, launch: launch, target: target, joined: make(chan struct{})}
	f.starts++
	f.processes = append(f.processes, process)
	return process, nil
}

func (f *desktopCandidatePrefixOwnedFixture) publishHeartbeat(t *testing.T) {
	t.Helper()
	for name, value := range map[string]any{"node-candidate-prefix-ready.json": f.ready, "node-mtu-status.json": f.live} {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		pending := "." + name + ".pending"
		if err := f.launch.directoryRoot.WriteFile(pending, body, 0600); err != nil {
			t.Fatal(err)
		}
		if err := f.launch.directoryRoot.Rename(pending, name); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *desktopCandidatePrefixOwnedFixture) stagePublish(t *testing.T) {
	t.Helper()
	if err := stageDesktopNodeLaunchContext(f.operation, f.a, f.launch); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	err := f.a.publishDesktopCandidatePrefixStartLocked(f.operation, f.launch, f.selection)
	f.a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *desktopCandidatePrefixOwnedFixture) start(t *testing.T) {
	t.Helper()
	f.stagePublish(t)
	if err := startDesktopOwnedCandidatePrefixLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopCandidatePrefixOwnedKeepsClosedPurposeAndFullSavedControl(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			f := newDesktopCandidatePrefixOwnedFixture(t, mode, 0)
			before := cloneRouterProfileStore(f.a.profiles)
			f.start(t)
			if f.starts != 1 || f.launch.command.Process != nil || f.launch.chain != nil || f.launch.ownedNode.ready != nil ||
				f.launch.candidatePrefix.ready == nil || f.a.state.Connected || f.a.state.RouterID != f.selection.Control.ID ||
				f.launch.profileID == f.selection.Control.ID || f.a.state.RuntimeMode != mode || !f.kernel.locked {
				t.Fatal("prefix parent borrowed full-path readiness or lost its saved control")
			}
			for _, name := range []string{"node-ready.json", "node-chain-ready.json", "node-dns-result.json"} {
				if _, err := f.launch.directoryRoot.Lstat(name); !os.IsNotExist(err) {
					t.Fatal("prefix child fabricated ordinary proof", name, err)
				}
			}
			if _, err := f.a.readDesktopOwnedNodeReadyContext(f.operation, f.launch, true); err == nil {
				t.Fatal("prefix passed ordinary Ready")
			}
			if _, _, _, err := captureOrderedPerformanceContext(f.operation, f.a); err == nil {
				t.Fatal("prefix granted connected Performance")
			}
			if err := desktopOwnedCandidatePrefixCurrent(f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			if err := f.purpose.retireNative(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !f.purpose.nativeDown || f.kernel.target != nil || f.kernel.locked || f.a.cmd != nil || f.a.state != f.purpose.state ||
				!reflect.DeepEqual(before, f.a.profiles) {
				t.Fatal("prefix native DOWN did not preserve complete saved profile and Home")
			}
			if _, err := os.Lstat(f.launch.directory); !os.IsNotExist(err) {
				t.Fatal("joined prefix workspace remained", err)
			}
		})
	}
}

func TestDesktopCandidatePrefixOwnedRejectsForeignObservation(t *testing.T) {
	for _, fault := range []string{"untested-member", "selected-control", "controller", "network", "source", "ready-source", "ready-generation", "ready-stale", "ready-application", "ready-dns", "ready-missing", "mtu-reader", "mtu-path", "mtu-receipt", "mixed-policy"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopCandidatePrefixOwnedFixture(t, "wg", 0)
			f.start(t)
			switch fault {
			case "untested-member":
				f.a.profiles.Profiles[1].APIToken += "-replaced"
			case "selected-control":
				f.a.state.RouterID = f.launch.profileID
			case "controller":
				f.controller.Store(true)
			case "network":
				f.network.Store("replacement-network")
			case "source":
				f.launch.ownedNode.source = append(f.launch.ownedNode.source, '\n')
			case "ready-source":
				f.ready.SourceSHA256 = strings.Repeat("f", 64)
			case "ready-generation":
				f.ready.Generation++
			case "ready-stale":
				f.ready.ObservedAt = time.Now().Add(-3 * time.Second).UnixMilli()
			case "ready-application":
				f.ready.ApplicationOpen = true
			case "ready-dns":
				f.ready.DNSOpen = true
			case "mtu-reader":
				f.live.Reader++
			case "mtu-path":
				f.live.Path = strings.Repeat("f", 64)
			case "mtu-receipt":
				f.live.NetworkReceipt = ""
			case "mixed-policy":
				f.launch.ownedNode.policy = &mobilemultihop.DesktopNodePolicy{}
			}
			f.publishHeartbeat(t)
			if fault == "ready-missing" {
				if err := f.launch.directoryRoot.Remove("node-candidate-prefix-ready.json"); err != nil {
					t.Fatal(err)
				}
			}
			if err := desktopOwnedCandidatePrefixCurrent(f.operation, f.a, f.launch); err == nil {
				t.Fatal("prefix observation accepted substituted original owner", fault)
			}
			// Restore only modeled kernel/controller state for the exact cleanup.
			f.launch.ownedNode.policy = nil
		})
	}
}

func TestDesktopCandidatePrefixOwnedRetainsFailedOriginalCleanup(t *testing.T) {
	f := newDesktopCandidatePrefixOwnedFixture(t, "wg", 1)
	f.startFailure = errors.New("modeled failure after original prefix child creation")
	f.stagePublish(t)
	if err := startDesktopOwnedCandidatePrefixLaunch(f.operation, f.operation, f.a, f.launch); err == nil {
		t.Fatal("partial start unexpectedly succeeded")
	}
	if len(f.processes) != 1 || desktopOwnedNodeProcess(f.launch) != f.processes[0] {
		t.Fatal("prefix partial start lost original process")
	}
	child := f.processes[0]
	child.closeErr = errors.New("original modeled prefix child still joining")
	if err := f.purpose.retireNative(context.Background()); err == nil || f.launch.ownedNode.retired || f.purpose.nativeDown || f.a.cmd != f.launch.command {
		t.Fatal("prefix native DOWN preceded original child join")
	}
	if _, err := os.Stat(f.launch.directory); err != nil {
		t.Fatal("prefix failed cleanup deleted original workspace", err)
	}
	child.closeErr = nil
	if err := f.purpose.retireNative(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.purpose.nativeDown || !child.closed || f.kernel.target != nil {
		t.Fatal("prefix retry did not retire its original owner")
	}
}

func TestDesktopCandidatePrefixOwnedLateCleanupPreservesReplacement(t *testing.T) {
	f := newDesktopCandidatePrefixOwnedFixture(t, "wg", 0)
	f.start(t)
	replacement := &exec.Cmd{}
	f.a.cmd = replacement
	f.a.state.RouterID, f.a.state.Phase = "replacement", "starting"
	replacementState := f.a.state
	if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err != nil {
		t.Fatal(err)
	}
	if err := f.purpose.finishWindowsNativeDown(context.Background(), f.launch); err != nil {
		t.Fatal(err)
	}
	if f.a.cmd != replacement || f.a.state != replacementState {
		t.Fatal("late prefix cleanup replaced newer Home or command")
	}
}

func TestDesktopCandidatePrefixOwnedCommandAndProtectionRemainTyped(t *testing.T) {
	f := newDesktopCandidatePrefixOwnedFixture(t, "wg", 0)
	f.stagePublish(t)
	args, err := desktopOwnedNodeArguments(f.launch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateDesktopNodeCandidatePrefixProcessArguments(args, f.launch.directory); err != nil {
		t.Fatal(err)
	}
	if _, err := validateDesktopNodeProcessArguments(args, f.launch.directory); err == nil {
		t.Fatal("prefix command became ordinary node")
	}
	if _, err := validateDesktopNodeChainProcessArguments(args, f.launch.directory); err == nil {
		t.Fatal("prefix command became complete chain")
	}
	for _, fault := range []string{"command", "capture-missing", "capture-foreign", "capture-duplicate", "imported", "directory"} {
		copy := append([]string(nil), args...)
		switch fault {
		case "command":
			copy[0] = "routervpn-node-chain"
		case "capture-missing":
			copy = copy[:len(copy)-2]
		case "capture-foreign":
			copy[len(copy)-1] = "not-a-capture"
		case "capture-duplicate":
			copy = append(copy, "--prefix-capture-sha256", strings.Repeat("d", 64))
		case "imported":
			copy[7] = "--imported-source-sha256"
		case "directory":
			copy[2] = filepath.Dir(f.launch.directory)
		}
		if _, err := validateDesktopNodeCandidatePrefixProcessArguments(copy, f.launch.directory); err == nil {
			t.Fatal("prefix argv accepted foreign purpose", fault)
		}
	}
	attempt := f.launch.ownedNode.attempt
	if !attempt.matchesOwned(f.launch.ownedNode) {
		t.Fatal("prefix lost original typed protection")
	}
	attempt.chain = &mobilemultihop.DesktopNodeChainPolicy{}
	if attempt.matchesOwned(f.launch.ownedNode) {
		t.Fatal("prefix protection borrowed another concrete family")
	}
	if _, err := attempt.selection(); err == nil {
		t.Fatal("mixed prefix selection accepted")
	}
	attempt.chain = nil
}

func TestDesktopCandidatePrefixOwnedAlwaysProtectionKeepsFullSavedControl(t *testing.T) {
	f := newDesktopCandidatePrefixOwnedFixture(t, "wg", 0, func(a *app) {
		// A stronger original member can require retained protection even while
		// the saved full control is a different, on-connect profile.
		a.profiles.Profiles[0].KillSwitchPolicy = "always"
	})
	f.start(t)
	policy := f.launch.candidatePrefix.policy
	if policy.Metadata().ProfileID == f.selection.Control.ID || policy.Metadata().KillSwitchPolicy != "always" {
		t.Fatal("fixture omitted distinct prefix and saved control identities")
	}
	selection, err := f.launch.ownedNode.attempt.selection()
	if err != nil || selection.profileID != f.selection.Control.ID ||
		f.launch.ownedNode.attempt.profileRevision != desktopOwnedNodeProfileToken(f.selection.Control) {
		t.Fatal("prefix protection attributed the saved control revision to another member", err)
	}
	if err := f.purpose.retireNative(context.Background()); err != nil {
		t.Fatal(err)
	}
	slot := f.launch.ownedNode.slot
	if slot.target == nil || slot.target.Policy != "always" || f.kernel.locked ||
		slot.binding.ProfileID != f.selection.Control.ID || slot.profileRevision != desktopOwnedNodeProfileToken(f.selection.Control) ||
		f.a.profiles.SelectedID != f.selection.Control.ID {
		t.Fatal("retained prefix protection lost full saved control attribution")
	}
	capture := f.a.captureProfileProtection(f.selection.Control)
	view := protectionSettingsWithCapture(f.selection.Control, capture)
	if view.ProtectionProfileID != f.selection.Control.ID || view.ProtectionStatus != "retained" || view.EffectivePolicy != "always" || view.Message != "" {
		t.Fatal("prefix protection UI directed Off to an unrelated member", view)
	}
	// Capture the real Off transaction without removing the modeled baseline.
	// It must preserve both the selected full control and its source revision.
	slot.backend.recover = slot.backend.release
	off, err := slot.captureOff(context.Background(), f.selection.Control.ID, capture.revision, capture.resultRevision, capture.token)
	if err != nil || off.profileID != f.selection.Control.ID || off.sourceRevision != desktopOwnedNodeProfileToken(f.selection.Control) {
		t.Fatal("prefix Off capture used a different original profile", err)
	}
}
