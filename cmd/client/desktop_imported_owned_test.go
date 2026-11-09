//go:build go1.25

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// The shared constructors, private files, actual parent process/admission
// dispatch, readiness parser and succession slot execute unchanged. Only the
// authenticated Windows controller, child/kernel and physical inventory are
// modeled. Native BFE/Box traffic remains a separate platform acceptance gate.
type desktopImportedOwnedFixture struct {
	a          *app
	selection  multihopSelection
	launch     *desktopNodeLaunch
	kernel     *desktopNodeProtectionFixture
	operation  context.Context
	cancel     context.CancelFunc
	network    atomic.Value
	controller atomic.Bool
	starts     int
	processes  []*desktopImportedOwnedProcess
	onStart    func(context.Context, *desktopImportedOwnedProcess)
}

type desktopImportedOwnedProcess struct {
	mu       sync.Mutex
	fixture  *desktopImportedOwnedFixture
	launch   *desktopNodeLaunch
	target   mobiletor.DesktopWindowsProtectionTarget
	joined   chan struct{}
	closed   bool
	closes   int
	closeErr error
}

func (p *desktopImportedOwnedProcess) Started() bool { return true }
func (p *desktopImportedOwnedProcess) Alive() error {
	return p.AliveContext(context.Background())
}
func (p *desktopImportedOwnedProcess) AliveContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("modeled exact imported child has joined")
	}
	return nil
}
func (p *desktopImportedOwnedProcess) Wait(ctx context.Context) (uint32, error) {
	if ctx == nil {
		return 0, errors.New("modeled imported child wait has no caller")
	}
	p.mu.Lock()
	joined := p.joined
	p.mu.Unlock()
	if joined == nil {
		return 0, errors.New("modeled imported child lost its captured join")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-joined:
		return 0, ctx.Err()
	}
}
func (p *desktopImportedOwnedProcess) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	if ctx.Err() != nil || p.closeErr != nil {
		return errors.Join(ctx.Err(), p.closeErr)
	}
	if p.closed {
		return nil
	}
	// The modeled native child returns only its own target; replacing the
	// kernel owner cannot be repaired by writing a different retirement file.
	for name, value := range map[string]any{
		"node-protection-retired.json": desktopNodeProtectionRetired(p.launch.ownedNode.attempt, &p.target),
		"stopped.json":                 desktopExternalStop{Schema: 1, SessionID: p.launch.mtuSession, SourceSHA256: p.launch.configSHA256, Closed: true},
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := writeDesktopRuntimeFile(p.launch, name, raw, false); err != nil {
			return err
		}
	}
	if p.fixture.kernel.target != nil && *p.fixture.kernel.target == p.target {
		p.fixture.kernel.locked = false
	}
	p.closed = true
	close(p.joined)
	return nil
}

func newDesktopImportedOwnedFixture(t *testing.T, protocol, finalMode, policy string, configure ...func(*multihopSelection)) *desktopImportedOwnedFixture {
	t.Helper()
	root, selection := desktopImportedFixture(t, protocol, finalMode)
	selection.Exit.KillSwitch, selection.Exit.KillSwitchPolicy = true, policy
	selection.Exit.MTUPolicy, selection.Exit.ManualMTU, selection.Exit.EffectiveMTU = "auto", 0, 9000
	selection.Exit.IPv6Mode = "off"
	for _, apply := range configure {
		apply(&selection)
	}
	selection.Control = cloneRouterProfile(selection.Exit)
	operation, cancel := context.WithCancel(context.Background())
	f := &desktopImportedOwnedFixture{operation: operation, cancel: cancel, kernel: &desktopNodeProtectionFixture{}}
	f.network.Store("original-imported-physical-network")
	f.a = &app{connectionContext: operation, connectionCancel: cancel,
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json"), ScriptsDir: filepath.Join(root, "modes")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion, SelectedID: selection.Control.ID,
			Profiles: []common.RouterProfile{cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)}},
		state: state{Mode: "off", Phase: "off"}, nodeProtection: &desktopNodeProtectionSlot{backend: f.kernel.backend()}}
	packageRoot := filepath.Join(root, "captured-package")
	current := func(ctx context.Context) error {
		if f.controller.Load() {
			return errors.New("modeled original Windows controller replaced")
		}
		return ctx.Err()
	}
	f.a.nodeConnectionHost = &desktopNodeConnectionHost{
		capture: func(a *app) (desktopOwnedNodePreparation, error) {
			if a != f.a {
				return desktopOwnedNodePreparation{}, errors.New("captured another application")
			}
			return desktopOwnedNodePreparation{packageRoot: packageRoot, dataRoot: root, lifetime: operation,
				current: func() error { return current(context.Background()) }, currentContext: current,
				protectionBackend: func() (desktopNodeProtectionBackend, error) { return f.kernel.backend(), current(context.Background()) }}, nil
		},
		verify: func(ctx context.Context, path string) (string, error) {
			if path != packageRoot {
				return "", errors.New("substituted a different package")
			}
			return filepath.Join(packageRoot, "runtime", "native", nativeBinaryName()), current(ctx)
		},
		start: func(ctx context.Context, a *app, launch *desktopNodeLaunch, arguments, environment []string, directory string) (desktopNodeProcess, error) {
			if a != f.a || directory != launch.directory || launch.command.Process != nil || !reflect.DeepEqual(launch.command.Env, environment) {
				return nil, errors.New("typed parent substituted a process, directory or environment")
			}
			want, err := desktopOwnedNodeArguments(launch)
			if err != nil || !reflect.DeepEqual(arguments, want) || !strings.Contains(strings.Join(arguments, " "), "--imported-source-sha256") {
				return nil, errors.New("typed parent did not dispatch its original imported command")
			}
			p, err := f.nativeStart(t, launch)
			if err == nil && f.onStart != nil {
				f.onStart(ctx, p)
			}
			return p, err
		},
	}
	var err error
	f.selection, err = captureNativeMultihopForAppContext(operation, f.a, selection, []string{finalMode})
	if err != nil {
		t.Fatal(err)
	}
	f.launch, err = prepareDesktopOwnedImportedLaunchWith(operation, f.a, f.selection, f.readNetwork)
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
		cancel()
		for _, child := range f.processes {
			_ = child.Close(context.Background())
		}
		if f.launch.directoryRoot != nil {
			_ = f.launch.directoryRoot.Close()
		}
		_ = f.launch.ownedNode.closeImportedConstructor()
		desktopNodeOwners.Delete(f.a)
		nativeMultihopOwners.Delete(f.a)
		activeMultihopGraphs.Delete(f.a)
		activeDNSRuntimeIdentities.Delete(f.a)
		speedLabTemporaryOwners.Delete(f.a)
		sessionTrackers.Delete(f.a)
	})
	return f
}

func (f *desktopImportedOwnedFixture) readNetwork(ctx context.Context) (string, error) {
	return f.network.Load().(string), ctx.Err()
}

func (f *desktopImportedOwnedFixture) nativeStart(t *testing.T, launch *desktopNodeLaunch) (*desktopImportedOwnedProcess, error) {
	t.Helper()
	owned := launch.ownedNode
	// Reconstruct the child inputs independently from the actual private
	// producer file; the child cannot reuse a parent object as its authority.
	raw, err := readDesktopRuntimeFile(launch, "imported-source.json", mobilemultihop.ImportedLaunchInputLimit)
	if err != nil {
		return nil, err
	}
	original, err := mobilemultihop.ParseImportedLaunchInput(string(raw))
	if err != nil {
		return nil, err
	}
	defer original.Close()
	meta := owned.imported.policy.Metadata()
	policy, err := mobilemultihop.NewDesktopImportedPolicyWithMTU(original, meta.SessionID, "windows", meta.RestoredMTU)
	if err != nil || !reflect.DeepEqual(policy.Metadata(), meta) || policy.Config() != owned.imported.policy.Config() {
		return nil, errors.Join(err, errors.New("child parser changed original imported policy"))
	}
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
	_, commonMeta, capture, err := owned.physicalState()
	if err != nil {
		return nil, err
	}
	mtu := capture.ConfiguredMTU
	if commonMeta.RestoredMTU != 0 {
		mtu = commonMeta.RestoredMTU
	}
	ready := mobilemultihop.DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: owned.attempt.digest,
		DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: "router-vpn", InterfaceIndex: 71,
		MTU: mtu, ProvedAt: time.Now().UnixMilli(), DNSMilliseconds: 1.25}
	live := desktopNodeMTURecord{Schema: 1, Session: meta.SessionID, Config: meta.ConfigSHA256, Path: strings.Repeat("f", 64),
		Reader: 1, Interface: ready.InterfaceName, Index: int(ready.InterfaceIndex), MTU: mtu, Heartbeat: time.Now().UnixMilli()}
	desktopOwnedNodeTestWrite(t, launch, "node-ready.json", ready)
	desktopOwnedNodeTestWrite(t, launch, "node-mtu-status.json", live)
	p := &desktopImportedOwnedProcess{fixture: f, launch: launch, target: target, joined: make(chan struct{})}
	f.starts++
	f.processes = append(f.processes, p)
	return p, nil
}

func (f *desktopImportedOwnedFixture) stage(t *testing.T) {
	t.Helper()
	if err := stageOwnedNativeMultihopCommandContext(f.operation, f.a, f.selection, f.launch); err != nil {
		t.Fatal(err)
	}
}

func (f *desktopImportedOwnedFixture) publish(t *testing.T) {
	t.Helper()
	f.a.mu.Lock()
	err := f.a.publishDesktopImportedMultihopStartLocked(f.operation, f.launch, f.selection)
	f.a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	setActiveMultihopGraph(f.a, f.selection)
	if err := bindNativeMultihopRuntimeContext(f.operation, f.a, f.launch, f.selection, f.network.Load().(string)); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopImportedOwnedSourceAndNativeDispatch(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, protocol, "reality-vision", "always")
			before := cloneRouterProfileStore(f.a.profiles)
			if f.launch.ownedNode.policy != nil || f.launch.ownedNode.imported.policy.Metadata().EntryID != f.selection.Entry.ID {
				t.Fatal("imported entry was coerced into ordinary Node authority")
			}
			if _, err := compileRetainedNativeMultihopLaunch(f.selection, nil); err == nil {
				t.Fatal("protected capture silently used a legacy helper")
			}
			f.stage(t)
			if !reflect.DeepEqual(before, f.a.profiles) || f.kernel.target != nil || f.starts != 0 {
				t.Fatal("private staging changed profiles or acquired kernel/runtime ownership")
			}
			if _, err := os.Lstat(filepath.Join(f.launch.directory, "node-source.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("imported producer emitted an ordinary-node source")
			}
			identity, ok := activeDNSRuntimeIdentities.Load(f.a)
			if !ok || identity.(activeDNSRuntimeIdentity).ImportedEntry != true || identity.(activeDNSRuntimeIdentity).ProfileID != f.selection.Exit.ID {
				t.Fatal("typed command lost imported final DNS ownership")
			}
			f.publish(t)
			caller, cancel := context.WithCancel(f.operation)
			if err := startDesktopOwnedImportedLaunch(caller, f.operation, f.a, f.launch); err != nil {
				cancel()
				t.Fatal(err)
			}
			cancel()
			if f.starts != 1 || f.launch.command.Process != nil || f.launch.ownedNode.operation != f.operation ||
				f.a.desktopOwnedNodeCurrentContext(context.Background(), f.launch, true) != nil || f.a.state.Connected {
				t.Fatal("startup replaced operation lifetime or invented connected proof")
			}
			if _, err := f.a.readDesktopOwnedNodeReadyContext(context.Background(), f.launch, false); err != nil {
				t.Fatal("parsed readiness did not retain both original inputs", err)
			}
		})
	}
}

func TestDesktopImportedOwnedDynamicRelayRequiresTypedHost(t *testing.T) {
	f := newDesktopImportedOwnedFixture(t, "socks5", "shadowsocks", "always")
	meta := f.launch.ownedNode.imported.policy.Metadata()
	if !meta.SOCKSUDPAssociationRequired {
		t.Fatal("typed SOCKS graph lost its negotiated relay requirement")
	}
	for _, socket := range f.launch.nodePhysicalEgress {
		if socket.Network == "udp" {
			t.Fatal("static parent capture invented a SOCKS UDP permit", socket)
		}
	}
	if _, err := captureNativeMultihopSelection(context.Background(), f.launch.root, f.selection, []string{f.selection.ExitMode}, nil); !errors.Is(err, mobilemultihop.ErrDynamicPhysicalEgress) {
		t.Fatal("legacy capture acquired typed dynamic-relay authority", err)
	}
	f.stage(t)
	f.publish(t)
	if err := startDesktopOwnedImportedLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopImportedOwnedCommandRejectsMixedFamilies(t *testing.T) {
	f := newDesktopImportedOwnedFixture(t, "shadowsocks", "reality-vision", "always")
	f.stage(t)
	args, err := desktopOwnedNodeArguments(f.launch)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"both-sources", "missing-source", "unbounded-source", "other-directory", "external-command", "duplicate-source", "relative-directory"} {
		t.Run(fault, func(t *testing.T) {
			changed := append([]string(nil), args...)
			switch fault {
			case "both-sources":
				changed = append(changed, "--physical-source-sha256", strings.Repeat("b", 64))
			case "missing-source":
				changed = append(changed[:7], changed[9:]...)
			case "unbounded-source":
				changed[8] = strings.Repeat("b", 65)
			case "other-directory":
				changed[2] = filepath.Join(f.launch.directory, "other")
			case "external-command":
				changed[0] = "routervpn-external"
			case "duplicate-source":
				changed = append(changed, "--imported-source-sha256", changed[8])
			case "relative-directory":
				changed[2] = "relative"
			}
			if _, err := validateDesktopNodeProcessArguments(changed, f.launch.directory); err == nil {
				t.Fatal("malformed source-family command reached native admission")
			}
			command := &exec.Cmd{Args: append([]string{"captured-native"}, changed...), Dir: f.launch.directory}
			if fault != "external-command" {
				if _, err := nativeMultihopRuntimeDirFromCommand(command); err == nil {
					t.Fatal("malformed typed command registered a DNS workspace")
				}
			}
		})
	}
	external := append([]string(nil), args...)
	external[0] = "routervpn-external"
	if _, err := validateDesktopExternalProcessArguments(external, f.launch.directory); err == nil {
		t.Fatal("ordinary external process borrowed imported authority")
	}
}

func TestDesktopImportedOwnedSuccessionRetainsLatestPredecessor(t *testing.T) {
	for _, kill := range []string{"on-connect", "always"} {
		t.Run(kill, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, "shadowsocks", "reality-vision", kill)
			slot := f.a.nodeProtection
			original := desktopNodeProtectionPolicy(t, "1", kill, 0)
			a, err := slot.begin(f.operation, &desktopNodeLaunch{}, original)
			if err != nil {
				t.Fatal(err)
			}
			targetA := desktopNodeProtectionInstalled(original)
			f.kernel.target, f.kernel.locked = copyDesktopNodeProtectionTarget(&targetA), true
			if err := slot.provePrepared(f.operation, a, targetA, func() bool { return true }); err != nil {
				t.Fatal(err)
			}
			if err := slot.finish(f.operation, a, desktopNodeProtectionRetired(a, &targetA), func(context.Context) error { f.kernel.locked = false; return nil }); err != nil {
				t.Fatal(err)
			}
			f.stage(t)
			if got := f.launch.ownedNode.attempt.transfer.Predecessor; got == nil || *got != targetA {
				t.Fatal("temporary imported graph lost original joined predecessor")
			}
			f.publish(t)
			if err := startDesktopOwnedImportedLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			child := f.processes[0]
			targetB := child.target
			child.closeErr = errors.New("modeled child descendants still joining")
			if err := f.a.retireDesktopOwnedNode(f.operation, f.launch); err == nil || slot.active != f.launch.ownedNode.attempt || f.launch.ownedNode.imported.policy.Validate() != nil {
				t.Fatal("failed close discarded the original constructor or protection attempt", err)
			}
			child.closeErr = nil
			if err := f.a.retireDesktopOwnedNode(f.operation, f.launch); err != nil || slot.active != nil || slot.target == nil || *slot.target != targetB || !child.closed {
				t.Fatal("temporary imported child did not independently settle its latest target", err)
			}
			if f.launch.ownedNode.imported.policy.Validate() == nil {
				t.Fatal("retired pure constructor stayed eligible for reuse")
			}
			restored := desktopNodeProtectionPolicy(t, "3", kill, 1280)
			aPrime, err := slot.begin(f.operation, &desktopNodeLaunch{}, restored)
			if err != nil || aPrime.transfer.Predecessor == nil || *aPrime.transfer.Predecessor != targetB || *aPrime.transfer.Predecessor == targetA {
				t.Fatal("restored original graph reused A instead of the joined imported target B", err)
			}
			latest := desktopNodeProtectionInstalled(restored)
			f.kernel.target, f.kernel.locked = &latest, true
			closes := child.closes
			if err := f.a.retireDesktopOwnedNode(f.operation, f.launch); err != nil || slot.active != aPrime || !f.kernel.locked || *f.kernel.target != latest || child.closes != closes {
				t.Fatal("late imported cleanup touched restored A-prime", err)
			}
			if err := slot.provePrepared(f.operation, aPrime, latest, func() bool { return true }); err != nil {
				t.Fatal(err)
			}
			if err := slot.finish(f.operation, aPrime, desktopNodeProtectionRetired(aPrime, &latest), func(context.Context) error { f.kernel.locked = false; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := slot.release(f.operation); err != nil || (slot.target != nil) != (kill == "always") {
				t.Fatal("normal release lost the captured Always/on-connect policy", err)
			}
		})
	}
}

func TestDesktopImportedOwnedRestorationKeepsGraphHostAndLiveMTU(t *testing.T) {
	f := newDesktopImportedOwnedFixture(t, "hysteria2", "shadowsocks", "always")
	f.stage(t)
	f.publish(t)
	if err := startDesktopOwnedImportedLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
		t.Fatal(err)
	}
	live, err := readDesktopNodeMTUContext(f.operation, f.launch)
	if err != nil {
		t.Fatal(err)
	}
	live.Reader, live.MTU = 2, 1280
	desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
	graph, _ := getActiveMultihopGraph(f.a)
	selection, err := captureNativeMultihopRestoreContext(f.operation, f.a, f.launch.command, graph, f.selection.Control, f.selection.Entry, f.selection.Exit)
	if err != nil || selection.restoreMTU != 1280 || selection.Native != f.selection.Native || selection.Native.importedHost != f.launch.ownedNode.host {
		t.Fatal("restoration lost its original graph/host or reused historical 9000-byte MTU", err)
	}
	old := f.launch
	meta := old.ownedNode.imported.policy.Metadata()
	if err := f.a.retireDesktopOwnedNode(f.operation, old); err != nil {
		t.Fatal(err)
	}
	retained := copyDesktopNodeProtectionTarget(f.a.nodeProtection.target)
	desktopNodeOwners.CompareAndDelete(f.a, old)
	nativeMultihopOwners.Delete(f.a)
	f.a.cmd = nil
	restored, err := prepareDesktopOwnedImportedLaunchWith(f.operation, f.a, selection, f.readNetwork)
	if err != nil {
		t.Fatal(err)
	}
	newMeta := restored.ownedNode.imported.policy.Metadata()
	if restored.ownedNode.host != old.ownedNode.host || newMeta.OriginalSourceSHA256 != meta.OriginalSourceSHA256 ||
		newMeta.OriginalCaptureSHA256 != meta.OriginalCaptureSHA256 || newMeta.SourceSHA256 == meta.SourceSHA256 ||
		newMeta.SessionID == meta.SessionID || newMeta.RestoredMTU != 1280 || restored.ownedNode.imported.policy.OriginalController() == old.ownedNode.imported.policy.OriginalController() {
		t.Fatal("restoration reacquired different original inputs or reused retired session")
	}
	f.launch, f.selection = restored, selection
	f.stage(t)
	defer restored.directoryRoot.Close()
	if got := restored.ownedNode.attempt.transfer.Predecessor; got == nil || *got != *retained {
		t.Fatal("restoration did not consume newest joined target")
	}
	f.publish(t)
	if err := startDesktopOwnedImportedLaunch(f.operation, f.operation, f.a, restored); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.readDesktopOwnedNodeReadyContext(f.operation, restored, false); err != nil {
		t.Fatal(err)
	}
	if old.directoryRoot != nil {
		_ = old.directoryRoot.Close()
	}
}

func TestDesktopImportedOwnedCancellationAndReplacementKeepCleanup(t *testing.T) {
	for _, fault := range []string{"caller", "operation", "entry-source", "final-source", "network", "controller", "native-ready-source", "native-ready-dns"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, "shadowsocks", "reality-vision", "always")
			f.stage(t)
			f.publish(t)
			caller, cancel := context.WithCancel(f.operation)
			defer cancel()
			f.onStart = func(_ context.Context, p *desktopImportedOwnedProcess) {
				switch fault {
				case "caller":
					cancel()
				case "operation":
					f.a.connectionCancelIntent = f.operation
				case "entry-source":
					f.a.profiles.Profiles[0].External.ExpectedPublicIP = "203.0.113.239"
				case "final-source":
					f.a.profiles.Profiles[1].APIToken = "same-id-different-private-pairing"
				case "network":
					f.network.Store("replacement-physical-network")
				case "controller":
					f.controller.Store(true)
					f.kernel.readFail = true
				case "native-ready-source", "native-ready-dns":
					raw, err := readDesktopRuntimeFile(p.launch, "node-ready.json", mobilemultihop.DesktopNodeReadyRecordLimit)
					var ready mobilemultihop.DesktopNodeReadyRecord
					if err != nil || json.Unmarshal(raw, &ready) != nil {
						t.Fatal("modeled child readiness unavailable", err)
					}
					if fault == "native-ready-source" {
						ready.SourceSHA256 = strings.Repeat("b", 64)
					} else {
						ready.DNSConfigSHA256 = strings.Repeat("b", 64)
					}
					desktopOwnedNodeTestWrite(t, p.launch, "node-ready.json", ready)
				}
			}
			if err := startDesktopOwnedImportedLaunch(caller, f.operation, f.a, f.launch); err == nil || f.starts != 1 || f.launch.ownedNode.process != f.processes[0] || f.launch.ownedNode.ready != nil || f.a.state.Connected {
				t.Fatal("changed startup accepted readiness or lost its partial native child", err)
			}
			if fault == "controller" {
				if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err == nil || f.a.nodeProtection.active != f.launch.ownedNode.attempt || f.launch.ownedNode.imported.policy.Validate() != nil {
					t.Fatal("missing original controller discarded unresolved protected ownership", err)
				}
				f.controller.Store(false)
				f.kernel.readFail = false
			}
			if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err != nil || !f.processes[0].closed || f.a.nodeProtection.active != nil || f.a.nodeProtection.target == nil {
				t.Fatal("cancelled startup failed to join original child and settle exact protected target", err)
			}
		})
	}
}

func TestDesktopImportedOwnedCancelledAdmissionDoesNotWaitForHeldLock(t *testing.T) {
	for _, held := range []string{"application", "workspace"} {
		t.Run(held, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, "shadowsocks", "reality-vision", "always")
			f.stage(t)
			f.publish(t)
			gate := &f.a.mu
			if held == "workspace" {
				gate = &f.launch.workspaceMu
			}
			gate.Lock()
			caller, cancel := context.WithCancel(f.operation)
			done := make(chan error, 1)
			go func() { done <- startDesktopOwnedImportedLaunch(caller, f.operation, f.a, f.launch) }()
			cancel()
			select {
			case err := <-done:
				gate.Unlock()
				if err == nil || f.starts != 0 || !f.launch.ownedNode.started.IsZero() {
					t.Fatal("cancelled original caller reached native process creation", err)
				}
			case <-time.After(2 * time.Second):
				gate.Unlock()
				<-done
				t.Fatal("cancelled startup retained a background admission lock")
			}
		})
	}
}

func TestDesktopImportedOwnedPublicationPreservesReplacement(t *testing.T) {
	for _, fault := range []string{"command", "owner", "operation", "entry", "policy-family"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, "shadowsocks", "reality-vision", "always")
			f.stage(t)
			replacement := &desktopNodeLaunch{command: &exec.Cmd{}}
			switch fault {
			case "command":
				f.a.cmd = replacement.command
			case "owner":
				desktopNodeOwners.Store(f.a, replacement)
			case "operation":
				f.a.connectionCancelIntent = f.operation
			case "entry":
				f.a.profiles.Profiles[0].External.ExpectedPublicIP = "203.0.113.233"
			case "policy-family":
				f.launch.ownedNode.policy = desktopNodeProtectionPolicy(t, "9", "always", 0)
			}
			before := f.a.state
			f.a.mu.Lock()
			err := f.a.publishDesktopImportedMultihopStartLocked(f.operation, f.launch, f.selection)
			f.a.mu.Unlock()
			if err == nil || f.a.state != before || f.starts != 0 {
				t.Fatal("stale imported publication altered another connection", err)
			}
			if fault == "command" && f.a.cmd != replacement.command {
				t.Fatal("stale publication replaced a newer command")
			}
			if fault == "owner" {
				if current, found := desktopNodeOwners.Load(f.a); !found || current != replacement {
					t.Fatal("stale publication replaced a newer runtime owner")
				}
			}
		})
	}
}

func TestDesktopImportedOwnedDerivedConfigKeepsOriginalEnvelope(t *testing.T) {
	for _, fault := range []string{"valid", "legacy-config", "derived-digest", "session", "source-envelope", "equivalent-host", "entry-capture", "edited-file"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, "shadowsocks", "reality-vision", "always")
			actual := []byte(f.launch.ownedNode.imported.policy.Config())
			switch fault {
			case "legacy-config":
				actual = []byte(f.selection.Native.configs[f.selection.ExitMode])
			case "derived-digest":
				f.launch.configSHA256 = strings.Repeat("b", 64)
			case "session":
				f.launch.mtuSession = strings.Repeat("b", 32)
			case "source-envelope":
				f.launch.ownedNode.source = append([]byte(nil), f.launch.ownedNode.source...)
				f.launch.ownedNode.source[len(f.launch.ownedNode.source)-2] ^= 1
			case "equivalent-host":
				copy := *f.launch.ownedNode.host
				f.launch.ownedNode.host = &copy
			case "entry-capture":
				f.launch.ownedNode.imported.selection.Entry = cloneRouterProfile(f.selection.Entry)
				f.launch.ownedNode.imported.selection.Entry.External.ExpectedPublicIP = "203.0.113.230"
			case "edited-file":
				actual[len(actual)-2] ^= 1
			}
			err := validateDesktopOwnedImportedConfigContext(f.operation, f.launch, actual)
			if (err == nil) != (fault == "valid") {
				t.Fatal("derived physical config lost its distinct original constructor identity", fault, err)
			}
		})
	}
}
