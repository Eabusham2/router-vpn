package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
)

// These tests execute the existing parent source, staging, protection slot,
// start, heartbeat and retirement paths. The Windows controller/child/kernel
// are explicit models; encrypted and native OS acceptance remain separate.
type desktopNodeChainOwnedFixture struct {
	*desktopImportedOwnedFixture
	executionModel        *desktopExecutionOwnedModel
	capture               *desktopNodeChainHostCapture
	ready                 mobilemultihop.DesktopNodeChainReadyRecord
	live                  desktopNodeMTURecord
	heartbeat             sync.Mutex
	pulseDone             chan struct{}
	pulseErr              error
	staleProof, omitProof bool
}

func newDesktopNodeChainOwnedFixture(t *testing.T, count int) *desktopNodeChainOwnedFixture {
	t.Helper()
	a, selection := desktopNodeChainHostSelectionFixture(t, count)
	return newDesktopNodeChainOwnedFixtureWith(t, a, selection)
}
func newDesktopNodeChainOwnedFixtureWith(t *testing.T, a *app, selection multihopSelection) *desktopNodeChainOwnedFixture {
	t.Helper()
	operation, cancel := context.WithCancel(context.Background())
	f := &desktopNodeChainOwnedFixture{desktopImportedOwnedFixture: &desktopImportedOwnedFixture{
		a: a, selection: selection, operation: operation, cancel: cancel, kernel: &desktopNodeProtectionFixture{}}}
	a.connectionContext, a.connectionCancel = operation, cancel
	a.nodeProtection = &desktopNodeProtectionSlot{backend: f.kernel.backend()}
	root := clientRoot(a)
	packageRoot := filepath.Join(root, "captured-package")
	current := func(ctx context.Context) error {
		if f.controller.Load() {
			return errors.New("original modeled chain controller replaced")
		}
		return ctx.Err()
	}
	a.nodeConnectionHost = &desktopNodeConnectionHost{
		capture: func(owner *app) (desktopOwnedNodePreparation, error) {
			if owner != a {
				return desktopOwnedNodePreparation{}, errors.New("foreign chain application")
			}
			return desktopOwnedNodePreparation{packageRoot: packageRoot, dataRoot: root, lifetime: operation,
				current: func() error { return current(context.Background()) }, currentContext: current,
				protectionBackend: func() (desktopNodeProtectionBackend, error) { return f.kernel.backend(), current(context.Background()) }}, nil
		},
		verify: func(ctx context.Context, path string) (string, error) {
			if path != packageRoot {
				return "", errors.New("chain substituted installed package")
			}
			return filepath.Join(packageRoot, "runtime", "native", nativeBinaryName()), current(ctx)
		},
		start: func(ctx context.Context, owner *app, launch *desktopNodeLaunch, arguments, environment []string, directory string) (desktopNodeProcess, error) {
			want, err := desktopOwnedNodeArguments(launch)
			if err != nil || owner != a || launch != f.launch || directory != launch.directory || launch.command.Process != nil ||
				!reflect.DeepEqual(arguments, want) || !reflect.DeepEqual(environment, launch.command.Env) || arguments[0] != launch.chain.commandName() {
				return nil, errors.New("chain substituted original typed command")
			}
			process, err := f.nativeStart(t)
			if err == nil && f.onStart != nil {
				f.onStart(ctx, process)
			}
			return process, err
		},
	}
	var err error
	f.network.Store("original-chain-physical-network")
	f.capture, err = captureDesktopNodeChainHostContextWith(operation, a, selection, f.readNetwork)
	if err != nil {
		t.Fatal(err)
	}
	f.launch, err = prepareDesktopOwnedNodeChainLaunch(operation, f.capture, selection)
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
		if f.pulseDone != nil {
			<-f.pulseDone
			if f.pulseErr != nil {
				t.Error(f.pulseErr)
			}
		}
		for _, process := range f.processes {
			_ = process.Close(context.Background())
		}
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

func (f *desktopNodeChainOwnedFixture) nativeStart(t *testing.T) (*desktopImportedOwnedProcess, error) {
	t.Helper()
	if f.executionModel != nil {
		return f.executionModel.start(t, f)
	}
	launch, owned := f.launch, f.launch.ownedNode
	raw, err := readDesktopRuntimeFile(launch, launch.chain.sourceName(), mobilemultihop.NodeChainInputLimit)
	if err != nil {
		return nil, err
	}
	_, meta, capture, err := launch.chain.readPolicy()
	if err != nil {
		return nil, err
	}
	if launch.chain.socksPolicy != nil {
		policy, parseErr := mobilemultihop.ParseDesktopNodeChainSOCKSLaunchInput(string(raw))
		if parseErr != nil {
			return nil, parseErr
		}
		parsedConfig, parsedMeta, parsedCapture, parseErr := policy.ReadValidated()
		originalConfig, originalMeta, originalCapture, originalErr := launch.chain.socksPolicy.ReadValidated()
		if parseErr != nil || originalErr != nil || parsedConfig != originalConfig || !reflect.DeepEqual(parsedMeta, originalMeta) || !reflect.DeepEqual(parsedCapture, originalCapture) || len(parsedMeta.Prefixes) != len(f.selection.Nodes) {
			return nil, errors.Join(parseErr, originalErr, errors.New("child replay changed original typed ordered graph"))
		}
	} else if launch.chain.connectPolicy != nil {
		policy, parseErr := mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(string(raw))
		if parseErr != nil {
			return nil, parseErr
		}
		parsedConfig, parsedMeta, parsedCapture, parseErr := policy.ReadValidated()
		originalConfig, originalMeta, originalCapture, originalErr := launch.chain.connectPolicy.ReadValidated()
		if parseErr != nil || originalErr != nil || parsedConfig != originalConfig || !reflect.DeepEqual(parsedMeta, originalMeta) || !reflect.DeepEqual(parsedCapture, originalCapture) || len(parsedMeta.Prefixes) != len(f.selection.Nodes) {
			return nil, errors.Join(parseErr, originalErr, errors.New("child replay changed original typed ordered graph"))
		}
	} else {
		policy, parseErr := mobilemultihop.ParseDesktopNodeChainLaunchInput(string(raw))
		if parseErr != nil || policy.Config() != launch.chain.policy.Config() || !reflect.DeepEqual(policy.Metadata(), launch.chain.policy.Metadata()) || len(policy.NodeChain().ProofInventory()) != len(f.selection.Nodes) {
			return nil, errors.Join(parseErr, errors.New("child replay changed captured ordered graph"))
		}
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
	f.ready, f.live, _ = desktopNodeChainReadyFixture(t, launch)
	f.ready.TransferSHA256 = owned.attempt.digest
	ready := mobilemultihop.DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: owned.attempt.digest,
		DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: f.ready.InterfaceName, InterfaceIndex: f.ready.InterfaceIndex,
		MTU: f.ready.MTU, ProvedAt: time.Now().UnixMilli(), DNSMilliseconds: 1}
	desktopOwnedNodeTestWrite(t, launch, "node-ready.json", ready)
	f.publishHeartbeat(t)
	process := &desktopImportedOwnedProcess{fixture: f.desktopImportedOwnedFixture, launch: launch, target: target, joined: make(chan struct{})}
	f.starts++
	f.processes = append(f.processes, process)
	f.pulseDone = make(chan struct{})
	go func() {
		defer close(f.pulseDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-f.operation.Done():
				return
			case <-process.joined:
				return
			case <-ticker.C:
			}
			f.heartbeat.Lock()
			if !f.staleProof {
				f.ready.ObservedAt = time.Now().UnixMilli()
			}
			f.live.Heartbeat = time.Now().UnixMilli()
			err := f.publishHeartbeatLocked()
			f.heartbeat.Unlock()
			if err != nil {
				f.pulseErr = err
				return
			}
		}
	}()
	return process, nil
}

func (f *desktopNodeChainOwnedFixture) publishHeartbeat(t *testing.T) {
	t.Helper()
	f.heartbeat.Lock()
	defer f.heartbeat.Unlock()
	if err := f.publishHeartbeatLocked(); err != nil {
		t.Fatal(err)
	}
}

func (f *desktopNodeChainOwnedFixture) publishHeartbeatLocked() error {
	f.launch.workspaceMu.Lock()
	defer f.launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(f.launch); err != nil {
		return err
	}
	for name, record := range map[string]any{f.launch.chain.readyName(): f.ready, "node-mtu-status.json": f.live} {
		if name == f.launch.chain.readyName() && f.omitProof {
			if err := f.launch.directoryRoot.Remove(name); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		pending := "." + name + ".pending"
		if err := f.launch.directoryRoot.WriteFile(pending, raw, 0600); err != nil {
			return err
		}
		if err := f.launch.directoryRoot.Rename(pending, name); err != nil {
			return err
		}
	}
	return nil
}

func (f *desktopNodeChainOwnedFixture) stagePublish(t *testing.T) {
	t.Helper()
	if err := stageOwnedNativeMultihopCommandContext(f.operation, f.a, f.selection, f.launch); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	err := f.a.publishDesktopNodeChainStartLocked(f.operation, f.launch, f.selection)
	f.a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	setActiveMultihopGraph(f.a, f.selection)
	if err := bindNativeMultihopRuntimeContext(f.operation, f.a, f.launch, f.selection, f.capture.network); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopNodeChainOwnedLaunchUsesOriginalStartProofAndRetirement(t *testing.T) {
	for _, count := range []int{3, 4} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			f := newDesktopNodeChainOwnedFixture(t, count)
			f.stagePublish(t)
			if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			if f.starts != 1 || f.launch.command.Process != nil || f.launch.ownedNode.ready == nil || f.launch.chain.ready == nil || !f.kernel.locked {
				t.Fatal("typed parent did not retain original modeled child/protection/proof")
			}
			if err := proveDesktopNodeChainContext(f.operation, f.a, f.selection, f.launch.command); err != nil {
				t.Fatal(err)
			}
			if err := validateDesktopNodeChainRestore(f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			assertMTUNodeChainProvedCapture(t, f)
			// A full fresh proof may follow only the same native owner's new reader.
			f.heartbeat.Lock()
			f.ready.Generation, f.ready.Reader, f.ready.InterfaceIndex, f.ready.MTU = 2, 2, 92, 1300
			f.live.Reader, f.live.Index, f.live.MTU = 2, 92, 1300
			f.ready.ObservedAt, f.live.Heartbeat = time.Now().UnixMilli(), time.Now().UnixMilli()
			f.heartbeat.Unlock()
			f.publishHeartbeat(t)
			if err := desktopNodeChainCurrent(f.operation, f.a, f.launch); err != nil {
				t.Fatal("exact new proof reader refused:", err)
			}
			cause := errors.New("original native join still pending")
			f.processes[0].closeErr = cause
			if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); !errors.Is(err, cause) || f.launch.ownedNode.retired || !f.kernel.locked {
				t.Fatal("failed original native join released retained owner", err)
			}
			f.processes[0].closeErr = nil
			if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); err != nil || !f.launch.ownedNode.retired || f.kernel.locked || !f.processes[0].closed {
				t.Fatal("original native retirement did not settle", err)
			}
			<-f.pulseDone
			if err := cleanupDesktopNodeLaunch(f.launch); err != nil {
				t.Fatal("joined chain workspace did not retire:", err)
			}
		})
	}
}

func TestDesktopNodeChainOwnedRejectsStaleProofAndMiddleSource(t *testing.T) {
	for _, fault := range []string{"engine", "network", "physical-network", "middle", "reader", "path", "expired-proof", "missing-proof", "controller", "host-capture"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopNodeChainOwnedFixture(t, 3)
			f.stagePublish(t)
			if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			f.heartbeat.Lock()
			switch fault {
			case "engine":
				f.ready.Identity.EngineID = "replacement-engine"
			case "network":
				f.ready.Identity.NetworkID = "replacement-network"
			case "physical-network":
				f.network.Store("replacement-physical-network")
			case "host-capture":
				replacement := *f.capture
				f.selection.Native.chain.host = &replacement
			case "middle":
				f.a.profiles.Profiles[1].APIToken += "-relinked"
			case "reader":
				f.live.Reader++
			case "path":
				f.live.Path = strings.Repeat("f", 64)
			case "expired-proof":
				f.ready.ObservedAt = time.Now().Add(-3 * time.Second).UnixMilli()
				f.staleProof = true
			case "missing-proof":
				f.omitProof = true
			case "controller":
				f.controller.Store(true)
			}
			f.heartbeat.Unlock()
			f.publishHeartbeat(t)
			if proveDesktopNodeChainContext(f.operation, f.a, f.selection, f.launch.command) == nil {
				t.Fatal("altered ordered proof/source remained current")
			}
			if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); err != nil || !f.processes[0].closed {
				t.Fatal("source rejection lost original cleanup", err)
			}
		})
	}
}

func TestDesktopNodeChainOwnedPartialStartRetainsExactChild(t *testing.T) {
	f := newDesktopNodeChainOwnedFixture(t, 3)
	f.stagePublish(t)
	f.onStart = func(_ context.Context, _ *desktopImportedOwnedProcess) {
		f.heartbeat.Lock()
		f.ready.Identity.SourceSHA256 = strings.Repeat("e", 64)
		f.heartbeat.Unlock()
		f.publishHeartbeat(t)
	}
	if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err == nil ||
		f.launch.ownedNode.ready != nil || f.launch.chain.ready != nil || !desktopOwnedNodeCreated(f.launch) || f.starts != 1 {
		t.Fatal("invalid initial proof was accepted or its original child discarded", err)
	}
	if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); err != nil || !f.processes[0].closed || f.kernel.locked {
		t.Fatal("partial startup did not join its exact native child", err)
	}
}
