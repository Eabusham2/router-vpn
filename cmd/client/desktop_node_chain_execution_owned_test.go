package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

type desktopExecutionOwnedModel struct {
	winner string
	ready  mobilemultihop.DesktopNodeChainExecutionReadyRecord
}

// This models authenticated child records and the Windows controller/kernel.
// Actual staging, protection ownership, parent parsing, observation and joined
// retirement execute; this is not encrypted or physical Windows acceptance.
func (m *desktopExecutionOwnedModel) start(t *testing.T, f *desktopNodeChainOwnedFixture) (*desktopImportedOwnedProcess, error) {
	t.Helper()
	launch, owned := f.launch, f.launch.ownedNode
	raw, err := readDesktopRuntimeFile(launch, launch.chain.sourceName(), mobilemultihop.NodeChainInputLimit)
	if err != nil {
		return nil, err
	}
	prep, err := mobilemultihop.ParseDesktopNodeChainExecutionPreparation(string(raw))
	if err != nil {
		return nil, err
	}
	if prep.SourceSHA256() != launch.chain.execution.preparation.SourceSHA256() {
		return nil, errors.New("modeled child received different preparation")
	}
	var local mobilemultihop.NodeChainSource
	if json.Unmarshal([]byte(prep.LocalSource()), &local) != nil || len(local.Nodes) != 2 {
		return nil, errors.New("modeled child requires exact two-member source")
	}
	entry, err := mobilemultihop.ParseNodeLaunchInput(local.Nodes[0])
	if err != nil {
		return nil, err
	}
	proofs := launch.chain.policy.OriginalChain().ProofInventory()
	serverInput := mobilemultihop.NodeChainServerSource{Schema: 1, EntryID: proofs[0].ProfileID, EntryNodeID: proofs[0].NodeID, EntryMode: proofs[0].Mode, Nodes: local.Nodes[1:], IdentitySources: local.IdentitySources[1:]}
	encoded, _ := json.Marshal(serverInput)
	server, err := mobilemultihop.NewNodeChainServerPolicy(string(encoded))
	if err != nil {
		return nil, err
	}
	descriptor := server.Descriptor()
	digest, err := descriptor.Digest()
	if err != nil {
		return nil, err
	}
	key, err := entry.PacketClientPublicKey()
	if err != nil {
		return nil, err
	}
	var graph struct {
		Endpoints []struct {
			Address []string `json:"address"`
		} `json:"endpoints"`
	}
	if json.Unmarshal([]byte(entry.Config()), &graph) != nil || len(graph.Endpoints) != 1 || len(graph.Endpoints[0].Address) == 0 {
		return nil, errors.New("missing modeled entry address")
	}
	peer, err := netip.ParsePrefix(graph.Endpoints[0].Address[0])
	if err != nil {
		return nil, err
	}
	request := multihoprelay.NodeChainRequest{Schema: 1, SessionID: strings.Repeat("7", 32), EntryNodeID: descriptor.EntryNodeID, SourceSHA256: descriptor.SourceSHA256, DescriptorSHA256: digest, DNSPolicySHA256: descriptor.DNSPolicySHA256, Epoch: strings.Repeat("8", 64), Peer: peer.Addr().String(), AcquireExpiresAt: time.Now().Add(10 * time.Second).Unix(), LocalPacketPublicKeys: []string{key}, Port: 32003, Users: []multihoprelay.NodeChainUser{{Position: 1, Username: strings.Repeat("9", 48), Password: strings.Repeat("a", 48)}}}
	source := mobilemultihop.NodeChainExecutionSource{Schema: 1, Execution: prep.Execution(), LocalSource: prep.LocalSource(), Server: descriptor, Request: request, FirstPort: 32000, LastPort: 32007}
	encoded, _ = json.Marshal(source)
	policy, err := mobilemultihop.NewNodeChainExecutionPolicy(string(encoded))
	if err != nil {
		return nil, err
	}
	projection, err := prep.BindExecution(policy)
	if err != nil {
		return nil, err
	}
	_, meta, capture, err := launch.chain.readPolicy()
	if err != nil {
		return nil, err
	}
	identity := mobilemultihop.NodeChainIdentity{EngineID: "original-execution-engine", SessionID: meta.SessionID, NetworkID: "original-execution-network", SourceSHA256: projection.SourceSHA256(), ConfigSHA256: projection.ConfigSHA256()}
	adoption, err := mobilemultihop.NewDesktopNodeChainExecutionAdoptionRecord(projection, identity, owned.attempt.digest)
	if err != nil {
		return nil, err
	}
	handoff := desktopNodeHandoffRecord{Schema: 1, Kind: "routervpn-node-physical-handoff-v2", SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: owned.attempt.digest, NetworkID: strings.Repeat("d", 32), Policy: meta.KillSwitchPolicy, BaselineSHA256: strings.Repeat("e", 64), Nonce: strings.Repeat("a", 64)}
	encoded, _ = json.Marshal(handoff)
	_, target, err := desktopNodeHandoff(encoded, launch)
	if err != nil {
		return nil, err
	}
	f.kernel.target, f.kernel.locked = copyDesktopNodeProtectionTarget(&target), true
	desktopOwnedNodeTestWrite(t, launch, "node-physical-handoff-ready.json", handoff)
	desktopOwnedNodeTestWrite(t, launch, "node-chain-execution-adoption.json", adoption)
	last := desktopExecutionParentSavedChoice(t, prep, projection, m.winner, mobilemultihop.Targets[1])
	var saved json.RawMessage = []byte(last.JSON())
	desktopOwnedNodeTestWrite(t, launch, "node-chain-execution-last.json", saved)
	selected, err := projection.ProofInventory(m.winner)
	if err != nil {
		return nil, err
	}
	candidate := routechoice.Candidate{Execution: routechoice.Execution(m.winner), Transport: "ordered-node-chain", EntryID: selected[0].ProfileID, ExitID: selected[len(selected)-1].ProfileID}
	measured, err := routechoice.Score(candidate, 2*time.Millisecond, 4*time.Millisecond)
	if err != nil {
		return nil, err
	}
	progress := mobilemultihop.NodeChainExecutionProgress{NodeChainProgress: mobilemultihop.NodeChainProgress{Stage: "selected", Execution: m.winner, Complete: true, Ready: true, DNSProven: true, PublicProven: true}, Comparison: routechoice.Result{Target: mobilemultihop.Targets[1], Winner: &candidate, Final: &measured, Measurements: []routechoice.Measurement{measured}}}
	for _, proof := range selected {
		progress.Prefixes = append(progress.Prefixes, mobilemultihop.NodeChainPrefixProgress{Position: proof.Position, ProfileID: proof.ProfileID, Proven: true, ResponseMS: 2})
	}
	mtu := capture.ConfiguredMTU
	if meta.RestoredMTU != 0 {
		mtu = meta.RestoredMTU
	}
	m.ready = mobilemultihop.DesktopNodeChainExecutionReadyRecord{Schema: 1, Kind: "routervpn-node-chain-execution-ready-v1", SourceSHA256: meta.SourceSHA256, PreparationSourceSHA256: prep.SourceSHA256(), PreparationConfigSHA256: prep.ConfigSHA256(), TransferSHA256: owned.attempt.digest, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, Identity: identity, SelectionEpoch: 1, Generation: 1, Reader: 1, InterfaceName: "router-vpn", InterfaceIndex: 91, MTU: mtu, ObservedAt: time.Now().UnixMilli(), Progress: progress}
	if err := m.ready.Validate(projection, owned.attempt.digest); err != nil {
		return nil, err
	}
	base := mobilemultihop.DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: owned.attempt.digest, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: m.ready.InterfaceName, InterfaceIndex: m.ready.InterfaceIndex, MTU: m.ready.MTU, ProvedAt: time.Now().UnixMilli(), DNSMilliseconds: 1}
	desktopOwnedNodeTestWrite(t, launch, "node-ready.json", base)
	f.live = desktopNodeMTURecord{Schema: 1, Session: meta.SessionID, Config: meta.ConfigSHA256, Path: strings.Repeat("c", 64), Reader: 1, Interface: m.ready.InterfaceName, Index: 91, MTU: mtu, Heartbeat: time.Now().UnixMilli()}
	publish := func() error {
		launch.workspaceMu.Lock()
		defer launch.workspaceMu.Unlock()
		for name, record := range map[string]any{"node-chain-execution-ready.json": m.ready, "node-mtu-status.json": f.live} {
			data, err := json.Marshal(record)
			if err != nil {
				return err
			}
			pending := "." + name + ".pending"
			if err := launch.directoryRoot.WriteFile(pending, data, 0600); err != nil {
				return err
			}
			if err := launch.directoryRoot.Rename(pending, name); err != nil {
				return err
			}
		}
		return nil
	}
	if err := publish(); err != nil {
		return nil, err
	}
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
			m.ready.ObservedAt = time.Now().UnixMilli()
			f.live.Heartbeat = time.Now().UnixMilli()
			err := publish()
			f.heartbeat.Unlock()
			if err != nil {
				f.pulseErr = err
				return
			}
		}
	}()
	return process, nil
}

func TestDesktopNodeChainExecutionOwnedStartupProofAndRetirement(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f := newDesktopNodeChainOwnedFixture(t, 2)
			f.executionModel = &desktopExecutionOwnedModel{winner: winner}
			request := &desktopNodeChainExecutionRequest{capture: f.capture, native: f.selection.Native, requested: "auto"}
			launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, f.selection, nil, request)
			if err != nil {
				t.Fatal(err)
			}
			f.launch = launch
			if err := stageOwnedNativeMultihopCommandContext(f.operation, f.a, f.selection, launch); err != nil {
				t.Fatal(err)
			}
			f.a.mu.Lock()
			err = f.a.publishDesktopNodeChainStartLocked(f.operation, launch, f.selection)
			f.a.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, launch); err != nil {
				t.Fatal(err)
			}
			if f.starts != 1 || launch.chain.ready != nil || launch.chain.execution.ready == nil || !f.kernel.locked {
				t.Fatal("execution lost its original typed process/protection/ready")
			}
			graph, err := publishDesktopMultihopPlatformGraph(f.operation, f.a, launch, f.selection, winner)
			if err != nil || graph.Execution != winner {
				t.Fatal(err)
			}
			if err := bindNativeMultihopRuntimeContext(f.operation, f.a, launch, f.selection, f.capture.network); err != nil {
				t.Fatal(err)
			}
			if err := proveDesktopNodeChainContext(f.operation, f.a, f.selection, launch.command); err != nil {
				t.Fatal(err)
			}
			owner, err := capturedNativeMultihopRuntimeContext(f.operation, f.a, launch.command, graph)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := captureMTUNodeChainSnapshot(owner)
			if err != nil || snapshot.Execution == nil || snapshot.Execution != owner.execution {
				t.Fatal("execution MTU capture borrowed Local or legacy relay", err)
			}
			restore, err := launch.chain.execution.captureRestoreContext(f.operation, f.a, launch)
			if err != nil {
				t.Fatal("captured original chosen restore failed", err)
			}
			if _, _, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows"); err == nil {
				t.Fatal("unjoined execution allowed restore")
			}
			cause := errors.New("original execution native join pending")
			f.processes[0].closeErr = cause
			if err := restore.retireContext(context.Background()); !errors.Is(err, cause) || launch.ownedNode.retired || !f.kernel.locked {
				t.Fatal("failed join lost original execution owner", err)
			}
			f.processes[0].closeErr = nil
			if err := restore.retireContext(context.Background()); err != nil || !launch.ownedNode.retired || f.kernel.locked {
				t.Fatal("original execution did not retire", err)
			}
			<-f.pulseDone
			next, execution, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows")
			if err != nil {
				t.Fatal("joined saved-choice restore failed", err)
			}
			retained, present, err := execution.preparation.DesktopLast()
			if err != nil || !present || retained.Execution() != winner || retained.Target() != mobilemultihop.Targets[1] || next.mtuSession == launch.mtuSession || next.chain.policy.Metadata().RestoredMTU != f.live.MTU {
				t.Fatal("restore reran Compare or replaced winner/target/MTU", err)
			}
		})
	}
}
