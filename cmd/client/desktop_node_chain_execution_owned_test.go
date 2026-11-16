package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

type desktopExecutionOwnedModel struct {
	winner                 string
	importedSourceOverride *string
	startErr               error
	ready                  mobilemultihop.DesktopNodeChainExecutionReadyRecord
	beforePublish          func()
	afterPublish           func(int64, int64)
}

// This models authenticated child records and the Windows controller/kernel.
// Actual staging, protection ownership, parent parsing, observation and joined
// retirement execute; this is not encrypted or physical Windows acceptance.
func (m *desktopExecutionOwnedModel) start(t *testing.T, f *desktopNodeChainOwnedFixture) (*desktopImportedOwnedProcess, error) {
	t.Helper()
	if m.startErr != nil {
		return nil, m.startErr
	}
	launch, owned := f.launch, f.launch.ownedNode
	raw, err := readDesktopRuntimeFile(launch, launch.chain.sourceName(), mobilemultihop.NodeChainInputLimit)
	if err != nil {
		return nil, err
	}
	var prep *mobilemultihop.NodeChainExecutionPreparation
	if launch.chain.execution.socksPhysical != nil {
		prep, err = mobilemultihop.ParseDesktopNodeChainSOCKSExecutionPreparation(string(raw))
	} else if launch.chain.execution.connectPhysical != nil {
		prep, err = mobilemultihop.ParseDesktopNodeChainCONNECTExecutionPreparation(string(raw))
	} else {
		prep, err = mobilemultihop.ParseDesktopNodeChainExecutionPreparation(string(raw))
	}
	if err != nil {
		return nil, err
	}
	if prep.SourceSHA256() != launch.chain.execution.preparation.SourceSHA256() {
		return nil, errors.New("modeled child received different preparation")
	}
	var local mobilemultihop.NodeChainSource
	if json.Unmarshal([]byte(prep.LocalSource()), &local) != nil || len(local.Nodes) < 2 || len(local.Nodes) > 8 {
		return nil, errors.New("modeled child requires its exact bounded complete source")
	}
	entry, err := mobilemultihop.ParseNodeLaunchInput(local.Nodes[0])
	if err != nil {
		return nil, err
	}
	var proofs []mobilemultihop.NodeChainProof
	if local.Schema == 3 {
		original, sourceErr := prep.OriginalSOCKSSource()
		if sourceErr != nil {
			return nil, sourceErr
		}
		_, metadata, sourceErr := original.ReadValidated()
		if sourceErr != nil {
			return nil, sourceErr
		}
		proofs = metadata.Proofs
	} else if local.Schema == 4 {
		original, sourceErr := prep.OriginalCONNECTSource()
		if sourceErr != nil {
			return nil, sourceErr
		}
		_, metadata, sourceErr := original.ReadValidated()
		if sourceErr != nil {
			return nil, sourceErr
		}
		proofs = metadata.Proofs
	} else {
		proofs = launch.chain.policy.OriginalChain().ProofInventory()
	}
	serverInput := mobilemultihop.NodeChainServerSource{Schema: 1, EntryID: proofs[0].ProfileID, EntryNodeID: proofs[0].NodeID, EntryMode: proofs[0].Mode}
	if local.Schema == 2 {
		middle := len(local.Nodes) - 2
		if len(local.Nodes) < 3 || local.IdentitySources[middle] != "" || proofs[middle].NodeKind != "external" || proofs[middle].Mode != "shadowsocks" {
			return nil, errors.New("modeled imported execution lost original complete prefix")
		}
		serverInput.Schema = 2
	}
	if local.Schema == 4 {
		middle := len(local.Nodes) - 2
		if len(local.Nodes) < 3 || local.IdentitySources[middle] != "" || proofs[middle].NodeKind != "external" || (proofs[middle].Mode != "http-connect" && proofs[middle].Mode != "https-connect") {
			return nil, errors.New("modeled CONNECT execution lost its original complete typed path")
		}
		serverInput.Schema = 4
	}
	if local.Schema == 3 {
		if len(local.Nodes) != 3 || local.IdentitySources[1] != "" || proofs[1].NodeKind != "external" || proofs[1].Mode != "socks5" {
			return nil, errors.New("modeled SOCKS execution lost its original UDP association source")
		}
		serverInput.Schema = 3
	}
	for position := 1; position < len(local.Nodes); position++ {
		input, identity, err := desktopExecutionServerNode(local.Nodes[position], local.IdentitySources[position], position)
		if err != nil {
			return nil, err
		}
		serverInput.Nodes = append(serverInput.Nodes, input)
		serverInput.IdentitySources = append(serverInput.IdentitySources, identity)
	}
	if m.importedSourceOverride != nil {
		if serverInput.Schema != 2 || len(serverInput.Nodes) < 2 {
			return nil, errors.New("imported source control requires original schema two")
		}
		serverInput.Nodes[len(serverInput.Nodes)-2] = *m.importedSourceOverride
	}
	encoded, _ := json.Marshal(serverInput)
	var server *mobilemultihop.NodeChainServerPolicy
	if local.Schema == 3 {
		server, err = mobilemultihop.NewNodeChainSOCKSServerPolicy(string(encoded))
	} else if local.Schema == 4 {
		server, err = mobilemultihop.NewNodeChainCONNECTServerPolicy(string(encoded))
	} else {
		server, err = mobilemultihop.NewNodeChainServerPolicy(string(encoded))
	}
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
	request := multihoprelay.NodeChainRequest{Schema: descriptor.Schema, SessionID: strings.Repeat("7", 32), EntryNodeID: descriptor.EntryNodeID, SourceSHA256: descriptor.SourceSHA256, DescriptorSHA256: digest, DNSPolicySHA256: descriptor.DNSPolicySHA256, Epoch: strings.Repeat("8", 64), Peer: peer.Addr().String(), AcquireExpiresAt: time.Now().Add(10 * time.Second).Unix(), LocalPacketPublicKeys: []string{key}, Port: 32003, Users: []multihoprelay.NodeChainUser{{Position: 1, Username: strings.Repeat("9", 48), Password: strings.Repeat("a", 48)}}}
	if descriptor.Schema == 2 || descriptor.Schema == 3 || descriptor.Schema == 4 {
		request.LocalPacketPositions = []int{0}
	}
	for position := 1; position+1 < len(local.Nodes); position++ {
		if (descriptor.Schema == 2 || descriptor.Schema == 3 || descriptor.Schema == 4) && position == len(local.Nodes)-2 {
			// Imported SS has no packet client; retain its original source and
			// separate relay user without fabricating paired credentials.
			request.Users = append(request.Users, multihoprelay.NodeChainUser{Position: position + 1,
				Username: fmt.Sprintf("%048x", 256+position*2), Password: fmt.Sprintf("%048x", 257+position*2)})
			continue
		}
		node, err := mobilemultihop.ParseNodeLaunchInput(local.Nodes[position])
		if err != nil {
			return nil, err
		}
		public, err := node.PacketClientPublicKey()
		if err != nil {
			return nil, err
		}
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, public)
		if descriptor.Schema == 2 || descriptor.Schema == 4 {
			request.LocalPacketPositions = append(request.LocalPacketPositions, position)
		}
		request.Users = append(request.Users, multihoprelay.NodeChainUser{Position: position + 1,
			Username: fmt.Sprintf("%048x", 256+position*2), Password: fmt.Sprintf("%048x", 257+position*2)})
	}
	if err := request.Validate(descriptor); err != nil {
		return nil, fmt.Errorf("independent modeled server request: %w", err)
	}
	if local.Schema == 1 && len(local.Nodes) > 2 {
		// Restoring the original faulty fixture must still be rejected by the
		// actual shared validator: server and local packet clients are distinct.
		bad := request.Clone()
		bad.LocalPacketPublicKeys[1] = descriptor.Members[0].ClientPublicKey
		if bad.Validate(descriptor) == nil {
			return nil, errors.New("modeled server failed its reused-local-client rejection")
		}
	}
	source := mobilemultihop.NodeChainExecutionSource{Schema: 1, Execution: prep.Execution(), LocalSource: prep.LocalSource(), Server: descriptor, Request: request, FirstPort: 32000, LastPort: 32007}
	if local.Schema == 3 || local.Schema == 4 {
		source.Schema = local.Schema
	}
	encoded, _ = json.Marshal(source)
	var policy *mobilemultihop.NodeChainExecutionPolicy
	if local.Schema == 3 {
		policy, err = mobilemultihop.NewNodeChainSOCKSExecutionPolicy(prep, string(encoded))
	} else if local.Schema == 4 {
		policy, err = mobilemultihop.NewNodeChainCONNECTExecutionPolicy(prep, string(encoded))
	} else {
		policy, err = mobilemultihop.NewNodeChainExecutionPolicy(string(encoded))
	}
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
	var adoption any
	if local.Schema == 3 {
		adoption, err = mobilemultihop.NewDesktopNodeChainSOCKSExecutionAdoptionRecord(projection, identity, owned.attempt.digest)
	} else if local.Schema == 4 {
		adoption, err = mobilemultihop.NewDesktopNodeChainCONNECTExecutionAdoptionRecord(projection, identity, owned.attempt.digest)
	} else {
		adoption, err = mobilemultihop.NewDesktopNodeChainExecutionAdoptionRecord(projection, identity, owned.attempt.digest)
	}
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
	if local.Schema == 3 {
		m.ready.Kind = "routervpn-node-chain-socks-execution-ready-v1"
		err = mobilemultihop.DesktopNodeChainSOCKSExecutionReadyRecord(m.ready).Validate(projection, owned.attempt.digest)
	} else if local.Schema == 4 {
		m.ready.Kind = "routervpn-node-chain-connect-execution-ready-v1"
		err = mobilemultihop.DesktopNodeChainCONNECTExecutionReadyRecord(m.ready).Validate(projection, owned.attempt.digest)
	} else {
		err = m.ready.Validate(projection, owned.attempt.digest)
	}
	if err != nil {
		return nil, err
	}
	base := mobilemultihop.DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: owned.attempt.digest, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: m.ready.InterfaceName, InterfaceIndex: m.ready.InterfaceIndex, MTU: m.ready.MTU, ProvedAt: time.Now().UnixMilli(), DNSMilliseconds: 1}
	desktopOwnedNodeTestWrite(t, launch, "node-ready.json", base)
	f.live = desktopNodeMTURecord{Schema: 1, Session: meta.SessionID, Config: meta.ConfigSHA256, Path: strings.Repeat("c", 64), Reader: 1, Interface: m.ready.InterfaceName, Index: 91, MTU: mtu, Heartbeat: time.Now().UnixMilli()}
	publish := func() error {
		if m.beforePublish != nil {
			m.beforePublish()
		}
		launch.workspaceMu.Lock()
		defer launch.workspaceMu.Unlock()
		// The modeled child shares this lock with its parent; a real child
		// does not. Stamp publication only after that artificial contention,
		// while the initial constructor or heartbeat mutex owns the model.
		m.ready.ObservedAt = time.Now().UnixMilli()
		f.live.Heartbeat = time.Now().UnixMilli()
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
		if m.afterPublish != nil {
			m.afterPublish(m.ready.ObservedAt, f.live.Heartbeat)
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

// Derive a separate server packet client through the real profile compiler.
// Keep node/server identity, DNS and Start Layers unchanged. These deterministic
// keys belong only to the controller model and never to installed credentials.
func desktopExecutionServerNode(input, identity string, position int) (string, string, error) {
	var capture struct {
		Mode         string `json:"mode"`
		Files        string `json:"files"`
		ProfileJSON  string `json:"profile_json"`
		Start        string `json:"start"`
		DNSBootstrap string `json:"dns_bootstrap"`
	}
	if err := json.Unmarshal([]byte(input), &capture); err != nil {
		return "", "", err
	}
	if !mobilemultihop.NodeChainPrefixMode(capture.Mode) {
		return input, identity, nil
	}
	node, err := mobilemultihop.ParseNodeLaunchInput(input)
	if err != nil {
		return "", "", err
	}
	var graph struct {
		Endpoints []struct {
			PrivateKey string `json:"private_key"`
		} `json:"endpoints"`
	}
	if json.Unmarshal([]byte(node.Config()), &graph) != nil || len(graph.Endpoints) != 1 || graph.Endpoints[0].PrivateKey == "" {
		return "", "", errors.New("model lacks original packet client")
	}
	var assets map[string]string
	if err := json.Unmarshal([]byte(capture.Files), &assets); err != nil {
		return "", "", err
	}
	name, companion := "wg.conf", "wg-socks.conf"
	if capture.Mode != "wg" {
		name, companion = "awg.conf", "awg-socks.conf"
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(221 + position)}, 32))
	for _, asset := range []string{name, companion} {
		encoded, exists := assets[asset]
		if !exists && asset == companion {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || !strings.Contains(string(raw), graph.Endpoints[0].PrivateKey) {
			return "", "", errors.New("model lacks original matching packet asset")
		}
		// The optional split-route file is the same peer with different routes.
		// Preserve it and rotate its client identity with the full source.
		raw = []byte(strings.Replace(string(raw), graph.Endpoints[0].PrivateKey, key, 1))
		assets[asset] = base64.StdEncoding.EncodeToString(raw)
	}
	files, err := json.Marshal(assets)
	if err != nil {
		return "", "", err
	}
	server, err := mobilemultihop.NewNodeProfile(capture.Mode, string(files), capture.ProfileJSON, capture.Start, capture.DNSBootstrap)
	if err != nil {
		return "", "", err
	}
	input, err = server.LaunchInput()
	if capture.Mode == "wg" {
		identity = string(files)
	}
	return input, identity, err
}

func TestDesktopNodeChainExecutionHeartbeatStampsOriginalPublication(t *testing.T) {
	f, s := prepareDesktopExecutionSessionModel(t, "local")
	if err := s.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	published := make(chan [2]int64, 1)
	resume := make(chan struct{})
	var enterOnce, publishOnce, resumeOnce sync.Once
	defer resumeOnce.Do(func() { close(resume) })
	// Acquire in the writer's own order; install observers under heartbeat
	// ownership before allowing the next pulse to wait on the parent lock.
	f.heartbeat.Lock()
	f.launch.workspaceMu.Lock()
	f.executionModel.beforePublish = func() { enterOnce.Do(func() { close(entered) }) }
	f.executionModel.afterPublish = func(proof, mtu int64) {
		publishOnce.Do(func() {
			published <- [2]int64{proof, mtu}
			<-resume // Pin the first publication; a later good pulse cannot hide it.
		})
	}
	f.heartbeat.Unlock()
	locked := true
	defer func() {
		if locked {
			f.launch.workspaceMu.Unlock()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original pulse did not reach the held workspace")
	}
	// Cross a real millisecond boundary after the old stamp would have been
	// taken. This controls only lock contention, never the production clock.
	<-time.After(2 * time.Millisecond)
	releasedAt := time.Now().UnixMilli()
	f.launch.workspaceMu.Unlock()
	locked = false
	select {
	case stamp := <-published:
		if stamp[0] < releasedAt || stamp[1] < releasedAt {
			t.Fatalf("first original publication retained a pre-lock timestamp: proof=%d mtu=%d released=%d", stamp[0], stamp[1], releasedAt)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original pulse did not publish after workspace release")
	}
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
	f, session := prepareDesktopExecutionSessionModel(t, "server")
	cause := errors.New("modeled child rejected before process creation")
	f.executionModel.startErr = cause
	if err := session.startContext(f.operation); !errors.Is(err, cause) {
		t.Fatal("failed start lost original constructor refusal", err)
	}
	if desktopOwnedNodeProcess(session.launch) != nil || f.starts != 0 || len(f.processes) != 0 {
		t.Fatal("failed model constructor fabricated a process owner")
	}
	if err := session.Close(context.Background()); err != nil || !session.closed {
		t.Fatal("failed constructor did not retain normal exact cleanup", err)
	}

}
