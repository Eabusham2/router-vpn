package main

import (
	"context"
	"testing"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/routechoice"
)

// The native adoption is an explicit boundary model here. These tests verify
// retained parent identity; child cryptographic/network proof has separate gates.
func desktopExecutionGraphFixture(t *testing.T, winner routechoice.Execution) (*desktopNodeLaunch, *desktopNodeChainExecutionProof, activeMultihopGraph) {
	t.Helper()
	launch, e := desktopExecutionAttachedFixture(t, "windows")
	e.projection = &mobilemultihop.NodeChainExecutionProjection{}
	e.identity = mobilemultihop.NodeChainIdentity{EngineID: "original-engine", SessionID: launch.mtuSession, NetworkID: "original-network", SourceSHA256: "original-source", ConfigSHA256: "original-config"}
	candidate := routechoice.Candidate{Execution: winner, Transport: "ordered-node-chain", EntryID: "entry", ExitID: "exit"}
	e.ready = &mobilemultihop.DesktopNodeChainExecutionReadyRecord{Identity: e.identity, SelectionEpoch: 1, Progress: mobilemultihop.NodeChainExecutionProgress{
		NodeChainProgress: mobilemultihop.NodeChainProgress{Execution: string(winner), Complete: true, Ready: true, DNSProven: true, PublicProven: true},
		Comparison:        routechoice.Result{Target: mobilemultihop.Targets[1], Winner: &candidate}}}
	proof, err := captureDesktopNodeChainExecutionProofContext(context.Background(), launch)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := desktopNodeChainExecutionGraph(context.Background(), launch, launch.chain.selection)
	if err != nil {
		t.Fatal(err)
	}
	return launch, proof, graph
}

func TestDesktopNodeChainExecutionGraphRetainsSelectedAuthority(t *testing.T) {
	for _, winner := range []routechoice.Execution{routechoice.Local, routechoice.Server} {
		t.Run(string(winner), func(t *testing.T) {
			for _, fault := range []string{"original", "omitted", "projection", "identity", "target", "winner", "epoch", "label", "physical", "preparation"} {
				t.Run(fault, func(t *testing.T) {
					launch, proof, graph := desktopExecutionGraphFixture(t, winner)
					e := launch.chain.execution
					switch fault {
					case "omitted":
						proof = nil
					case "projection":
						e.projection = &mobilemultihop.NodeChainExecutionProjection{}
					case "identity":
						e.identity.EngineID = "replacement"
					case "target":
						e.ready.Progress.Comparison.Target = mobilemultihop.Targets[0]
					case "winner":
						e.ready.Progress.Comparison.Winner.ExitID = "replacement"
					case "epoch":
						e.ready.SelectionEpoch = 0
					case "label":
						graph.Execution = "auto"
					case "physical":
						e.physical = &mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy{}
					case "preparation":
						_, other := desktopExecutionAttachedFixture(t, "windows")
						e.preparation = other.preparation
					}
					err := proof.currentContext(context.Background(), launch, graph)
					if (err == nil) != (fault == "original") {
						t.Fatal("wrong retained graph authority", err)
					}
					if fault == "original" && (graph.ChainNodes != 2 || graph.SourceSHA != launch.chain.selection.Native.source || graph.Execution != string(winner) || launch.chain.ready != nil) {
						t.Fatal("execution borrowed Local readiness or rewrote captured graph")
					}
				})
			}
		})
	}
}

func TestDesktopNodeChainExecutionObservationHonorsCallerAndBusyReceipt(t *testing.T) {
	launch, proof, graph := desktopExecutionGraphFixture(t, routechoice.Server)
	e := launch.chain.execution
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := captureDesktopNodeChainExecutionProofContext(ctx, launch); err == nil {
		t.Fatal("cancelled source capture entered retained mutex")
	}
	if err := proof.currentContext(ctx, launch, graph); err == nil {
		t.Fatal("cancelled graph observation entered retained mutex")
	}
	if err := proof.currentLocked(launch, graph); err == nil {
		t.Fatal("app-locked observation waited for a busy native receipt")
	}
}
