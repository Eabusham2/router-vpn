package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// These tests use the existing explicit controller/kernel boundary. Source
// staging, typed child replay, fresh proof, retained ownership and the durable
// Last writer are shipping code; this is not a native OS traffic claim.
func startupProvedNodeChainOwner(t *testing.T, count int) *desktopNodeChainOwnedFixture {
	t.Helper()
	f := newDesktopNodeChainOwnedFixture(t, count)
	f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "startup-owned-last.json")
	f.stagePublish(t)
	if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
		t.Fatal(err)
	}
	if err := proveDesktopNodeChainContext(f.operation, f.a, f.selection, f.launch.command); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	f.a.state.Connected, f.a.state.Phase = true, "connected"
	f.a.mu.Unlock()
	return f
}

func startupReadOwnedReceipt(t *testing.T, a *app) []byte {
	t.Helper()
	raw, err := os.ReadFile(a.startupStatePath())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStartupNodeChainLastRequiresConnectedOriginalOwner(t *testing.T) {
	for _, phase := range []string{"before-launch", "before-connected"} {
		t.Run(phase, func(t *testing.T) {
			f := newDesktopNodeChainOwnedFixture(t, 3)
			f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "startup-owned-last.json")
			before := []byte("previous durable selection must survive\n")
			if err := os.WriteFile(f.a.startupStatePath(), before, 0600); err != nil {
				t.Fatal(err)
			}
			f.stagePublish(t)
			if phase == "before-connected" {
				if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
					t.Fatal(err)
				}
				if err := proveDesktopNodeChainContext(f.operation, f.a, f.selection, f.launch.command); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.a.saveNodeChainStartupSelection(f.operation, f.launch, f.selection); err == nil {
				t.Fatal("unconnected ordered owner wrote a proved Last receipt")
			}
			if !bytes.Equal(startupReadOwnedReceipt(t, f.a), before) {
				t.Fatal("rejected ordered owner replaced the prior durable receipt")
			}
		})
	}
	for _, count := range []int{3, 4} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			f := startupProvedNodeChainOwner(t, count)
			if err := f.a.saveNodeChainStartupSelection(f.operation, f.launch, f.selection); err != nil {
				t.Fatal("fresh original ordered owner could not record Last:", err)
			}
			raw := startupReadOwnedReceipt(t, f.a)
			var receipt startupSelection
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			capture := &startupNodeChainCapture{root: f.selection.Native.root, selection: f.selection, assets: f.selection.Native.chain.assets}
			if receipt.PathKind != startupNodeChainPathKind || receipt.NodeChain == nil ||
				receipt.RouterID != f.selection.Control.ID || receipt.RuntimeMode != f.selection.ExitMode ||
				receipt.ProfileToken != startupExternalProfileToken(f.selection.Control) ||
				!reflect.DeepEqual(receipt.NodeChain, capture.receipt()) {
				t.Fatal("Last did not retain the exact proved Local graph")
			}
			for _, node := range f.selection.Nodes {
				encodedToken, err := json.Marshal(node.Profile.APIToken)
				if err != nil {
					t.Fatal(err)
				}
				if node.Profile.APIToken != "" && bytes.Contains(raw, encodedToken) {
					t.Fatal("Last copied an original node credential")
				}
			}
			if bytes.Contains(raw, []byte("PrivateKey")) || bytes.Contains(raw, []byte("private_key")) {
				t.Fatal("Last copied private transport source instead of its digest")
			}
		})
	}
}

func TestStartupNodeChainLastRejectsRetiredOrSubstitutedOwner(t *testing.T) {
	faults := []string{
		"foreign-context", "cancelled-operation", "middle-policy", "middle-source",
		"wrong-command", "stale-proof", "missing-proof", "missing-runtime",
		"foreign-runtime", "changed-caller-order", "changed-caller-mode",
	}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			f := startupProvedNodeChainOwner(t, 4)
			if err := f.a.saveNodeChainStartupSelection(f.operation, f.launch, f.selection); err != nil {
				t.Fatal(err)
			}
			before := startupReadOwnedReceipt(t, f.a)
			ctx, selection := f.operation, f.selection
			switch fault {
			case "foreign-context":
				ctx = context.Background()
			case "cancelled-operation":
				f.cancel()
			case "middle-policy":
				f.a.mu.Lock()
				f.a.profiles.Profiles[1].APIToken += "-relinked"
				f.a.mu.Unlock()
			case "middle-source":
				path := filepath.Join(clientRoot(f.a), "generated", f.selection.Nodes[1].Profile.ID, "wg", "wg.conf")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, []byte("\n# replaced original source\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-command":
				f.a.mu.Lock()
				f.a.cmd = &exec.Cmd{Path: "replacement-command"}
				f.a.mu.Unlock()
			case "stale-proof":
				f.heartbeat.Lock()
				f.ready.ObservedAt = time.Now().Add(-3 * time.Second).UnixMilli()
				f.staleProof = true
				f.heartbeat.Unlock()
				f.publishHeartbeat(t)
			case "missing-proof":
				f.heartbeat.Lock()
				f.omitProof = true
				f.heartbeat.Unlock()
				f.publishHeartbeat(t)
			case "missing-runtime":
				nativeMultihopOwners.Delete(f.a)
			case "foreign-runtime":
				nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
			case "changed-caller-order":
				selection.Nodes = cloneDesktopNodeChainMembers(selection.Nodes)
				selection.Nodes[1], selection.Nodes[2] = selection.Nodes[2], selection.Nodes[1]
			case "changed-caller-mode":
				selection.Nodes = cloneDesktopNodeChainMembers(selection.Nodes)
				selection.Nodes[1].Mode = "awg2-strong"
			}
			if err := f.a.saveNodeChainStartupSelection(ctx, f.launch, selection); err == nil {
				t.Fatal("retired or substituted ordered owner wrote a new Last receipt")
			}
			if !bytes.Equal(startupReadOwnedReceipt(t, f.a), before) {
				t.Fatal("failed ordered Last write damaged the prior receipt")
			}
		})
	}
}

func TestStartupNodeChainOrdinaryRecorderCannotEraseRetainedGraph(t *testing.T) {
	f := startupProvedNodeChainOwner(t, 3)
	if err := f.a.saveNodeChainStartupSelection(f.operation, f.launch, f.selection); err != nil {
		t.Fatal(err)
	}
	before := startupReadOwnedReceipt(t, f.a)
	f.a.mu.Lock()
	profile := cloneRouterProfile(f.selection.Control)
	st := f.a.state
	if ordinaryStartupRecordAllowed(f.a, profile, st) {
		f.a.mu.Unlock()
		t.Fatal("ordinary recorder accepted the active ordered runtime")
	}
	profile.MultihopEnabled, profile.MultihopNodes = false, nil
	if ordinaryStartupRecordAllowed(f.a, profile, st) {
		f.a.mu.Unlock()
		t.Fatal("cleared preferences downgraded the actual retained ordered owner")
	}
	nativeMultihopOwners.Delete(f.a)
	if ordinaryStartupRecordAllowed(f.a, profile, st) {
		f.a.mu.Unlock()
		t.Fatal("missing runtime owner downgraded the retained ordered graph")
	}
	activeMultihopGraphs.Delete(f.a)
	if ordinaryStartupRecordAllowed(f.a, profile, st) {
		f.a.mu.Unlock()
		t.Fatal("cleanup gap admitted an ordinary overwrite of ordered Last")
	}
	f.a.mu.Unlock()
	if !bytes.Equal(startupReadOwnedReceipt(t, f.a), before) {
		t.Fatal("ordinary classification mutated the durable selection")
	}
}

func TestStartupNodeChainOrdinaryRecorderKeepsActualPairedOwner(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	profile := common.RouterProfile{ID: "paired-exit"}
	command := &exec.Cmd{Path: "captured-paired-runtime"}
	a := &app{cmd: command}
	st := state{Mode: "multihop", LogicalMode: "multihop", RuntimeMode: "shadowsocks", RouterID: profile.ID, Base: "wg"}
	graph := activeMultihopGraph{Execution: "local", EntryID: "paired-entry", ExitID: profile.ID, Base: st.Base, ExitMode: st.RuntimeMode}
	native := &nativeMultihopCapture{}
	owner := &nativeMultihopRuntime{launch: &desktopNodeLaunch{command: command}, graph: graph,
		selection: multihopSelection{Exit: profile, ExitMode: st.RuntimeMode, Base: st.Base, Native: native}}
	t.Cleanup(func() {
		activeMultihopGraphs.Delete(a)
		nativeMultihopOwners.Delete(a)
	})
	activeMultihopGraphs.Store(a, graph)
	nativeMultihopOwners.Store(a, owner)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !ordinaryStartupRecordAllowed(a, profile, st) {
		t.Fatal("canonical native paired owner was mistaken for an ordered graph")
	}
	a.cmd = &exec.Cmd{Path: "foreign-paired-runtime"}
	if ordinaryStartupRecordAllowed(a, profile, st) {
		t.Fatal("paired classification ignored its original command")
	}
	a.cmd = command
	nativeMultihopOwners.Store(a, "untyped-owner")
	if ordinaryStartupRecordAllowed(a, profile, st) {
		t.Fatal("untyped runtime owner gained ordinary Last authority")
	}
	nativeMultihopOwners.Delete(a)
	if allowed := ordinaryStartupRecordAllowed(a, profile, st); allowed == retainedNativeMultihopSelected() {
		t.Fatal("legacy/native paired classification lost its retained-host boundary")
	}
	activeMultihopGraphs.Delete(a)
	if ordinaryStartupRecordAllowed(a, profile, st) {
		t.Fatal("paired cleanup gap gained ordinary Last authority")
	}
	st.Mode, st.LogicalMode, st.RuntimeMode = "wg", "wireguard", "wg"
	if !ordinaryStartupRecordAllowed(a, profile, st) {
		t.Fatal("ordinary non-multihop connection lost its existing Last recorder")
	}
	profile.MultihopEnabled = true
	profile.MultihopNodes = []common.MultihopNodeSelection{{ID: "paired-entry", Mode: "wg"}, {ID: profile.ID, Mode: "shadowsocks"}}
	if ordinaryStartupRecordAllowed(a, profile, st) {
		t.Fatal("active saved ordered policy was written as an ordinary receipt")
	}
}
