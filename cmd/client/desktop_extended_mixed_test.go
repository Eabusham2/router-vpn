package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"router-vpn/internal/hopmeasure"
)

func TestDesktopExtendedMixedOriginal(t *testing.T) {
	for _, n := range []int{9, 16} {
		for _, spec := range []struct {
			mode    string
			packets int
		}{{"wg", 2}, {"awg2-fast", 1}} {
			t.Run(fmt.Sprintf("%d-%s", n, spec.mode), func(t *testing.T) {
				imports := make([]int, n-spec.packets-1)
				for i := range imports {
					imports[i] = i + spec.packets
				}
				a, nodes := desktopIndependentImportedFixture(t, desktopIndependentImportedLayout{"mixed", n, imports}, spec.mode, "")
				a.cfg.StateFile = filepath.Join(t.TempDir(), "startup.json")
				control := a.profiles.Profiles[n-1]
				for _, mode := range []string{"server", "auto"} {
					if err := desktopOrderedExecutionSelection(nodes, mode); err == nil {
						t.Fatal("Local original accepted non-Local", mode)
					}
				}
				selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
				if err != nil {
					t.Fatal(err)
				}
				selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
				if err != nil {
					t.Fatal(err)
				}
				chain := selection.Native.chain.chain
				if chain.ExtendedMixedLocalPacketCount() != spec.packets {
					t.Fatal("changed original packet and stream roles")
				}
				last, err := originalStartupNodeChainReceipt(selection, "local", "", nil)
				if err != nil || last.NodeChain.Schema != 6 || len(last.NodeChain.Nodes) != n {
					t.Fatal("original Last inventory", err)
				}
				if err = a.saveStartupSelection(last); err != nil {
					t.Fatal(err)
				}
				reopened, found, err := a.loadStartupNodeChainReceipt(control.ID)
				if err != nil || !found || !reflect.DeepEqual(reopened.NodeChain, last.NodeChain) {
					t.Fatal("reopened Last rewrote original sources", err)
				}
				saved := saveOrderedConnectionFixture(t, a, nodes)
				late := a.profiles.Profiles[n-2]
				a.profiles.Profiles[n-2].DNSPort = 5353
				loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved})
				if loaded.Code != http.StatusOK || a.profiles.Profiles[n-2].DNSPort != late.DNSPort || !reflect.DeepEqual(a.profiles.Profiles[n-2].External, late.External) {
					t.Fatal("named restore lost original late private import", loaded.Code)
				}
				control = a.profiles.Profiles[n-1]
				selection, err = resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
				if err != nil {
					t.Fatal(err)
				}
				selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
				if err != nil {
					t.Fatal(err)
				}
				chain = selection.Native.chain.chain
				launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "linux")
				if err != nil {
					t.Fatal(err)
				}
				graph := activeMultihopGraph{ChainNodes: n, Execution: "local", SourceSHA: selection.Native.source}
				retained := &nativeMultihopRuntime{launch: launch, selection: selection, graph: graph}
				if !desktopOrderedMTUDepth(retained, graph) {
					t.Fatal("lost mixed original MTU")
				}
				_, meta, _, err := launch.chain.readPolicy()
				if err != nil {
					t.Fatal(err)
				}
				inventory, err := desktopOrderedLatencyInventory(selection, meta)
				if err != nil || len(inventory) != n {
					t.Fatal("latency source", err)
				}
				status := hopmeasure.Status{Stage: "complete", Complete: true, Drained: true}
				for i, node := range inventory {
					kind := "private-node"
					if i >= spec.packets && i < n-1 {
						kind = "public-path"
					}
					if node.Kind != kind {
						t.Fatal("wrong kind", i)
					}
					r := desktopOrderedReceiptFixtureFor(i, n, kind)
					r.NodeID, r.Result.ID = node.NodeID, node.NodeID
					r.SourceSHA256, r.ConfigSHA256 = chain.SourceSHA256(), meta.ConfigSHA256
					capture := desktopOrderedLatencyCapture{SourceSHA256: r.SourceSHA256, ConfigSHA256: r.ConfigSHA256, GenerationSHA256: r.GenerationSHA256, ExtendedLocalNodes: n, PairedPrefixNodes: spec.packets}
					if err := node.saveCapturedHistory(a, capture, r, func() error { return nil }); err != nil {
						t.Fatal("valid source-bound history", i, err)
					}
					capture.PairedPrefixNodes = 0
					if node.saveCapturedHistory(a, capture, r, func() error { return nil }) == nil {
						t.Fatal("history accepted stripped mixed witness")
					}
					tr := hopmeasure.Transfer{Bytes: 8 << 20, Seconds: 1, Mbps: float64(8<<20) * 8 / 1e6}
					status.Results = append(status.Results, hopmeasure.Result{ID: node.NodeID, Role: node.Role, Kind: kind, Ready: true, Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}, Download: &tr, Upload: &tr})
				}
				get, post := desktopExtendedThroughputPublicReplay(t, a, selection, status)
				for _, raw := range [][]byte{get, post} {
					var result struct {
						Source desktopOrderedPerformanceSource `json:"ordered_local_source"`
						Rows   []speedLabHopMeasurement        `json:"hops"`
					}
					if json.Unmarshal(raw, &result) != nil || result.Source.PairedWireGuard || result.Source.PairedPrefixNodes != spec.packets || len(result.Source.NodeIDs) != n {
						t.Fatal("throughput source missing original position witness")
					}
					for i, row := range result.Rows {
						if strings.Contains(row.SpeedLabel, "to the public benchmark") != (i >= spec.packets && i < n-1) {
							t.Fatal("changed protected benchmark destination label", i)
						}
					}
				}
			})
		}
	}
}

func TestDesktopMeasuredPacketBeforeMixedStreamsGrowsEightToNine(t *testing.T) {
	// Keep the third original paired peer linked in the store and available for
	// insertion. Its real independent transport files still exist on disk.
	a, complete := desktopIndependentImportedFixture(t, desktopIndependentImportedLayout{"future-mixed", 9, []int{3, 4, 5, 6, 7}}, "wg", "")
	candidate := a.profiles.Profiles[2]
	prior := append(slices.Clone(complete[:2]), complete[3:]...)
	control := a.profiles.Profiles[8]
	members, err := resolveDesktopNodeChainMembers(control, a.profiles.Profiles, prior, "local")
	if err != nil {
		t.Fatal(err)
	}
	next, refs, err := orderedDraftProposal("local", members, 1, candidate, a.profiles.Profiles)
	if err != nil || !reflect.DeepEqual(refs, complete) {
		t.Fatal("measured insertion lost packet or original imported suffix", err)
	}
	catalog := slices.Clone(a.profiles.Profiles)
	catalog[8] = next
	capture, err := captureDesktopNodeChain(t.Context(), clientRoot(a), next, catalog, refs, "local", nil)
	if err != nil || capture.chain.ExtendedMixedLocalPacketCount() != 3 {
		t.Fatal("nine-member proposal could not compile its original source", err)
	}
	for _, requested := range []string{"auto", "server"} {
		if _, _, err := orderedDraftProposal(requested, members, 1, candidate, a.profiles.Profiles); err == nil {
			t.Fatal("mixed future acquired remote execution")
		}
	}
}
