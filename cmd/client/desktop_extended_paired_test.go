package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/hopmeasure"
)

func TestDesktopExtendedPairedOriginal(t *testing.T) {
	for _, count := range []int{9, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, count)
			a.cfg.StateFile = filepath.Join(t.TempDir(), "startup.json")
			for _, p := range a.profiles.Profiles {
				if count <= 9 {
					break
				}
				for _, file := range []string{"wg.conf", "wg-socks.conf"} {
					path := filepath.Join(clientRoot(a), "generated", p.ID, "wg", file)
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(path, []byte(strings.Replace(string(raw), "MTU = 2000", "MTU = 3000", 1)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
			}
			control := a.profiles.Profiles[count-1]
			for _, execution := range []string{"server", "auto"} {
				if _, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, execution); err == nil {
					t.Fatal("extended paired route acquired unproved execution", execution)
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
			if chain.ExtendedPairedLocalNodeCount() != count {
				t.Fatal("complete original paired source lost")
			}
			for _, target := range []string{"linux", "windows", "darwin"} {
				c, err := selection.Native.chain.project(t.Context(), target, 0)
				if err != nil || c.ExtendedPairedLocalNodeCount() != count {
					t.Fatal(target, err)
				}
			}
			last, err := originalStartupNodeChainReceipt(selection, "local", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if last.NodeChain.Schema != 1 || len(last.NodeChain.Nodes) != count {
				t.Fatal("Last dropped original paired asset references")
			}
			if err = a.saveStartupSelection(last); err != nil {
				t.Fatal(err)
			}
			reread, found, err := a.loadStartupNodeChainReceipt(control.ID)
			if err != nil || !found || !reflect.DeepEqual(reread.NodeChain, last.NodeChain) {
				t.Fatal("Last changed original complete source", err)
			}
			last.NodeChain.Nodes[count-2].Mode = "awg2-fast"
			if validateStartupNodeChainSelection(last) == nil {
				t.Fatal("Last accepted relabeled late private hop")
			}
			launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "linux")
			if err != nil {
				t.Fatal(err)
			}
			graph := activeMultihopGraph{ChainNodes: count, Execution: "local", SourceSHA: selection.Native.source}
			retained := &nativeMultihopRuntime{launch: launch, selection: selection, graph: graph}
			if !desktopOrderedMTUDepth(retained, graph) {
				t.Fatal("complete retained paired MTU policy refused its original graph")
			}
			for _, fault := range []string{"depth", "source", "remote", "projected-config"} {
				changed := graph
				originalConfig := launch.configSHA256
				switch fault {
				case "depth":
					changed.ChainNodes++
				case "source":
					changed.SourceSHA = strings.Repeat("7", 64)
				case "remote":
					changed.Execution = "server"
				case "projected-config":
					launch.configSHA256 = strings.Repeat("8", 64)
				}
				if desktopOrderedMTUDepth(retained, changed) {
					t.Fatal("foreign original MTU owner admitted", fault)
				}
				launch.configSHA256 = originalConfig
			}
			_, meta, _, err := launch.chain.readPolicy()
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := desktopOrderedLatencyInventory(selection, meta)
			if err != nil || len(inventory) != count {
				t.Fatal("latency inventory", err)
			}
			position := count - 2
			node := inventory[position]
			r := desktopOrderedReceiptFixtureFor(position, count, "private-node")
			r.NodeID, r.Result.ID = node.NodeID, node.NodeID
			r.SourceSHA256, r.ConfigSHA256 = chain.SourceSHA256(), meta.ConfigSHA256
			receipt := desktopOrderedLatencyCapture{SourceSHA256: r.SourceSHA256, ConfigSHA256: r.ConfigSHA256, GenerationSHA256: r.GenerationSHA256, ExtendedLocalNodes: count}
			if node.Kind != "private-node" || node.saveCapturedHistory(a, receipt, r, func() error { return nil }) != nil {
				t.Fatal("private late receipt lost its exact source")
			}
			reopened, err := readDesktopOrderedHistory(a)
			if err != nil || len(reopened.Receipts) != 1 || !reflect.DeepEqual(reopened.Receipts[0], r) {
				t.Fatal("private late hop history did not round trip", err)
			}
			r.SourceSHA256 = strings.Repeat("f", 64)
			if node.saveCapturedHistory(a, receipt, r, func() error { return nil }) == nil {
				t.Fatal("foreign private receipt saved")
			}
			saved := saveOrderedConnectionFixture(t, a, nodes)
			late := a.profiles.Profiles[position]
			a.profiles.Profiles[position].DNSPort = 5353
			loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved})
			if loaded.Code != http.StatusOK || a.profiles.Profiles[position].DNSPort != late.DNSPort || !reflect.DeepEqual(a.profiles.Profiles[count-1].MultihopNodes, nodes) {
				t.Fatal("complete saved paired profile lost original late source", loaded.Body)
			}

			control = a.profiles.Profiles[count-1]
			selection, err = resolveDesktopNodeChainSelection(control, a.profiles.Profiles, control.MultihopNodes, "local")
			if err != nil {
				t.Fatal("restored paired selection", err)
			}
			selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal("restored paired source", err)
			}
			status := hopmeasure.Status{Stage: "complete", Complete: true, Drained: true}
			for _, n := range inventory {
				transfer := hopmeasure.Transfer{Bytes: 8 << 20, Seconds: 1, Mbps: float64(8<<20) * 8 / 1e6}
				status.Results = append(status.Results, hopmeasure.Result{ID: n.NodeID, Role: n.Role, Kind: n.Kind, Ready: true, Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}, Download: &transfer, Upload: &transfer})
			}
			_, post := desktopExtendedThroughputPublicReplay(t, a, selection, status)
			var result struct {
				Source desktopOrderedPerformanceSource `json:"ordered_local_source"`
				Rows   []speedLabHopMeasurement        `json:"hops"`
			}
			if err := json.Unmarshal(post, &result); err != nil || !result.Source.PairedWireGuard || len(result.Rows) != count {
				t.Fatal("missing original paired throughput", err)
			}
			for i, row := range result.Rows {
				if row.LatencyLabel != fmt.Sprintf("Cumulative path through node %d of %d HTTP response", i+1, count) {
					t.Fatal("changed original private hop", row)
				}
			}

		})
	}
}
