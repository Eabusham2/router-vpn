package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

// The native transport has its own real packet/byte qualification. These tests
// exercise the shipping parent HTTP handlers and durable profile transaction.
func TestDesktopExtendedSelectedThroughputPublicController(t *testing.T) {
	for _, entryMode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(entryMode, func(t *testing.T) {
			for _, layout := range desktopIndependentSelectedLayouts()[3:] {
				for _, choice := range [][2]string{{"server", "server"}, {"auto", "local"}, {"auto", "server"}} {
					t.Run(layout.name+"/"+choice[0]+"/"+choice[1], func(t *testing.T) {
						f, view := desktopMultipleImportedSelectedLatencyFixtureForEntry(t, layout, entryMode, choice[0], choice[1])
						if view.Capture.ExtendedOriginalNodes != layout.count || view.Capture.ExtendedLocalNodes != 0 {
							t.Fatal("selected source substituted ordinary Local metadata")
						}
						for _, fault := range []string{"missing", "count", "local", "ordinary"} {
							changed := view.Capture
							switch fault {
							case "missing":
								changed.ExtendedOriginalNodes = 0
							case "count":
								changed.ExtendedOriginalNodes--
							case "local":
								changed.ExtendedLocalNodes = layout.count
							case "ordinary":
								changed.SelectedCaptureJSON = ""
							}
							if validateDesktopSelectedLatencyCaptureBinding(changed) == nil {
								t.Fatal("borrowed selected source metadata", fault)
							}
						}
						identity, token, count, err := captureOrderedThroughputContext(t.Context(), f.a)
						if err != nil || count != layout.count || identity.orderedOriginalSource == nil || identity.orderedLocalSource != nil {
							t.Fatal("selected throughput preflight lost original source", err)
						}
						original := identity.orderedOriginalSource
						if original.SourceSHA256 != view.Capture.SourceSHA256 || original.ConfigSHA256 != view.Capture.ConfigSHA256 ||
							original.GenerationSHA256 != view.Capture.GenerationSHA256 || original.Execution != choice[1] || len(original.NodeIDs) != count {
							t.Fatal("preflight changed selected source or winner")
						}
						if selectedThroughputParentCapture(t, f) != token {
							t.Fatal("public preflight changed original capture")
						}
						ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
						defer cancel()
						if w := <-selectedThroughputParentRequest(t, f, ctx, strings.Repeat("0", 64)); w.Code != http.StatusConflict {
							t.Fatal("foreign throughput capture admitted", w.Code)
						}
						done := selectedThroughputParentRequest(t, f, ctx, token)
						raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedLatencyRequestFile, done)
						var request desktopSelectedLatencyRequest
						if json.Unmarshal(raw, &request) != nil || request.Bytes != 8<<20 || request.Position != count-1 ||
							request.Selected != view.Capture.SelectedCaptureJSON || request.Capture.Progress.Execution != choice[1] || !mtuSuspended(f.a) {
							t.Fatal("throughput changed original selected mailbox")
						}
						status := hopmeasure.Status{Request: request.Request, Stage: "complete", Complete: true, Drained: true}
						for position, node := range view.Nodes {
							if original.NodeIDs[position] != node.NodeID {
								t.Fatal("original preflight reordered nodes")
							}
							duration := float64(position + 1)
							transfer := hopmeasure.Transfer{Seconds: duration, Bytes: 8 << 20, Mbps: float64(8<<20) * 8 / duration / 1e6}
							status.Results = append(status.Results, hopmeasure.Result{ID: node.NodeID, Role: node.Role, Kind: node.Kind, Label: node.Label, Ready: true,
								Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}, Download: &transfer, Upload: &transfer})
						}
						selectedThroughputParentReply(t, f, request, status)
						response := <-done
						var body struct {
							Source    *desktopSelectedPerformanceSource `json:"ordered_original_source"`
							Local     *desktopOrderedPerformanceSource  `json:"ordered_local_source"`
							Hops      []speedLabHopMeasurement          `json:"hops"`
							Execution string                            `json:"execution"`
						}
						if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || !reflect.DeepEqual(body.Source, original) ||
							body.Local != nil || body.Execution != choice[1] || len(body.Hops) != count || mtuSuspended(f.a) {
							t.Fatal("selected throughput response lost original joined ownership", response.Code, response.Body.String())
						}
						for position, row := range body.Hops {
							if row.RouterID != original.NodeIDs[position] || row.Speed == nil || row.Speed.Bytes != 8<<20 || !strings.Contains(row.SpeedLabel, "Cumulative "+choice[1]+" path") {
								t.Fatal("selected prefix byte receipt was relabeled", position)
							}
						}
					})
				}
			}

		})
	}
}

func TestConnectionProfileExtendedSelectedTransactionalRestore(t *testing.T) {
	for _, entryMode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(entryMode, func(t *testing.T) {
			for _, layout := range desktopIndependentSelectedLayouts()[3:] {
				for _, execution := range []string{"server", "auto"} {
					t.Run(layout.name+"/"+execution, func(t *testing.T) {
						a, nodes := desktopIndependentImportedFixture(t, layout, entryMode, "off")
						response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
							"name": "Original extended " + execution, "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": execution, "multihop_nodes": nodes,
						})
						if response.Code != http.StatusOK {
							t.Fatal("selected profile save", response.Code, response.Body.String())
						}
						var saved struct {
							Profile connectionProfileRecord `json:"profile"`
						}
						if json.Unmarshal(response.Body.Bytes(), &saved) != nil || len(saved.Profile.NodeChain) != layout.count || saved.Profile.Prefs.MultihopExecution != execution {
							t.Fatal("saved selected inventory changed")
						}
						original := cloneRouterProfileStore(a.profiles)
						position := layout.count / 2
						a.profiles.Profiles[position].DNSPort = 53
						response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.Profile.ID})
						if response.Code != http.StatusOK || a.profiles.Profiles[position].DNSPort != original.Profiles[position].DNSPort ||
							a.profiles.Profiles[layout.count-1].MultihopExecution != execution || !reflect.DeepEqual(a.profiles.Profiles[layout.count-1].MultihopNodes, nodes) {
							t.Fatal("selected profile did not restore complete original inventory", response.Code, response.Body.String())
						}
						a.profiles.Profiles[position].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
						before := cloneRouterProfileStore(a.profiles)
						response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.Profile.ID})
						if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) {
							t.Fatal("changed private source partially restored")
						}
					})
				}
			}

		})
	}
}

func TestDesktopSelectedHistoryKeepsOriginalMultipleImportedDescriptor(t *testing.T) {
	for _, entryMode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(entryMode, func(t *testing.T) {
			for _, layout := range desktopIndependentSelectedLayouts()[3:] {
				t.Run(layout.name, func(t *testing.T) {
					f, view := desktopMultipleImportedSelectedLatencyFixtureForEntry(t, layout, entryMode, "server", "server")
					for _, fault := range []string{"original", "public-source", "original-source"} {
						selected, _, err := decodeDesktopSelectedLatencyCapture(view.Capture.SelectedCaptureJSON)
						if err != nil {
							t.Fatal(err)
						}
						selected.GenerationSHA256 = strings.Repeat("a", 64)
						if fault == "public-source" {
							selected.MultipleImported.Public[len(selected.MultipleImported.Public)-1].SourceSHA256 = strings.Repeat("f", 64)
						}
						if fault == "original-source" {
							selected.MultipleImported.OriginalSourceSHA256 = strings.Repeat("f", 64)
						}
						raw, _ := json.Marshal(selected)
						capture := view.Capture
						capture.SelectedCaptureJSON, capture.GenerationSHA256 = string(raw), selected.GenerationSHA256
						saved := desktopSelectedLatencyReceiptFixture(capture, view.Nodes[layout.count-2])
						history := desktopSelectedLatencyHistory{Schema: 1, Records: []desktopSelectedLatencyHistoryRecord{{Capture: string(raw), Receipt: saved}}}
						body, _ := json.Marshal(history)
						if _, err := decodeDesktopSelectedLatencyHistory(body); err != nil {
							t.Fatal("valid historical shape rejected", fault, err)
						}
						if err := os.WriteFile(desktopSelectedLatencyHistoryPath(f.a), body, 0600); err != nil {
							t.Fatal(err)
						}
						got, err := readDesktopOrderedLatencyViewHistory(f.a, view)
						want := 0
						if fault == "original" {
							want = 1
						}
						if err != nil || len(got) != want {
							t.Fatal("history substituted original private source identity", fault, err, len(got))
						}
					}
				})
			}

		})
	}
}

func TestDesktopMacOSExtendedOriginalBaselineCapture(t *testing.T) {
	for _, entryMode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run(entryMode+"/"+execution, func(t *testing.T) {
				for _, layout := range desktopIndependentSelectedLayouts()[3:] {
					t.Run(fmt.Sprint(layout.count), func(t *testing.T) {
						a, nodes := desktopIndependentImportedFixture(t, layout, entryMode, "off")
						selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[layout.count-1], a.profiles.Profiles, nodes, execution)
						if err != nil {
							t.Fatal(err)
						}
						selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
						if err != nil {
							t.Fatal(err)
						}
						launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "darwin")
						if err != nil {
							t.Fatal(err)
						}
						if execution != "local" {
							selected, err := newDesktopNodeChainExecutionSource(launch.chain, execution)
							if err != nil {
								t.Fatal("selected original macOS preparation", err)
							}
							launch.chain.execution = selected
						}
						capture, err := newDesktopMacOSNodeChainSelection(launch.chain)
						if err != nil || !capture.validMembers() {
							t.Fatal("long original macOS member capture", err)
						}
						value := macOSNodeChainBaselineFixture(capture.Policy, "active")
						value.Schema, value.Capture = 3, capture
						raw, _ := json.Marshal(value)
						if _, err := decodeDesktopMacOSNodeChainReceipt(raw, capture, "active"); err != nil {
							t.Fatal(err)
						}
						if _, err := encodeDesktopMacOSNodeChainBaselineRequest(capture, "current", &value); err != nil {
							t.Fatal(err)
						}
						launch.chain.selection.Nodes[layout.count/2].Profile.StartLayer = "aes-256-gcm"
						if _, err := newDesktopMacOSNodeChainSelection(launch.chain); err == nil {
							t.Fatal("baseline accepted replaced original source")
						}
					})
				}

			})
		}
	}
}
