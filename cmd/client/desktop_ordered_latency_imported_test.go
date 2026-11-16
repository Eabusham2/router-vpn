package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

func desktopOrderedIndependentSelection(t *testing.T, layout desktopIndependentImportedLayout) (*app, multihopSelection) {
	t.Helper()
	a, nodes := desktopIndependentImportedFixture(t, layout, "wg", "off")
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
	}
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, selection
}

func TestDesktopOrderedLatencyIndependentImportedInventory(t *testing.T) {
	for _, layout := range desktopIndependentImportedLayouts {
		t.Run(layout.name, func(t *testing.T) {
			_, selection := desktopOrderedIndependentSelection(t, layout)
			launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "linux")
			if err != nil {
				t.Fatal(err)
			}
			_, meta, _, err := launch.chain.readPolicy()
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := desktopOrderedLatencyInventory(selection, meta)
			if err != nil || len(inventory) != layout.count {
				t.Fatal("complete independently captured latency inventory refused", err)
			}
			public := map[int]bool{}
			for _, position := range layout.positions {
				public[position] = true
			}
			for position, node := range inventory {
				kind, label, metric := "private-node", fmt.Sprintf("Cumulative path through node %d of %d", position+1, layout.count), "routed-private-response-including-connection"
				if public[position] {
					kind, label, metric = "public-path", fmt.Sprintf("Cumulative path through custom node %d of %d → Cloudflare edge", position+1, layout.count), "routed-https-response-after-tls"
				}
				if node.Position != position || node.NodeID != selection.Nodes[position].Profile.ID || node.Kind != kind || node.Label != label || node.Measurement != metric {
					t.Fatalf("original position or measurement meaning changed: %+v", node)
				}
				saved := desktopOrderedReceiptFixtureFor(position, layout.count, kind)
				saved.NodeID, saved.Result.ID = node.NodeID, node.NodeID
				if err := validateDesktopOrderedReceipt(saved, time.Now()); err != nil || !desktopOrderedReceiptMatchesNode(saved, node) {
					t.Fatal("complete original fifty receipt refused", err)
				}
				body, err := json.Marshal(desktopOrderedLatencyHistory{Schema: 1, Receipts: []hopmeasure.OrderedLatencyReceipt{saved}})
				if err != nil {
					t.Fatal(err)
				}
				reopened, err := decodeDesktopOrderedHistory(body)
				if err != nil || len(reopened.Receipts) != 1 || !reflect.DeepEqual(reopened.Receipts[0], saved) {
					t.Fatal("restart changed complete original fifty receipt", err)
				}
			}
			for _, fault := range []string{"public-entry", "public-final", "public-to-private", "private-to-public", "foreign-import", "swapped-import", "missing-position", "unknown-kind"} {
				t.Run(fault, func(t *testing.T) {
					bad := meta
					bad.Prefixes = append([]mobilemultihop.NodeChainProof(nil), meta.Prefixes...)
					position := layout.positions[0]
					switch fault {
					case "public-entry":
						bad.Prefixes[0].Kind = "public-path"
					case "public-final":
						bad.Prefixes[layout.count-1].Kind = "public-path"
					case "public-to-private":
						bad.Prefixes[position].Kind = "private-node"
					case "private-to-public":
						if layout.name == "maximum-public" || layout.name == "adjacent" {
							// These graphs have no paired interior. Their final remains private.
							bad.Prefixes[layout.count-1].Kind = "public-path"
						} else {
							for i := 1; i < layout.count-1; i++ {
								if !public[i] {
									bad.Prefixes[i].Kind = "public-path"
									break
								}
							}
						}
					case "foreign-import":
						bad.Prefixes[position].ProfileID = "foreign-import"
					case "swapped-import":
						bad.Prefixes[position], bad.Prefixes[position+1] = bad.Prefixes[position+1], bad.Prefixes[position]
					case "missing-position":
						bad.Prefixes = append(bad.Prefixes[:position], bad.Prefixes[position+1:]...)
					case "unknown-kind":
						bad.Prefixes[position].Kind = "icmp"
					}
					if _, err := desktopOrderedLatencyInventory(selection, bad); err == nil {
						t.Fatal("changed original proof inventory accepted")
					}
				})
			}
		})
	}
}

func TestDesktopOrderedLatencyIndependentImportedReceiptCannotRelabel(t *testing.T) {
	for count := 3; count <= 8; count++ {
		for position := 1; position < count-1; position++ {
			t.Run(fmt.Sprintf("%d-%d", count, position), func(t *testing.T) {
				saved := desktopOrderedReceiptFixtureFor(position, count, "public-path")
				node := desktopOrderedNodeForReceipt(saved)
				request := desktopOrderedLatencyRequest{Capture: desktopOrderedLatencyCapture{SourceSHA256: saved.SourceSHA256, ConfigSHA256: saved.ConfigSHA256, GenerationSHA256: saved.GenerationSHA256}, NodeID: saved.NodeID, Position: position, Request: saved.Request}
				result := desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: desktopNodeChainMeasurementRequest{Schema: 2, Operation: "ordered-latency-50", NodeID: saved.NodeID, Position: position, Request: saved.Request, Deadline: time.Now().Add(time.Minute).UnixMilli()}, CompletedAt: saved.MeasuredAt, Status: hopmeasure.Status{Request: saved.Request, Complete: true, Drained: true, Stage: "complete", Results: []hopmeasure.Result{saved.Result}}, Saved: &saved}
				if err := validateDesktopOrderedLatencyResult(request, node, result, time.Now()); err != nil {
					t.Fatal(err)
				}
				for _, fault := range []string{"count", "position", "kind", "partial", "foreign-generation", "selected-execution"} {
					bad := copyDesktopOrderedReceipt(saved)
					switch fault {
					case "count":
						other := count + 1
						if count == 8 {
							other = 7
							if position == 6 {
								other = 6
							}
						}
						bad.Result.Label = fmt.Sprintf("Cumulative path through custom node %d of %d → Cloudflare edge", position+1, other)
					case "position":
						bad.Position++
					case "kind":
						bad.Result.Kind = "private-node"
					case "partial":
						bad.Result.Benchmark.Attempts--
					case "foreign-generation":
						bad.GenerationSHA256 = strings.Repeat("f", 64)
					case "selected-execution":
						bad.Result.Label = "Local candidate cumulative path through custom node to Cloudflare edge"
					}
					changed := result
					changed.Saved = &bad
					changed.Status.Results = []hopmeasure.Result{bad.Result}
					if validateDesktopOrderedLatencyResult(request, node, changed, time.Now()) == nil {
						t.Fatal("receipt changed original captured meaning:", fault)
					}
				}
			})
		}
	}
	for _, position := range []int{0, 7} {
		if _, kind, _, _, _ := desktopOrderedLatencyMeaning(position, 8, "public-path"); kind != "" {
			t.Fatal("ordinary public benchmark admitted an entry or final")
		}
	}
}

func TestDesktopOrderedLatencyIndependentImportedController(t *testing.T) {
	for _, index := range []int{0, 2, 5} {
		layout := desktopIndependentImportedLayouts[index]
		t.Run(layout.name, func(t *testing.T) {
			a, selection := desktopOrderedIndependentSelection(t, layout)
			// This executes the real parent API, owned mailbox, MTU hold and
			// private durable transaction. Native traffic is an explicit model.
			desktopOrderedLatencyControllerFixture(t, a, selection, layout.positions[len(layout.positions)-1])
			if err := selection.Native.validate(selection); err != nil {
				t.Fatal("parent measurement changed its retained original source", err)
			}
		})
	}
}
