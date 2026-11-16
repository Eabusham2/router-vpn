package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

func desktopSelectedLatencyFixture(execution string, count int, public bool) (desktopOrderedLatencyCapture, []desktopOrderedLatencyNode) {
	selected := desktopSelectedLatencyCapture{Schema: 1, SourceSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64),
		GenerationSHA256: strings.Repeat("c", 64), Execution: execution, Nodes: []desktopSelectedLatencyNode{}}
	for position := 0; position < count; position++ {
		kind := "private-node"
		if public && position == count-2 {
			kind = "public-path"
		}
		role, _, _, _, _ := desktopSelectedLatencyMeaning(position, count, kind, execution)
		selected.Nodes = append(selected.Nodes, desktopSelectedLatencyNode{NodeID: fmt.Sprintf("node-%d", position), Position: position, Role: role, Kind: kind})
	}
	raw, _ := json.Marshal(selected)
	_, nodes, _ := decodeDesktopSelectedLatencyCapture(string(raw))
	return desktopOrderedLatencyCapture{SessionID: "session-1-1", ProfileID: "home-a", ProfileToken: strings.Repeat("f", 64),
		SourceSHA256: selected.SourceSHA256, ConfigSHA256: selected.ConfigSHA256, GenerationSHA256: selected.GenerationSHA256,
		SelectedCaptureJSON: string(raw)}, nodes
}

func desktopSelectedLatencyReceiptFixture(capture desktopOrderedLatencyCapture, node desktopOrderedLatencyNode) hopmeasure.OrderedLatencyReceipt {
	saved := desktopOrderedReceiptFixtureFor(node.Position, 8, "private-node")
	saved.NodeID, saved.Result.ID = node.NodeID, node.NodeID
	saved.SourceSHA256, saved.ConfigSHA256, saved.GenerationSHA256 = capture.SourceSHA256, capture.ConfigSHA256, capture.GenerationSHA256
	saved.Result.Role, saved.Result.Kind, saved.Result.Label = node.Role, node.Kind, node.Label
	saved.Result.Benchmark.Measurement = node.Measurement
	if node.Kind == "public-path" {
		saved.Result.Benchmark.Endpoint = "https://" + hopmeasure.PublicHost + "/__down?bytes=1"
	}
	return saved
}

func TestDesktopSelectedLatencyCompleteCaptureAndHistory(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		for count := 2; count <= 8; count++ {
			for _, public := range []bool{false, true} {
				if count == 2 && public {
					continue
				}
				t.Run(fmt.Sprintf("%s/%d/%t", execution, count, public), func(t *testing.T) {
					capture, nodes := desktopSelectedLatencyFixture(execution, count, public)
					if len(nodes) != count || validateDesktopSelectedLatencyCaptureBinding(capture) != nil {
						t.Fatal("complete selected native inventory refused")
					}
					a := &app{}
					a.cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
					for position, node := range nodes {
						saved := desktopSelectedLatencyReceiptFixture(capture, node)
						if err := validateDesktopSelectedLatencyReceipt(capture.SelectedCaptureJSON, saved, time.Now()); err != nil {
							t.Fatal("original selected receipt refused", position, err)
						}
						if validateDesktopOrderedReceipt(saved, time.Now()) == nil {
							t.Fatal("selected receipt entered ordinary Local history")
						}
						if err := saveDesktopOrderedCapturedHistory(a, capture, saved, func() error { return nil }); err != nil {
							t.Fatal(err)
						}
					}
					view := desktopOrderedLatencyView{Nodes: nodes, desktopOrderedLatencyRequest: desktopOrderedLatencyRequest{Capture: capture}}
					history, err := readDesktopOrderedLatencyViewHistory(&app{cfg: a.cfg}, view)
					if err != nil || len(history) != count {
						t.Fatal("selected history did not survive restart", err)
					}
					if _, err := os.Stat(desktopOrderedHistoryPath(a)); !os.IsNotExist(err) {
						t.Fatal("selected publication changed ordinary history")
					}
					other := "local"
					if execution == "local" {
						other = "server"
					}
					foreign, foreignNodes := desktopSelectedLatencyFixture(other, count, public)
					view.Capture, view.Nodes = foreign, foreignNodes
					history, err = readDesktopOrderedLatencyViewHistory(a, view)
					if err != nil || len(history) != 0 {
						t.Fatal("history crossed selected execution", err)
					}
				})
			}
		}
	}
}

func TestDesktopSelectedLatencyCaptureRefusesUnownedShape(t *testing.T) {
	original, _ := desktopSelectedLatencyFixture("server", 5, true)
	for _, fault := range []string{"schema", "choice", "source", "config", "generation", "empty", "one-node", "nine-nodes", "duplicate", "position", "role", "kind", "public-entry", "public-final", "earlier-public", "missing-role", "unknown", "unknown-node", "duplicate-json", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			var source map[string]any
			_ = json.Unmarshal([]byte(original.SelectedCaptureJSON), &source)
			nodes := source["nodes"].([]any)
			switch fault {
			case "schema":
				source["schema"] = 2
			case "choice":
				source["selected_execution"] = "auto"
			case "source":
				source["source_sha256"] = strings.Repeat("e", 64)
			case "config":
				source["config_sha256"] = strings.Repeat("e", 64)
			case "generation":
				source["generation_sha256"] = strings.Repeat("e", 64)
			case "empty":
				source["nodes"] = []any{}
			case "one-node":
				source["nodes"] = nodes[:1]
			case "nine-nodes":
				source["nodes"] = append(nodes, nodes[:4]...)
			case "duplicate":
				nodes[1].(map[string]any)["node_id"] = "node-0"
			case "position":
				nodes[1].(map[string]any)["position"] = 2
			case "role":
				nodes[1].(map[string]any)["role"] = "entry"
			case "kind":
				nodes[1].(map[string]any)["kind"] = "latency"
			case "public-entry":
				nodes[0].(map[string]any)["kind"] = "public-path"
			case "public-final":
				nodes[4].(map[string]any)["kind"] = "public-path"
			case "earlier-public":
				nodes[1].(map[string]any)["kind"] = "public-path"
			case "missing-role":
				delete(nodes[1].(map[string]any), "role")
			case "unknown":
				source["credential"] = "not-a-public-field"
			case "unknown-node":
				nodes[1].(map[string]any)["api_token"] = "not-a-public-field"
			}
			// Keep canonical field order for semantic negatives. This prevents
			// whitespace or object ordering from being their only rejection.
			raw, _ := json.Marshal(source)
			if fault != "unknown" && fault != "unknown-node" && fault != "missing-role" {
				var typed desktopSelectedLatencyCapture
				_ = json.Unmarshal(raw, &typed)
				raw, _ = json.Marshal(typed)
			}
			if fault == "duplicate-json" {
				raw = []byte(strings.Replace(original.SelectedCaptureJSON, `"schema":1`, `"schema":1,"schema":1`, 1))
			}
			if fault == "oversized" {
				raw = []byte(strings.Repeat(" ", desktopSelectedLatencyCaptureLimit+1))
			}
			changed := original
			changed.SelectedCaptureJSON = string(raw)
			if validateDesktopSelectedLatencyCaptureBinding(changed) == nil {
				t.Fatal("changed original selected capture accepted")
			}
		})
	}
}

func TestDesktopSelectedLatencyRenewalKeepsOriginalReady(t *testing.T) {
	original := mobilemultihop.DesktopNodeChainExecutionReadyRecord{Schema: 1, ObservedAt: 100, Reader: 1, Generation: 1, SelectionEpoch: 1, MTU: 1280,
		Identity: mobilemultihop.NodeChainIdentity{SessionID: "original", EngineID: "original", NetworkID: "original"},
		Progress: mobilemultihop.NodeChainExecutionProgress{NodeChainProgress: mobilemultihop.NodeChainProgress{Stage: "selected", Execution: "server", Complete: true, Ready: true, DNSProven: true, PublicProven: true,
			Prefixes: []mobilemultihop.NodeChainPrefixProgress{{Position: 0, ProfileID: "entry", ResponseMS: 1, Proven: true}, {Position: 1, ProfileID: "final", ResponseMS: 2, Proven: true}}}}}
	copyReady := func() mobilemultihop.DesktopNodeChainExecutionReadyRecord {
		raw, _ := json.Marshal(original)
		var copy mobilemultihop.DesktopNodeChainExecutionReadyRecord
		_ = json.Unmarshal(raw, &copy)
		return copy
	}
	renewed := copyReady()
	renewed.ObservedAt++
	renewed.Progress.Prefixes[0].ResponseMS, renewed.Progress.Prefixes[1].ResponseMS = 3, 4
	before, _ := json.Marshal(renewed)
	if !sameDesktopSelectedLatencyReady(original, renewed) {
		t.Fatal("valid periodic prefix proof changed selected ownership")
	}
	after, _ := json.Marshal(renewed)
	if string(before) != string(after) {
		t.Fatal("comparison mutated the live native heartbeat")
	}
	for _, fault := range []string{"older", "reader", "epoch", "proof-generation", "engine", "network", "mtu", "choice", "not-ready", "dns", "public", "prefix-id", "prefix-position", "prefix-kind", "prefix-label", "prefix-unproved", "prefix-zero", "prefix-nan", "prefix-infinite", "missing-prefix", "comparison-target"} {
		t.Run(fault, func(t *testing.T) {
			changed := copyReady()
			switch fault {
			case "older":
				changed.ObservedAt--
			case "reader":
				changed.Reader++
			case "epoch":
				changed.SelectionEpoch++
			case "proof-generation":
				changed.Generation++
			case "engine":
				changed.Identity.EngineID = "replacement"
			case "network":
				changed.Identity.NetworkID = "replacement"
			case "mtu":
				changed.MTU++
			case "choice":
				changed.Progress.Execution = "local"
			case "not-ready":
				changed.Progress.Ready = false
			case "dns":
				changed.Progress.DNSProven = false
			case "public":
				changed.Progress.PublicProven = false
			case "prefix-id":
				changed.Progress.Prefixes[0].ProfileID = "foreign"
			case "prefix-position":
				changed.Progress.Prefixes[0].Position++
			case "prefix-kind":
				changed.Progress.Prefixes[0].Kind = "public-path"
			case "prefix-label":
				changed.Progress.Prefixes[0].Label = "foreign"
			case "prefix-unproved":
				changed.Progress.Prefixes[0].Proven = false
			case "prefix-zero":
				changed.Progress.Prefixes[0].ResponseMS = 0
			case "prefix-nan":
				changed.Progress.Prefixes[0].ResponseMS = math.NaN()
			case "prefix-infinite":
				changed.Progress.Prefixes[0].ResponseMS = math.Inf(1)
			case "missing-prefix":
				changed.Progress.Prefixes = changed.Progress.Prefixes[:1]
			case "comparison-target":
				changed.Progress.Comparison.Target = "https://other.example"
			}
			if sameDesktopSelectedLatencyReady(original, changed) {
				t.Fatal("renewal borrowed changed native authority")
			}
		})
	}
}

func TestDesktopSelectedLatencyResultRequiresCompleteOriginalEcho(t *testing.T) {
	capture, nodes := desktopSelectedLatencyFixture("server", 3, true)
	saved := desktopSelectedLatencyReceiptFixture(capture, nodes[0])
	request := desktopOrderedLatencyRequest{Capture: capture, NodeID: nodes[0].NodeID, Position: 0, Request: saved.Request}
	result := desktopSelectedLatencyResult{desktopSelectedLatencyRequest: desktopSelectedLatencyRequest{Schema: 1, Operation: "selected-latency-50", Request: saved.Request,
		Generation: 1, Deadline: time.Now().Add(time.Minute).UnixMilli(), Path: strings.Repeat("e", 64), NodeID: saved.NodeID, Position: 0, Selected: capture.SelectedCaptureJSON},
		Saved: &saved, CompletedAt: saved.MeasuredAt, Status: hopmeasure.Status{Request: saved.Request, Complete: true, Drained: true, Stage: "complete", Results: []hopmeasure.Result{saved.Result}}}
	raw, _ := json.Marshal(result)
	decoded, err := decodeDesktopSelectedLatencyResult(raw)
	if err != nil || !reflect.DeepEqual(decoded, result) || validateDesktopSelectedLatencyResult(request, nodes[0], result, time.Now()) != nil {
		t.Fatal("complete selected native echo refused", err)
	}
	for _, field := range []string{"schema", "operation", "request_id", "generation", "deadline_at", "path_id", "node_id", "position", "capture", "selected_capture", "completed_at", "status"} {
		t.Run("missing-"+field, func(t *testing.T) {
			var changed map[string]json.RawMessage
			_ = json.Unmarshal(raw, &changed)
			delete(changed, field)
			body, _ := json.Marshal(changed)
			if _, err := decodeDesktopSelectedLatencyResult(body); err == nil {
				t.Fatal("native echo omitted required original field")
			}
		})
	}
	for _, fault := range []string{"wrong-choice", "wrong-generation", "partial-fifty", "ordinary-label", "missing-saved", "status-only", "undrained"} {
		t.Run(fault, func(t *testing.T) {
			var changed desktopSelectedLatencyResult
			_ = json.Unmarshal(raw, &changed)
			switch fault {
			case "wrong-choice":
				changed.Selected = strings.Replace(changed.Selected, `"server"`, `"local"`, 1)
			case "wrong-generation":
				changed.Saved.GenerationSHA256 = strings.Repeat("f", 64)
			case "partial-fifty":
				changed.Saved.Result.Benchmark.Attempts--
			case "ordinary-label":
				changed.Saved.Result.Label = "Cumulative path through node 1 of 3"
			case "missing-saved":
				changed.Saved = nil
			case "status-only":
				changed.Status.Results[0].Benchmark.Attempts--
			case "undrained":
				changed.Status.Drained = false
			}
			if validateDesktopSelectedLatencyResult(request, nodes[0], changed, time.Now()) == nil {
				t.Fatal("selected result changed its original receipt")
			}
		})
	}
}

func TestDesktopSelectedLatencyHistoryOriginalRollback(t *testing.T) {
	for _, fault := range []string{"success", "cancel-before-write", "cancel-after-rename", "newer-writer", "same-inode-newer-bytes", "invalid-history", "absent-cancel-after-rename"} {
		t.Run(fault, func(t *testing.T) {
			root := privateStoreTestRoot(t)
			if err := ensurePrivateRuntimeDirectory(root); err != nil {
				t.Fatal(err)
			}
			a := &app{cfg: common.ClientConfig{StateFile: filepath.Join(root, "state.json")}}
			capture, nodes := desktopSelectedLatencyFixture("server", 2, false)
			first, next := desktopSelectedLatencyReceiptFixture(capture, nodes[0]), desktopSelectedLatencyReceiptFixture(capture, nodes[1])
			if fault != "absent-cancel-after-rename" {
				if err := saveDesktopOrderedCapturedHistory(a, capture, first, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			path := desktopSelectedLatencyHistoryPath(a)
			before, _ := os.ReadFile(path)
			replacement := []byte("{\"schema\":1,\"records\":[]}\n")
			if fault == "invalid-history" {
				before = []byte(`{"schema":1,"records":[],"credential":"unexpected"}`)
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			}
			observedPublication := false
			check := func() error {
				if fault == "cancel-before-write" {
					return context.Canceled
				}
				raw, err := os.ReadFile(path)
				if err == nil && !bytes.Equal(raw, before) {
					observedPublication = true
					switch fault {
					case "cancel-after-rename", "absent-cancel-after-rename":
						return context.Canceled
					case "newer-writer":
						if err := atomicWritePrivate(path, replacement); err != nil {
							t.Fatal(err)
						}
						return context.Canceled
					case "same-inode-newer-bytes":
						if err := os.WriteFile(path, replacement, 0600); err != nil {
							t.Fatal(err)
						}
						return context.Canceled
					}
				}
				return nil
			}
			err := saveDesktopOrderedCapturedHistory(a, capture, next, check)
			after, readErr := os.ReadFile(path)
			if fault == "success" {
				history, loadErr := readDesktopSelectedLatencyHistory(a)
				if err != nil || readErr != nil || loadErr != nil || !observedPublication || len(history.Records) != 2 ||
					!reflect.DeepEqual(history.Records[0].Receipt, first) || !reflect.DeepEqual(history.Records[1].Receipt, next) {
					t.Fatal("selected durable receipt changed", err, loadErr)
				}
				info, statErr := os.Lstat(path)
				if statErr != nil || validatePrivateRuntimePathPermissions(path, info) != nil {
					t.Fatal("selected history lost private permissions", statErr)
				}
				return
			}
			if err == nil || readErr != nil {
				t.Fatal("failed selected transaction reported saved", err, readErr)
			}
			switch fault {
			case "newer-writer", "same-inode-newer-bytes":
				if !observedPublication || !bytes.Equal(after, replacement) {
					t.Fatal("selected rollback replaced another writer")
				}
			case "absent-cancel-after-rename":
				history, loadErr := decodeDesktopSelectedLatencyHistory(after)
				if !observedPublication || loadErr != nil || len(history.Records) != 0 {
					t.Fatal("cancelled first selected history remained saved", loadErr)
				}
			default:
				if !bytes.Equal(after, before) {
					t.Fatal("selected rollback changed the original history")
				}
			}
		})
	}
}

func TestDesktopSelectedLatencyPrivateBoundsPreserveRelay(t *testing.T) {
	type document struct {
		Value string `json:"value"`
	}
	small := []byte(`{"value":"retained"}`)
	for _, limit := range []int{16 << 10, 32 << 10, 128 << 10, 1 << 20} {
		var got document
		raw, _ := json.Marshal(document{Value: strings.Repeat("x", 9000)})
		if decodePrivateControlJSONBounded(raw, &got, limit) != nil || len(got.Value) != 9000 {
			t.Fatal("private capture/history bound discarded original bytes")
		}
		if decodeRelayControlJSONBounded(small, &got, limit) == nil {
			t.Fatal("private file limit widened relay authority")
		}
	}
	for _, limit := range []int{multihoprelay.MaxControlResponseBytes, multihoprelay.MaxCapabilitiesBytes} {
		var got document
		if decodeRelayControlJSONBounded(small, &got, limit) != nil || got.Value != "retained" {
			t.Fatal("original relay bound rejected its valid record")
		}
	}
	for _, raw := range [][]byte{[]byte(`{"value":"a","value":"b"}`), []byte(`{"value":"a","unknown":true}`),
		[]byte(`{"value":"a"} {}`), []byte("null"), []byte("[]"), []byte("{\"value\":\"\xff\"}"),
		[]byte(`{"value":"` + strings.Repeat("x", 16<<10) + `"}`)} {
		var got document
		if decodePrivateControlJSONBounded(raw, &got, 16<<10) == nil {
			t.Fatal("private control admitted ambiguous, unknown or excessive bytes")
		}
	}
}
