package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/routechoice"
)

func desktopOrderedReceiptFixture(position int) hopmeasure.OrderedLatencyReceipt {
	kind := "private-node"
	if position == 1 {
		kind = "public-path"
	}
	return desktopOrderedReceiptFixtureFor(position, 3, kind)
}
func desktopOrderedReceiptFixtureFor(position, count int, capturedKind string) hopmeasure.OrderedLatencyReceipt {
	role, kind, label, metric, endpoint := desktopOrderedLatencyMeaning(position, count, capturedKind)
	return hopmeasure.OrderedLatencyReceipt{Schema: 1, SourceSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), GenerationSHA256: strings.Repeat("c", 64), Position: position, NodeID: fmt.Sprintf("node-%d", position), Request: strings.Repeat("d", 32), MeasuredAt: time.Now().UnixMilli(), Result: hopmeasure.Result{ID: fmt.Sprintf("node-%d", position), Role: role, Kind: kind, Label: label, Ready: true, Benchmark: &hopmeasure.LatencyBenchmark{Schema: 1, Measurement: metric, Endpoint: endpoint, Attempts: 50, Distribution: &hopmeasure.Latency{Samples: 50, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4, Jitter: 0.5}, TrimmedMean: 2}}}
}
func copyDesktopOrderedReceipt(r hopmeasure.OrderedLatencyReceipt) hopmeasure.OrderedLatencyReceipt {
	raw, _ := json.Marshal(r)
	var copy hopmeasure.OrderedLatencyReceipt
	_ = json.Unmarshal(raw, &copy)
	return copy
}
func TestDesktopOrderedLatencyReceiptRejectsWrongMeaningAndPartialFifty(t *testing.T) {
	for _, position := range []int{0, 1, 2} {
		r := desktopOrderedReceiptFixture(position)
		if err := validateDesktopOrderedReceipt(r, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	faults := map[string]func(*hopmeasure.OrderedLatencyReceipt){
		"schema": func(r *hopmeasure.OrderedLatencyReceipt) { r.Schema++ }, "source": func(r *hopmeasure.OrderedLatencyReceipt) { r.SourceSHA256 = "foreign" }, "generation": func(r *hopmeasure.OrderedLatencyReceipt) { r.GenerationSHA256 = "" }, "future": func(r *hopmeasure.OrderedLatencyReceipt) { r.MeasuredAt = time.Now().Add(time.Minute).UnixMilli() }, "position": func(r *hopmeasure.OrderedLatencyReceipt) { r.Position = 3 }, "node": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.ID = "other" }, "secret-node": func(r *hopmeasure.OrderedLatencyReceipt) { r.NodeID = "https://secret@host/" }, "not-ready": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Ready = false }, "failure": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Failure = "failed fiftieth" }, "throughput": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Download = &hopmeasure.Transfer{} }, "idle-six": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Idle = &hopmeasure.Latency{Samples: 6} }, "response-three": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Response = &hopmeasure.PathResponse{} }, "secret-label": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Label = "token=secret" }, "endpoint": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Endpoint = "https://foreign" }, "meaning": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Measurement = "icmp" }, "attempts": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Attempts = 49 }, "failure-count": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Failed = 1 }, "samples": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Distribution.Samples = 49 }, "nan": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.TrimmedMean = math.NaN() }, "distribution": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Distribution.P90 = 0.5 }, "jitter": func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Distribution.Jitter = -1 },
	}
	faults["probe-budget"] = func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Distribution.Max = 5001 }
	faults["impossible-jitter"] = func(r *hopmeasure.OrderedLatencyReceipt) { r.Result.Benchmark.Distribution.Jitter = 4 }
	for name, mutate := range faults {
		t.Run(name, func(t *testing.T) {
			r := desktopOrderedReceiptFixture(1)
			mutate(&r)
			if validateDesktopOrderedReceipt(r, time.Now()) == nil {
				t.Fatal("foreign/partial receipt accepted")
			}
		})
	}
}
func TestDesktopOrderedLatencySavedReceiptBindsOriginalMailboxAndGeneration(t *testing.T) {
	saved := desktopOrderedReceiptFixture(1)
	request := desktopOrderedLatencyRequest{Capture: desktopOrderedLatencyCapture{SessionID: "session-1-1", ProfileID: "final", ProfileToken: "token", SourceSHA256: saved.SourceSHA256, ConfigSHA256: saved.ConfigSHA256, GenerationSHA256: saved.GenerationSHA256}, NodeID: saved.NodeID, Position: 1, Request: saved.Request}
	result := desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: desktopNodeChainMeasurementRequest{Schema: 2, Operation: "ordered-latency-50", NodeID: saved.NodeID, Position: 1, Request: saved.Request, Deadline: time.Now().Add(time.Minute).UnixMilli()}, CompletedAt: saved.MeasuredAt, Status: hopmeasure.Status{Request: saved.Request, Complete: true, Drained: true, Stage: "complete", Results: []hopmeasure.Result{saved.Result}}, Saved: &saved}
	if err := validateDesktopOrderedLatencyResult(request, desktopOrderedNodeForReceipt(saved), result, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"schema", "operation", "bytes", "position", "request", "source", "config", "generation", "saved-node", "saved-request", "missing-saved", "undrained", "status-request", "status-row", "status-partial", "future-adoption"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(result)
			var bad desktopNodeChainMeasurementResult
			_ = json.Unmarshal(raw, &bad)
			switch fault {
			case "schema":
				bad.Schema = 1
			case "operation":
				bad.Operation = "throughput"
			case "bytes":
				bad.Bytes = 65536
			case "position":
				bad.Position = 0
			case "request":
				bad.Request = strings.Repeat("e", 32)
			case "source":
				bad.Saved.SourceSHA256 = strings.Repeat("e", 64)
			case "config":
				bad.Saved.ConfigSHA256 = strings.Repeat("e", 64)
			case "generation":
				bad.Saved.GenerationSHA256 = strings.Repeat("e", 64)
			case "saved-node":
				bad.Saved.NodeID = "other"
			case "saved-request":
				bad.Saved.Request = strings.Repeat("e", 32)
			case "missing-saved":
				bad.Saved = nil
			case "undrained":
				bad.Status.Drained = false
			case "status-request":
				bad.Status.Request = strings.Repeat("e", 32)
			case "status-row":
				bad.Status.Results[0].Benchmark.TrimmedMean = 2.5
			case "status-partial":
				bad.Status.Results = nil
			case "future-adoption":
				bad.CompletedAt--
			}
			if validateDesktopOrderedLatencyResult(request, desktopOrderedNodeForReceipt(saved), bad, time.Now()) == nil {
				t.Fatal("unbound native saved receipt accepted")
			}
		})
	}
}
func TestDesktopOrderedLatencyHistoryAtomicReadbackAndExactRollback(t *testing.T) {
	for _, fault := range []string{"success", "cancel-before-write", "cancel-after-rename", "newer-writer", "same-inode-newer-bytes", "invalid-history"} {
		t.Run(fault, func(t *testing.T) {
			a := &app{cfg: common.ClientConfig{StateFile: filepath.Join(t.TempDir(), "state.json")}}
			first := desktopOrderedReceiptFixture(0)
			if err := saveDesktopOrderedHistory(a, first, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			path := desktopOrderedHistoryPath(a)
			before, _ := os.ReadFile(path)
			replacement := []byte("{\"schema\":1,\"receipts\":[]}\n")
			if fault == "invalid-history" {
				before = []byte(`{"schema":1,"receipts":[],"secret":"forbidden"}`)
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			}
			next := desktopOrderedReceiptFixture(1)
			calls := 0
			check := func() error {
				calls++
				if fault == "cancel-before-write" {
					return context.Canceled
				}
				if calls == 4 {
					switch fault {
					case "cancel-after-rename":
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
			err := saveDesktopOrderedHistory(a, next, check)
			after, _ := os.ReadFile(path)
			if fault == "success" {
				if err != nil {
					t.Fatal(err)
				}
				history, err := readDesktopOrderedHistory(a)
				if err != nil || len(history.Receipts) != 2 || !reflect.DeepEqual(history.Receipts[0], first) || !reflect.DeepEqual(history.Receipts[1], next) {
					t.Fatal("durable receipt changed", err)
				}
				info, _ := os.Stat(path)
				if info.Mode().Perm()&0077 != 0 {
					t.Fatal("history is not private")
				}
				return
			}
			if err == nil {
				t.Fatal("failed transaction reported saved")
			}
			if fault == "newer-writer" || fault == "same-inode-newer-bytes" {
				if !bytes.Equal(after, replacement) {
					t.Fatal("rollback overwrote newer writer")
				}
			} else if !bytes.Equal(after, before) {
				t.Fatal("failed transaction changed original history")
			}
		})
	}
}
func TestDesktopOrderedLatencyHistoryBoundsAndStrictRestart(t *testing.T) {
	a := &app{cfg: common.ClientConfig{StateFile: filepath.Join(t.TempDir(), "state.json")}}
	h := desktopOrderedLatencyHistory{Schema: 1, Receipts: []hopmeasure.OrderedLatencyReceipt{}}
	for i := 0; i < 128; i++ {
		r := desktopOrderedReceiptFixture(i % 3)
		r.SourceSHA256 = fmt.Sprintf("%064x", i+1)
		h.Receipts = append(h.Receipts, r)
	}
	raw, _ := json.Marshal(h)
	if len(raw) <= 8192 {
		t.Fatal("test failed to exceed ordinary mailbox bound")
	}
	if _, err := decodeDesktopOrderedHistory(raw); err != nil {
		t.Fatal("full bounded history rejected", err)
	}
	if err := atomicWritePrivate(desktopOrderedHistoryPath(a), raw); err != nil {
		t.Fatal(err)
	}
	next := desktopOrderedReceiptFixture(1)
	if err := saveDesktopOrderedHistory(a, next, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	loaded, err := readDesktopOrderedHistory(&app{cfg: a.cfg})
	if err != nil || len(loaded.Receipts) != 128 || loaded.Receipts[0].SourceSHA256 != h.Receipts[1].SourceSHA256 || !reflect.DeepEqual(loaded.Receipts[127], next) {
		t.Fatal("bounded restart history changed", err)
	}
	for _, bad := range [][]byte{[]byte(`{"schema":1,"schema":1,"receipts":[]}`), []byte(`{"schema":1,"receipts":null}`), []byte(`{"schema":1,"receipts":[],"secret":"x"}`), append(raw, []byte(` {}`)...), bytes.Repeat([]byte(" "), desktopOrderedHistoryLimit+1)} {
		if _, err := decodeDesktopOrderedHistory(bad); err == nil {
			t.Fatal("invalid history accepted")
		}
	}
	h.Receipts = append(h.Receipts, h.Receipts[0])
	raw, _ = json.Marshal(h)
	if _, err := decodeDesktopOrderedHistory(raw); err == nil {
		t.Fatal("excess history accepted")
	}
}
func desktopOrderedHTTP(t *testing.T, a *app, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(raw))
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerSpeedLabRoutes(mux, a)
	mux.ServeHTTP(response, request)
	return response
}
func TestDesktopOrderedLatencyCancellationRetainsOriginalCaptureAfterReplacement(t *testing.T) {
	a := &app{}
	slot := a.desktopOrderedLatencyFor()
	saved := desktopOrderedReceiptFixture(1)
	original := desktopOrderedLatencyRequest{Capture: desktopOrderedLatencyCapture{SessionID: "session-1-1", ProfileID: "final", ProfileToken: "revision", SourceSHA256: saved.SourceSHA256, ConfigSHA256: saved.ConfigSHA256, GenerationSHA256: saved.GenerationSHA256}, NodeID: saved.NodeID, Position: 1, Request: saved.Request}
	nodes := []desktopOrderedLatencyNode{{NodeID: "entry", Position: 0}, {NodeID: saved.NodeID, Position: 1}, {NodeID: "final", Position: 2}}
	slot.known[original.Capture] = nodes
	slot.capture = original.Capture
	slot.capture.SessionID = "session-2-2" // replacement; no permission to observe it is granted
	response := desktopOrderedHTTP(t, a, "POST", "/api/speed-lab/ordered-latency/cancel", original)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	var view desktopOrderedLatencyView
	if json.Unmarshal(response.Body.Bytes(), &view) != nil || view.Schema != 1 || view.desktopOrderedLatencyRequest != original || view.Status.Stage != "cancelled" || !view.Status.Complete || !view.Status.Drained || view.Receipt != nil {
		t.Fatal("queued cancellation fabricated or changed original operation")
	}
	if response := desktopOrderedHTTP(t, a, "POST", "/api/speed-lab/ordered-latency/cancel", original); response.Code != 200 {
		t.Fatal("cancellation not idempotent", response.Code)
	}
	wrong := original
	wrong.Capture.ConfigSHA256 = strings.Repeat("f", 64)
	if response := desktopOrderedHTTP(t, a, "POST", "/api/speed-lab/ordered-latency/cancel", wrong); response.Code != 409 {
		t.Fatal("foreign cancellation accepted")
	}
	status := desktopOrderedHTTP(t, a, "GET", "/api/speed-lab/ordered-latency?request_id="+original.Request, nil)
	if status.Code != 200 {
		t.Fatal(status.Code)
	}
	if slot.current != nil {
		t.Fatal("queued cancellation created native work")
	}
}

// Explicit mailbox fixture: source replay, real parent ownership/MTU hold,
// caller API and durable adoption run unchanged; native HTTP traffic belongs
// to the generated/installed child acceptance gates, not this model.
func TestDesktopOrderedLatencyControllerKeepsCapturedLeaseThroughCommit(t *testing.T) {
	a, selection, _ := desktopSOCKSPlatformFixture(t, "wg", "windows")
	desktopOrderedLatencyControllerFixture(t, a, selection, 0)
}

func TestDesktopOrderedLatencyOrdinaryController(t *testing.T) {
	for _, count := range []int{2, 3, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, selection := desktopNodeChainHostSelectionFixture(t, count)
			position := count - 1
			if count == 3 {
				position = 1
			} // A private middle must never borrow the public probe.
			desktopOrderedLatencyControllerFixture(t, a, selection, position)
		})
	}
}

func desktopOrderedLatencyControllerFixture(t *testing.T, a *app, selection multihopSelection, position int) {
	t.Helper()
	f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := retireDesktopOrderedLatencyFixture(ctx, a, f.launch.command); err != nil {
			t.Error("ordered latency fixture left background work before native/file cleanup", err)
		}
	})
	a.cfg.StateFile = filepath.Join(clientRoot(a), "ordered-fifty-state.json")
	f.stagePublish(t)
	if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, a, f.launch); err != nil {
		t.Fatal(err)
	}
	if err := proveDesktopNodeChainContext(f.operation, a, selection, f.launch.command); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.state.Connected, a.state.Phase = true, "connected"
	a.mu.Unlock()
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "session-1-1", Connected: true, Phase: "connected", PathProof: "passed", RouterID: selection.Control.ID}})
	info := desktopOrderedHTTP(t, a, "GET", "/api/speed-lab/ordered-latency", nil)
	var view desktopOrderedLatencyView
	if info.Code != 200 || json.Unmarshal(info.Body.Bytes(), &view) != nil || len(view.Nodes) != len(selection.Nodes) {
		t.Fatal("original capture", info.Code, info.Body.String())
	}
	request := desktopOrderedLatencyRequest{Capture: view.Capture, NodeID: view.Nodes[position].NodeID, Position: position, Request: strings.Repeat("a", 32)}
	foreign := request
	foreign.NodeID = view.Nodes[(position+1)%len(view.Nodes)].NodeID
	if refused := desktopOrderedHTTP(t, a, "POST", "/api/speed-lab/ordered-latency", foreign); refused.Code != 409 {
		t.Fatal("controller admitted another captured member", refused.Code)
	}
	response := desktopOrderedHTTP(t, a, "POST", "/api/speed-lab/ordered-latency", request)
	if response.Code != 202 {
		t.Fatal(response.Code, response.Body.String())
	}
	slot := a.desktopOrderedLatencyFor()
	slot.mu.Lock()
	op := slot.current
	slot.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var mailbox desktopNodeChainMeasurementRequest
	for {
		raw, err := readDesktopRuntimeFileContext(ctx, f.launch, "node-chain-measure-request.json", 16384)
		if err == nil {
			if decodeRelayControlJSON(raw, &mailbox) != nil {
				t.Fatal("invalid mailbox")
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-op.done:
			t.Fatal("original operation refused expected ordinary mailbox", op.view())
		case <-ctx.Done():
			t.Fatal("request did not start", ctx.Err(), op.view())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if mailbox.Schema != 2 || mailbox.Operation != "ordered-latency-50" || mailbox.Request != request.Request || mailbox.Bytes != 0 || !mtuSuspended(a) {
		t.Fatal("operation did not borrow exact original captured mailbox/hold")
	}
	if release, err := beginSpeedLabRun(a); err == nil {
		release()
		t.Fatal("overlapping Speed Lab admitted")
	}
	saved := desktopOrderedReceiptFixtureFor(position, len(view.Nodes), view.Nodes[position].Kind)
	saved.NodeID, saved.Result.ID = request.NodeID, request.NodeID
	saved.Request = request.Request
	saved.SourceSHA256, saved.ConfigSHA256, saved.GenerationSHA256 = request.Capture.SourceSHA256, request.Capture.ConfigSHA256, request.Capture.GenerationSHA256
	result := desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: mailbox, CompletedAt: time.Now().UnixMilli(), Saved: &saved, Status: hopmeasure.Status{Request: request.Request, Complete: true, Drained: true, Stage: "complete", Results: []hopmeasure.Result{saved.Result}}}
	raw, _ := json.Marshal(result)
	if err := writeDesktopRuntimeFile(f.launch, "node-chain-measure-result.json", raw, false); err != nil {
		t.Fatal(err)
	}
	if err := f.launch.directoryRoot.Remove("node-chain-measure-request.json"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-op.done:
	case <-ctx.Done():
		t.Fatal("original operation did not join", ctx.Err(), op.view())
	}
	completed := op.view()
	if completed.Receipt == nil || !completed.Status.Drained || completed.Status.Failure != "" {
		t.Fatal("exact completed receipt not committed", completed)
	}
	history, err := readDesktopOrderedHistory(a)
	if err != nil || len(history.Receipts) != 1 || !reflect.DeepEqual(history.Receipts[0], saved) {
		t.Fatal("durable native receipt differs", err)
	}
	if release, err := beginSpeedLabRun(a); err != nil {
		t.Fatal("joined lease not released", err)
	} else {
		release()
	}
	if response := desktopOrderedHTTP(t, a, "POST", "/api/speed-lab/ordered-latency", request); response.Code != 409 {
		t.Fatal("same original request reused", response.Code)
	}
}

func TestDesktopOrderedLatencyViewWaitsForExactLeaseRelease(t *testing.T) {
	saved := desktopOrderedReceiptFixture(0)
	op := &desktopOrderedLatencyOperation{done: make(chan struct{}), receipt: &saved, status: hopmeasure.Status{Stage: "complete", Complete: true, Drained: true, Results: []hopmeasure.Result{saved.Result}}}
	pending := op.view()
	if pending.Receipt != nil || pending.Status.Complete || pending.Status.Drained || len(pending.Status.Results) != 0 || pending.Status.Stage != "finishing" {
		t.Fatal("completed native worker exposed controller success before its lease release")
	}
	close(op.done)
	joined := op.view()
	if joined.Receipt == nil || !joined.Status.Complete || !joined.Status.Drained || len(joined.Status.Results) != 1 {
		t.Fatal("joined controller lost committed historical receipt")
	}
}

func desktopOrderedNodeForReceipt(r hopmeasure.OrderedLatencyReceipt) desktopOrderedLatencyNode {
	return desktopOrderedLatencyNode{NodeID: r.NodeID, Position: r.Position, Kind: r.Result.Kind, Role: r.Result.Role, Label: r.Result.Label, Measurement: r.Result.Benchmark.Measurement}
}

func TestDesktopOrderedLatencyOriginalInventoryTwoThroughEight(t *testing.T) {
	for count := 2; count <= 8; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			_, launch := desktopNodeChainLaunchFixture(t, count, "linux")
			_, meta, _, err := launch.chain.readPolicy()
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := desktopOrderedLatencyInventory(launch.chain.selection, meta)
			if err != nil || len(nodes) != count {
				t.Fatal("complete actual compiled inventory", err)
			}
			for position, node := range nodes {
				expectedRole := "intermediate"
				if position == 0 {
					expectedRole = "entry"
				} else if position == count-1 {
					expectedRole = "exit"
				}
				if node.NodeID != meta.Prefixes[position].ProfileID || node.Position != position || node.Role != expectedRole || node.Kind != "private-node" || node.Measurement != "routed-private-response-including-connection" || node.Label != fmt.Sprintf("Cumulative path through node %d of %d", position+1, count) {
					t.Fatalf("actual private prefix mislabeled: %+v", node)
				}
				r := desktopOrderedReceiptFixtureFor(position, count, "private-node")
				r.NodeID = node.NodeID
				r.Result.ID = node.NodeID
				if err := validateDesktopOrderedReceipt(r, time.Now()); err != nil || !desktopOrderedReceiptMatchesNode(r, node) {
					t.Fatal("complete captured private receipt", err)
				}
				r.Result.Benchmark.Distribution.Max = 2001
				if validateDesktopOrderedReceipt(r, time.Now()) == nil {
					t.Fatal("private intermediate borrowed the public probe budget")
				}
			}
			for _, fault := range []string{"missing", "position", "foreign-node", "kind", "public-entry"} {
				t.Run(fault, func(t *testing.T) {
					_, bad, _, err := launch.chain.readPolicy()
					if err != nil {
						t.Fatal(err)
					}
					switch fault {
					case "missing":
						bad.Prefixes = bad.Prefixes[:count-1]
					case "position":
						bad.Prefixes[0].Position = 1
					case "foreign-node":
						bad.Prefixes[0].ProfileID = "foreign"
					case "kind":
						bad.Prefixes[0].Kind = "icmp"
					case "public-entry":
						bad.Prefixes[0].Kind = "public-path"
					}
					if _, err := desktopOrderedLatencyInventory(launch.chain.selection, bad); err == nil {
						t.Fatal("changed captured inventory accepted")
					}
				})
			}
		})
	}
	for _, family := range []string{"socks", "connect"} {
		t.Run(family, func(t *testing.T) {
			var selection multihopSelection
			var launch *desktopNodeLaunch
			if family == "socks" {
				_, selection, launch = desktopSOCKSPlatformFixture(t, "wg", "linux")
			} else {
				_, selection, launch = desktopCONNECTPlatformFixture(t, "wg", "linux")
			}
			_, meta, _, err := launch.chain.readPolicy()
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := desktopOrderedLatencyInventory(selection, meta)
			if err != nil || len(nodes) != 3 || nodes[1].Kind != "public-path" || nodes[1].Measurement != "routed-https-response-after-tls" {
				t.Fatal("original imported-middle timing changed", err)
			}
		})
	}
}

func TestDesktopOrderedLatencyReceiptCannotRelabelCapturedPath(t *testing.T) {
	for _, count := range []int{2, 3, 4, 8} {
		for position := 0; position < count; position++ {
			saved := desktopOrderedReceiptFixtureFor(position, count, "private-node")
			node := desktopOrderedNodeForReceipt(saved)
			request := desktopOrderedLatencyRequest{Capture: desktopOrderedLatencyCapture{SourceSHA256: saved.SourceSHA256, ConfigSHA256: saved.ConfigSHA256, GenerationSHA256: saved.GenerationSHA256}, NodeID: saved.NodeID, Position: position, Request: saved.Request}
			result := desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: desktopNodeChainMeasurementRequest{Schema: 2, Operation: "ordered-latency-50", NodeID: saved.NodeID, Position: position, Request: saved.Request, Deadline: time.Now().Add(time.Minute).UnixMilli()}, CompletedAt: saved.MeasuredAt, Status: hopmeasure.Status{Request: saved.Request, Complete: true, Drained: true, Stage: "complete", Results: []hopmeasure.Result{saved.Result}}, Saved: &saved}
			if err := validateDesktopOrderedLatencyResult(request, node, result, time.Now()); err != nil {
				t.Fatal(err)
			}
			otherCount := 8
			if count == 8 {
				otherCount = 7
			}
			if position >= otherCount {
				continue
			}
			wrong := desktopOrderedReceiptFixtureFor(position, otherCount, "private-node")
			wrong.NodeID = saved.NodeID
			wrong.Result.ID = saved.NodeID
			wrong.MeasuredAt = saved.MeasuredAt
			result.Saved = &wrong
			result.Status.Results = []hopmeasure.Result{wrong.Result}
			if validateDesktopOrderedReceipt(wrong, time.Now()) != nil {
				t.Fatal("control must remain an independently valid historical receipt")
			}
			if validateDesktopOrderedLatencyResult(request, node, result, time.Now()) == nil {
				t.Fatal("same digests laundered a different path length")
			}
		}
	}
	private := desktopOrderedReceiptFixtureFor(1, 3, "private-node")
	public := desktopOrderedReceiptFixture(1)
	if desktopOrderedReceiptMatchesNode(public, desktopOrderedNodeForReceipt(private)) {
		t.Fatal("private middle relabeled public")
	}
	if desktopOrderedReceiptMatchesNode(private, desktopOrderedNodeForReceipt(public)) {
		t.Fatal("public middle relabeled private")
	}
}

// The child-owned comparison is a distinct lifetime even when its proved winner
// is Local. Per-node fifty may not start native observation on that authority.
func TestDesktopOrderedLatencyRejectsExecutionBeforeNativeObservation(t *testing.T) {
	for _, winner := range []routechoice.Execution{routechoice.Local, routechoice.Server} {
		t.Run(string(winner), func(t *testing.T) {
			launch, _, graph := desktopExecutionGraphFixture(t, winner)
			original := append([]byte(nil), launch.config...)
			observations := 0
			result, err := exchangeDesktopNodeChainMeasurementOperation(t.Context(), launch, func(context.Context) error {
				observations++
				return nil
			}, &desktopOrderedLatencyTarget{NodeID: launch.chain.selection.Nodes[0].Profile.ID, Position: 0, Request: strings.Repeat("e", 32)})
			if err == nil || observations != 0 || result.Request != "" || launch.chain.measurementGeneration != 0 || launch.chain.measurementOwner != nil || !bytes.Equal(original, launch.config) || graph.Execution != string(winner) {
				t.Fatal("ordinary fifty borrowed the child's selected execution owner", err)
			}
		})
	}
}
