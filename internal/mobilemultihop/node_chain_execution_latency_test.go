package mobilemultihop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// These tests exercise the selected execution owner and real authenticated
// private HTTP responses. The runtime fixture is a native ownership model;
// these results do not claim encrypted transport or installed-host acceptance.
// The original measurement fixture deliberately owns a short 30-second
// connection and a one-shot simulated server proof. Fifty-response Retest spans
// multiple proof periods. This fixture keeps the same actual HTTP/runtime and
// receipt validators, with a test-owned session and explicitly simulated proof
// completion events on the same retained native-worker boundary double. A
// heartbeat does not advance ProofAt; the original stale-proof tests are intact.
func executionFiftyMeasurementFixture(t *testing.T, execution string, configure ...func(*nodeChainExecutionRuntimeFixture)) (*nodeChainExecutionRuntimeFixture, *nodeChainExecutionMeasurementTestOwner, *NodeChainExecutionMeasurement) {
	t.Helper()
	f := newNodeChainExecutionRuntimeFixture(t, execution)
	if execution == "auto" {
		f.engine.localDelay, f.engine.serverDelay = time.Millisecond, 30*time.Millisecond
	}
	for _, apply := range configure {
		apply(f)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	nodeChainExecutionMeasurementHTTP(t, f)
	owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
	measurement, err := f.runtime.NewHopMeasurementContext(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := measurement.Close(); err != nil {
			t.Error(err)
		}
	})
	proofCtx, stopProof := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-proofCtx.Done():
				return
			case <-ticker.C:
				f.runner.mu.Lock()
				workers := append([]*nodeChainExecutionRuntimeWorker(nil), f.runner.workers...)
				f.runner.mu.Unlock()
				for _, worker := range workers {
					if worker.alive.Load() && worker.ready.Load() {
						// Explicit native-provider model event, separate from
						// Snapshot/lease heartbeat and the shared50 samples.
						if worker.Bootstrap(proofCtx) != nil {
							return
						}
					}
				}
			}
		}
	}()
	t.Cleanup(func() { stopProof(); <-joined })
	return f, owner, measurement
}

func executionFiftyHTTP(t *testing.T, f *nodeChainExecutionRuntimeFixture) (NodeChainProof, *atomic.Int32) {
	t.Helper()
	selected := f.runtime.Progress().Execution
	proofs, err := f.runtime.projection.ProofInventory(selected)
	if err != nil || len(proofs) != 3 {
		t.Fatal("original selected three-node projection", err)
	}
	position := len(proofs) - 1
	proof := proofs[position]
	node := f.runtime.projection.policy.local.nodes[position]
	api, err := privateAPI(predecessorText(node.profile, "router_api"))
	if err != nil {
		t.Fatal(err)
	}
	token := predecessorText(node.profile, "api_token")
	count := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != api.Host || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "foreign original node", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/health":
			if r.Method != http.MethodGet {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			switch r.Header.Get("Cache-Control") {
			case "no-store, no-transform":
				count.Add(1) // actual benchmark request
			case "no-store": // original periodic execution proof remains active
			default:
				http.Error(w, "uncaptured request kind", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": proof.NodeID, "proof": "router-vpn-private-agent-v1"})
		case "/api/benchmark/download":
			w.Header().Set("Content-Length", "65536")
			w.Header().Set("X-Routervpn-Benchmark", "download-v1")
			w.Header().Set("X-Routervpn-Benchmark-Bytes", "65536")
			_, _ = w.Write(make([]byte, 65536))
		case "/api/benchmark/upload":
			n, _ := io.Copy(io.Discard, r.Body)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "direction": "upload", "bytes": n, "server_receive_ms": 1, "peer": "captured", "proof": "authenticated tunnel-peer private throughput sink"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	f.engine.mu.Lock()
	f.engine.peers[proof.Tag+"/"+api.Host] = server.Listener.Addr().String()
	f.engine.mu.Unlock()
	return proof, count
}

func executionFiftyFacade(t *testing.T, service *NodeChainExecutionMeasurement) *NodeChainExecutionLatency {
	t.Helper()
	value, err := service.NewLatencyBenchmarkContext(t.Context(), func(ctx context.Context) error { return ctx.Err() })
	if err != nil || value == nil {
		t.Fatal("original execution fifty constructor", err)
	}
	t.Cleanup(func() {
		if err := value.Close(); err != nil {
			t.Error("original execution fifty close", err)
		}
	})
	return value
}

func executionFiftyFinish(t *testing.T, facade *NodeChainExecutionLatency, id string) hopmeasure.Status {
	t.Helper()
	deadline := time.NewTimer(hopmeasure.RequestTimeout + hopmeasure.ObservationTimeout)
	defer deadline.Stop()
	for {
		var state hopmeasure.Status
		if json.Unmarshal([]byte(facade.StatusJSON()), &state) != nil {
			t.Fatal("original execution fifty status")
		}
		if state.Complete {
			if err := facade.Drain(id); err != nil {
				t.Fatal("original execution fifty drain", err)
			}
			if json.Unmarshal([]byte(facade.StatusJSON()), &state) != nil || state.Request != id || !state.Complete || !state.Drained {
				t.Fatal("original execution fifty completion identity", state)
			}
			return state
		}
		select {
		case <-deadline.C:
			t.Fatal("original execution fifty did not join within its measurement bound")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func executionFiftyReady(t *testing.T, state hopmeasure.Status, node NodeChainProof, selected string) hopmeasure.Result {
	t.Helper()
	if state.Failure != "" || len(state.Results) != 1 {
		t.Fatal("original execution fifty result missing", state)
	}
	r := state.Results[0]
	if !r.Ready || r.ID != node.ProfileID || r.Role != "exit" || r.Kind != "private-node" || r.Label != fmt.Sprintf("Cumulative %s path through node 3 of 3", selected) || r.Idle != nil || r.Download != nil || r.Upload != nil || r.Benchmark == nil {
		t.Fatal("execution fifty became another measurement or path", r)
	}
	b := r.Benchmark
	if b.Schema != 1 || b.Attempts != 50 || b.Failed != 0 || b.Measurement != "routed-private-response-including-connection" || b.Endpoint != "" || b.Distribution == nil || b.Distribution.Samples != 50 {
		t.Fatal("execution fifty sample/metric inventory", b)
	}
	d := b.Distribution
	for _, v := range []float64{d.Min, d.Median, d.Average, d.P90, d.Max, b.TrimmedMean} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v < d.Min || v > d.Max {
			t.Fatal("execution fifty distribution is not a measured positive interval", d, b.TrimmedMean)
		}
	}
	if d.P90 < d.Median || math.IsNaN(d.Jitter) || math.IsInf(d.Jitter, 0) || d.Jitter < 0 {
		t.Fatal("execution fifty distribution ordering", d)
	}
	return r
}

func TestNodeChainExecutionLatencyRetainsSelectedProjectionAndFiftyResponses(t *testing.T) {
	for _, tc := range []struct{ name, mode, winner string }{{"server", "server", "server"}, {"compare-local", "auto", "local"}, {"compare-server", "auto", "server"}} {
		t.Run(tc.name, func(t *testing.T) {
			f, owner, measurement := executionFiftyMeasurementFixture(t, tc.mode, func(f *nodeChainExecutionRuntimeFixture) {
				if tc.winner == "server" {
					f.engine.localDelay, f.engine.serverDelay = 30*time.Millisecond, time.Millisecond
				}
			})
			if f.runtime.Progress().Execution != tc.winner {
				t.Fatal("fixture did not select requested original winner")
			}
			node, count := executionFiftyHTTP(t, f)
			facade := executionFiftyFacade(t, measurement)
			var capture struct {
				Schema     int                            `json:"schema"`
				Source     string                         `json:"source_sha256"`
				Config     string                         `json:"config_sha256"`
				Generation string                         `json:"generation_sha256"`
				Selected   string                         `json:"selected_execution"`
				Nodes      []nodeChainExecutionLatencyHop `json:"nodes"`
			}
			identity, err := measurement.engine.IdentityContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(identity))
			if json.Unmarshal([]byte(facade.CaptureJSON()), &capture) != nil || capture.Schema != 1 || capture.Source != f.runtime.projection.SourceSHA256() || capture.Config != f.runtime.projection.ConfigSHA256() || capture.Generation != hex.EncodeToString(digest[:]) || capture.Selected != tc.winner || len(capture.Nodes) != 3 {
				t.Fatal("execution fifty did not capture actual projection/trial/epoch", capture)
			}
			proofs, _ := f.runtime.projection.ProofInventory(tc.winner)
			for position, hop := range capture.Nodes {
				role := []string{"entry", "intermediate", "exit"}[position]
				if hop != (nodeChainExecutionLatencyHop{proofs[position].ProfileID, position, role, "private-node"}) {
					t.Fatal("execution fifty changed original inventory", hop)
				}
			}
			f.engine.mu.Lock()
			selections, public := append([]string(nil), f.engine.selections...), append([]string(nil), f.engine.publicCalls...)
			f.engine.mu.Unlock()
			f.mu.Lock()
			beforeRequests := append([]struct{ method, session string }(nil), f.requests...)
			f.mu.Unlock()
			trial, originalService := measurement.engine.trial, measurement.service
			trial.mu.Lock()
			attempt := trial.attempt
			trial.mu.Unlock()
			var remoteRequest multihoprelay.NodeChainRequest
			remoteOwner := ""
			if tc.winner == "server" {
				if attempt == nil {
					t.Fatal("selected server lost its actual lease attempt")
				}
				attempt.mu.Lock()
				remoteRequest, remoteOwner = attempt.request.Clone(), attempt.lease.OwnerID
				attempt.mu.Unlock()
				if remoteRequest.SessionID == "" || remoteOwner == "" {
					t.Fatal("selected server lost its captured remote owner")
				}
			}
			comparison := f.runtime.Progress().Comparison
			id := strings.Repeat("a", 32)
			if err := facade.Start(id, node.ProfileID); err != nil {
				t.Fatal(err)
			}
			state := executionFiftyFinish(t, facade, id)
			result := executionFiftyReady(t, state, node, tc.winner)
			if count.Load() != 50 || owner.active.Load() || owner.releases.Load() != 1 || measurement.service != originalService || measurement.engine.trial != trial {
				t.Fatal("execution fifty changed activity, original service/trial or actual response count", count.Load())
			}
			var saved hopmeasure.OrderedLatencyReceipt
			if json.Unmarshal([]byte(facade.SavedJSON(node.ProfileID)), &saved) != nil || saved.SourceSHA256 != capture.Source || saved.ConfigSHA256 != capture.Config || saved.GenerationSHA256 != capture.Generation || saved.NodeID != node.ProfileID || saved.Position != 2 || saved.Request != id || saved.MeasuredAt <= 0 || !reflect.DeepEqual(saved.Result, result) {
				t.Fatal("execution fifty saved receipt lost actual capture", saved)
			}
			f.engine.mu.Lock()
			changed := !reflect.DeepEqual(selections, f.engine.selections)
			newPublic := append([]string(nil), f.engine.publicCalls[len(public):]...)
			f.engine.mu.Unlock()
			if changed || !reflect.DeepEqual(comparison, f.runtime.Progress().Comparison) {
				t.Fatal("execution fifty reran selection/Compare")
			}
			target, err := url.Parse(Targets[0])
			if err != nil {
				t.Fatal(err)
			}
			for _, call := range newPublic {
				if call != trial.tag+"/"+target.Host {
					t.Fatalf("periodic readiness proof changed original selected route: got %q, want %q", call, trial.tag+"/"+target.Host)
				}
			}
			f.mu.Lock()
			requests := append([]struct{ method, session string }(nil), f.requests...)
			f.mu.Unlock()
			freshStatus := 0
			for _, request := range requests[len(beforeRequests):] {
				if tc.winner != "server" || request.session != remoteRequest.SessionID || request.method != "POST" && request.method != "PUT" {
					t.Fatal("execution fifty replaced its original remote lease", request)
				}
				if request.method == "POST" {
					freshStatus++
				}
			}
			trial.mu.Lock()
			sameAttempt := trial.attempt == attempt
			trial.mu.Unlock()
			if !sameAttempt {
				t.Fatal("execution fifty replaced its actual lease attempt")
			}
			if tc.winner == "server" {
				attempt.mu.Lock()
				retained := reflect.DeepEqual(attempt.request, remoteRequest) && attempt.lease.OwnerID == remoteOwner
				attempt.mu.Unlock()
				if !retained {
					t.Fatal("execution fifty changed original remote request or owner")
				}
			}
			if tc.winner == "server" && freshStatus == 0 {
				t.Fatal("server fifty did not validate a fresh remote receipt")
			}
		})
	}
}

func TestNodeChainExecutionLatencyRejectsUncapturedFactoryAndFacade(t *testing.T) {
	for _, reason := range []string{"copied-measurement", "nil-host", "failed-host", "cancelled", "other-runtime", "retired-native"} {
		t.Run(reason, func(t *testing.T) {
			f, owner, measurement := executionFiftyMeasurementFixture(t, "server")
			candidate := measurement
			ctx := t.Context()
			var calls atomic.Int32
			validate := func(ctx context.Context) error { calls.Add(1); return ctx.Err() }
			restore := func() {}
			switch reason {
			case "copied-measurement":
				candidate = &NodeChainExecutionMeasurement{self: measurement, service: measurement.service, engine: measurement.engine}
			case "nil-host":
				validate = nil
			case "failed-host":
				validate = func(context.Context) error { calls.Add(1); return errors.New("original host association changed") }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "other-runtime":
				other, err := NewNodeChainExecutionRuntime(f.runtime.projection, f.engine)
				if err != nil {
					t.Fatal(err)
				}
				owner.mu.Lock()
				owner.runtime = other
				owner.mu.Unlock()
				restore = func() { owner.mu.Lock(); owner.runtime = f.runtime; owner.mu.Unlock() }
			case "retired-native":
				f.engine.mu.Lock()
				f.engine.alive = false
				f.engine.mu.Unlock()
				restore = func() { f.engine.mu.Lock(); f.engine.alive = true; f.engine.mu.Unlock() }
			}
			bad, err := candidate.NewLatencyBenchmarkContext(ctx, validate)
			restore()
			if bad != nil || err == nil || owner.active.Load() || owner.releases.Load() != 0 {
				t.Fatal("uncaptured factory acquired an execution facade/activity", reason, err)
			}
			if reason == "failed-host" && calls.Load() != 1 || reason == "cancelled" && calls.Load() != 0 {
				t.Fatal("host callback did not retain actual caller boundary", calls.Load())
			}
			if reason == "retired-native" {
				// Actual failed native observation retires the original runtime;
				// restoring the test transport cannot revive that ownership.
				if revived, err := measurement.NewLatencyBenchmarkContext(t.Context(), func(ctx context.Context) error { return ctx.Err() }); revived != nil || err == nil {
					t.Fatal("failed native observation revived its retired runtime")
				}
				return
			}
			// A valid attachment immediately afterward proves the failed ABI call
			// did not leave an inaccessible facade attached to the borrowed owner.
			good := executionFiftyFacade(t, measurement)
			forged := &NodeChainExecutionLatency{self: good, measurement: measurement, service: good.service, capture: good.capture}
			if forged.CaptureJSON() != "" || forged.SavedJSON("foreign") != "" || forged.StatusJSON() != "{}" || forged.Start(strings.Repeat("a", 32), "foreign") == nil || forged.Close() == nil || forged.Drain(strings.Repeat("a", 32)) == nil {
				t.Fatal("copied facade acquired original ownership")
			}
			forged.Cancel(strings.Repeat("a", 32))
			forged.Invalidate()
			if good.CaptureJSON() == "" {
				t.Fatal("copied facade retired original capture")
			}
		})
	}
}

func executionFiftyHeldReleaseAndHistory(t *testing.T, action string) {
	t.Helper()
	f, owner, measurement := executionFiftyMeasurementFixture(t, "server")
	node, _ := executionFiftyHTTP(t, f)
	facade := executionFiftyFacade(t, measurement)
	if err := facade.Start(strings.Repeat("a", 32), node.ProfileID); err != nil {
		t.Fatal(err)
	}
	executionFiftyReady(t, executionFiftyFinish(t, facade, strings.Repeat("a", 32)), node, "server")
	previous := facade.SavedJSON(node.ProfileID)
	if previous == "" {
		t.Fatal("original saved fifty absent")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	owner.releaseHook = func() { close(entered); <-release }
	id := strings.Repeat("b", 32)
	if err := facade.Start(id, node.ProfileID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(hopmeasure.RequestTimeout):
		t.Fatal("completed fifty did not reach original activity release")
	}
	if action == "short-close" {
		ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
		err := facade.CloseContext(ctx)
		cancel()
		if err == nil {
			t.Fatal("short close abandoned retained execution release")
		}
	} else {
		facade.Invalidate()
	}
	var state hopmeasure.Status
	if json.Unmarshal([]byte(facade.StatusJSON()), &state) != nil || state.Request != id || state.Complete || state.Drained || len(state.Results) != 0 || !owner.active.Load() || owner.releases.Load() != 1 {
		t.Fatal("closed facade acknowledged worker-only retirement", state, owner.releases.Load())
	}
	if facade.SavedJSON(node.ProfileID) != previous {
		t.Fatal("unjoined release replaced previous saved fifty")
	}
	if err := measurement.Start(strings.Repeat("c", 32), 65536); err == nil {
		t.Fatal("throughput overlapped retained activity release")
	}
	unblock()
	if err := facade.Close(); err != nil {
		t.Fatal("same original close retry", err)
	}
	if owner.active.Load() || owner.releases.Load() != 2 || facade.SavedJSON(node.ProfileID) != previous {
		t.Fatal("release retry changed history or original activity")
	}
}

func TestNodeChainExecutionLatencyShortCloseRetainsHeldReleaseAndHistory(t *testing.T) {
	executionFiftyHeldReleaseAndHistory(t, "short-close")
}

func TestNodeChainExecutionLatencyInvalidateRetainsHeldReleaseAndHistory(t *testing.T) {
	executionFiftyHeldReleaseAndHistory(t, "invalidate")
}

func TestNodeChainExecutionLatencyRejectsRequestReuseAndPreservesThroughputSuccessor(t *testing.T) {
	var held atomic.Bool
	entered, release, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enterOnce, cancelOnce, releaseOnce sync.Once
	f, owner, measurement := executionFiftyMeasurementFixture(t, "server", func(f *nodeChainExecutionRuntimeFixture) {
		proofs, _ := f.runtime.projection.ProofInventory("server")
		f.engine.beforeDial = func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
			if !held.Load() || tag != proofs[1].Tag {
				return nil, nil, false
			}
			enterOnce.Do(func() { close(entered) })
			select {
			case <-release:
				return nil, nil, false
			case <-ctx.Done():
				cancelOnce.Do(func() { close(cancelled) })
				return nil, ctx.Err(), true
			}
		}
	})
	node, _ := executionFiftyHTTP(t, f)
	facade := executionFiftyFacade(t, measurement)
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unblock()
		if err := measurement.Close(); err != nil {
			t.Error("original successor cleanup", err)
		}
	})
	id := strings.Repeat("a", 32)
	if err := facade.Start(id, node.ProfileID); err != nil {
		t.Fatal(err)
	}
	executionFiftyReady(t, executionFiftyFinish(t, facade, id), node, "server")
	previous, oldScope := facade.SavedJSON(node.ProfileID), facade.scope
	if err := facade.Close(); err != nil {
		t.Fatal(err)
	}
	if err := measurement.Start(id, 65536); err == nil {
		t.Fatal("original service admitted a reused request ID")
	}
	successorID := strings.Repeat("b", 32)
	held.Store(true)
	if err := measurement.Start(successorID, 65536); err != nil {
		t.Fatal("borrowed facade retired original throughput service", err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("fresh-ID successor did not reach its original selected route")
	}
	measurement.engine.mu.Lock()
	successor := measurement.engine.scope
	measurement.engine.mu.Unlock()
	if successor == nil || successor == oldScope || successor.id != successorID {
		t.Fatal("fixture did not acquire a distinct fresh-ID scope")
	}
	facade.Cancel(id)
	if err := facade.Drain(id); err != nil {
		t.Fatal("old captured drain reached successor", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	err := facade.CloseContext(ctx)
	cancel()
	if err != nil {
		t.Fatal("old captured close waited for successor", err)
	}
	select {
	case <-cancelled:
		t.Fatal("late old callback cancelled fresh-ID successor")
	default:
	}
	measurement.engine.mu.Lock()
	current := measurement.engine.scope
	measurement.engine.mu.Unlock()
	if current != successor || !owner.active.Load() || owner.releases.Load() != 1 || facade.SavedJSON(node.ProfileID) != previous {
		t.Fatal("late callback replaced successor or historical receipt")
	}
	unblock()
	waitNodeChainExecutionMeasurement(t, measurement)
	if err := measurement.Drain(successorID); err != nil {
		t.Fatal(err)
	}
	var state hopmeasure.Status
	if json.Unmarshal([]byte(measurement.StatusJSON()), &state) != nil || !state.Complete || !state.Drained || state.Failure != "" || len(state.Results) != 3 || owner.active.Load() || owner.releases.Load() != 2 {
		t.Fatal("original throughput successor did not join", state)
	}
	for _, result := range state.Results {
		if !result.Ready || result.Download == nil || result.Download.Bytes != 65536 || result.Upload == nil || result.Upload.Bytes != 65536 || result.Benchmark != nil {
			t.Fatal("borrowed close lost actual throughput", result)
		}
	}
}

func TestNodeChainExecutionLatencyRequiresFreshServerReceiptAfterRelease(t *testing.T) {
	var reject atomic.Bool
	f, owner, measurement := executionFiftyMeasurementFixture(t, "server", func(f *nodeChainExecutionRuntimeFixture) {
		f.mutateStatus = func(status *multihoprelay.NodeChainLeaseStatus) {
			if reject.Load() {
				status.Receipt.Nonce = strings.Repeat("b", 64)
			}
		}
	})
	node, _ := executionFiftyHTTP(t, f)
	facade := executionFiftyFacade(t, measurement)
	first := strings.Repeat("a", 32)
	if err := facade.Start(first, node.ProfileID); err != nil {
		t.Fatal(err)
	}
	executionFiftyReady(t, executionFiftyFinish(t, facade, first), node, "server")
	previous := facade.SavedJSON(node.ProfileID)
	if previous == "" {
		t.Fatal("original saved fifty absent")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { reject.Store(false); unblock() })
	owner.releaseHook = func() { close(entered); <-release }
	second := strings.Repeat("b", 32)
	if err := facade.Start(second, node.ProfileID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(hopmeasure.RequestTimeout):
		t.Fatal("measured result did not reach original release")
	}
	// All samples and their worker-boundary checks have completed. The remote
	// proof becomes invalid before the stronger native release may publish them.
	reject.Store(true)
	unblock()
	if err := facade.Drain(second); err != nil {
		t.Fatal("original release did not join", err)
	}
	var state hopmeasure.Status
	if json.Unmarshal([]byte(facade.StatusJSON()), &state) != nil {
		t.Fatal("invalid original status")
	}
	for _, result := range state.Results {
		if result.Ready {
			t.Fatal("pending result published after original remote receipt was lost", state)
		}
	}
	if facade.SavedJSON(node.ProfileID) != previous {
		t.Fatal("stale server receipt committed pending fifty history")
	}
	if owner.active.Load() || owner.releases.Load() != 2 {
		t.Fatal("remote receipt refusal lost joined local activity")
	}
}
