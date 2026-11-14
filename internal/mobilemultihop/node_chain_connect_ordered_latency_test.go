package mobilemultihop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"router-vpn/internal/hopmeasure"
)

// Shared proof/worker composition, not native TUN or encrypted CONNECT
// acceptance. The original paired HTTP peers perform all fifty requests.
func TestNodeChainCONNECTOrderedLatencyKeepsOriginalServiceAfterReproof(t *testing.T) {
	runtime, engine := newNodeChainCONNECTRuntimeFixture(t, "wg", "http-connect")
	// The generic prefix peer deliberately accepts proof-only cache policy.
	// This paired peer also serves real measurement requests, retaining the
	// original host, token and response identity on both paths.
	proof := runtime.chain.ProofInventory()[0]
	node := runtime.chain.nodes[0]
	api, err := url.Parse(predecessorText(node.profile, "router_api"))
	if err != nil {
		t.Fatal(err)
	}
	var samples atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := r.Header.Get("Cache-Control")
		if r.Method != http.MethodGet || r.URL.Path != "/health" || r.Host != api.Host ||
			r.Header.Get("Authorization") != "Bearer "+predecessorText(node.profile, "api_token") ||
			r.Header.Get("Accept-Encoding") != "identity" || (policy != "no-store" && policy != "no-store, no-transform") {
			t.Error("ordered fifty changed original private API/token/policy ownership")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if policy == "no-store, no-transform" {
			samples.Add(1)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": proof.NodeID, "proof": "router-vpn-private-agent-v1"})
	}))
	t.Cleanup(peer.Close)
	engine.peers[proof.Tag] = peer.Listener.Addr().String()
	if err := runtime.Run(t.Context(), engine); err != nil {
		t.Fatal(err)
	}
	owner := &nodeChainCONNECTMeasurementFixture{runtime: runtime}
	throughput, err := runtime.NewHopMeasurementContext(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := throughput.Close(); err != nil {
			t.Error(err)
		}
	})
	_, meta, err := runtime.source.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	benchmark, err := hopmeasure.NewOrderedLatencyContext(t.Context(), throughput, meta.SourceSHA256, meta.ConfigSHA256)
	if err != nil {
		t.Fatal(err)
	}
	hop := meta.Proofs[0].ProfileID
	run := func(request string) string {
		t.Helper()
		startSamples := samples.Load()
		if err := benchmark.Start(request, hop); err != nil {
			t.Fatal("original ordered fifty admission", err)
		}
		if err := benchmark.Drain(request); err != nil {
			t.Fatal("original fifty worker did not join", err)
		}
		raw := benchmark.SavedJSON(hop)
		var saved hopmeasure.OrderedLatencyReceipt
		if json.Unmarshal([]byte(raw), &saved) != nil || saved.Request != request || saved.Position != 0 || saved.SourceSHA256 != meta.SourceSHA256 || saved.ConfigSHA256 != meta.ConfigSHA256 || !saved.Result.Ready || saved.Result.Benchmark == nil || saved.Result.Benchmark.Attempts != 50 || saved.Result.Benchmark.Distribution == nil || saved.Result.Benchmark.Distribution.Samples != 50 || saved.Result.Idle != nil || saved.Result.Download != nil || saved.Result.Upload != nil {
			t.Fatal("ordered fifty lost exact historical receipt")
		}
		if got := samples.Load() - startSamples; got != 50 {
			t.Fatalf("original private peer received %d samples, want 50", got)
		}
		return raw
	}
	before := run(strings.Repeat("1", 32))
	if err = runtime.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = benchmark.Start(strings.Repeat("2", 32), hop); err == nil {
		t.Fatal("paused original proof admitted fifty samples")
	}
	if benchmark.SavedJSON(hop) != before {
		t.Fatal("proof pause erased previous historical benchmark")
	}
	next, err := NewNodeChainCONNECTRuntime(runtime.source)
	if err != nil {
		t.Fatal(err)
	}
	next.chain.runtime.testTLS = runtime.chain.runtime.testTLS
	t.Cleanup(func() {
		if err := next.CloseContext(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err = next.Run(t.Context(), engine); err != nil {
		t.Fatal(err)
	}
	owner.runtime = next
	after := run(strings.Repeat("3", 32))
	var first, last hopmeasure.OrderedLatencyReceipt
	if json.Unmarshal([]byte(before), &first) != nil || json.Unmarshal([]byte(after), &last) != nil || first.GenerationSHA256 != last.GenerationSHA256 {
		t.Fatal("authorized reproof replaced original measurement identity")
	}
	// Shared worker exclusion remains the existing throughput lease. An idle
	// historical wrapper must not require replacing or closing that service.
	if err := benchmark.Close(); err != nil {
		t.Fatal("borrowed typed facade failed close", err)
	}
	request := strings.Repeat("4", 32)
	if err = throughput.Start(request, 65536); err != nil {
		t.Fatal("fifty wrapper stole original throughput service", err)
	}
	throughput.Cancel(request)
	if err = throughput.Drain(request); err != nil {
		t.Fatal(err)
	}
	if benchmark.SavedJSON(hop) != after || owner.active.Load() {
		t.Fatal("throughput cancellation erased fifty history or retained activity")
	}
}
