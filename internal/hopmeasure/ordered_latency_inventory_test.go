package hopmeasure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Only the native tagged dial boundary is mapped to local listeners here.
// Each response is real authenticated HTTP; encrypted graph acceptance is separate.
type ordinaryLatencyInventoryEngine struct {
	*testEngine
	held atomic.Bool
}

func (e *ordinaryLatencyInventoryEngine) IdentityContext(ctx context.Context) (string, error) {
	return e.Identity(), ctx.Err()
}
func (e *ordinaryLatencyInventoryEngine) VerifyMeasurement(ctx context.Context) error {
	return ctx.Err()
}
func (e *ordinaryLatencyInventoryEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.held.CompareAndSwap(false, true) {
		return nil, errors.New("original activity occupied")
	}
	return func() { e.held.Store(false) }, nil
}
func TestOrderedLatencyOrdinaryEveryTwoToEightPosition(t *testing.T) {
	for count := 2; count <= 8; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			engine := &ordinaryLatencyInventoryEngine{testEngine: &testEngine{generation: "original-captured-local", servers: map[string]*httptest.Server{}, destinations: map[string]string{}, requests: map[string]int{}}}
			hops := orderedHops(count)
			seen := make([]atomic.Int32, count)
			for i := range hops {
				h := &hops[i]
				h.Label = fmt.Sprintf("Cumulative path through node %d of %d", i+1, count)
				h.Token = fmt.Sprintf("captured-token-%d", i)
				hop := *h
				position := i
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "GET" || r.URL.Path != "/health" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+hop.Token {
						t.Error("request lost captured private endpoint/token")
						http.Error(w, "bad capture", 403)
						return
					}
					seen[position].Add(1)
					json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": hop.Proof, "proof": "router-vpn-private-agent-v1"})
				}))
				t.Cleanup(server.Close)
				engine.servers[h.Tag] = server
				engine.destinations[h.Tag] = "10.77.0.1:8787"
			}
			original, err := NewOrderedContext(t.Context(), engine, hops)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := original.Close(); err != nil {
					t.Error(err)
				}
			})
			facade, err := NewOrderedLatencyContext(t.Context(), original, strings.Repeat("a", 64), strings.Repeat("b", 64))
			if err != nil {
				t.Fatal(err)
			}
			for i, hop := range hops {
				request := fmt.Sprintf("%032x", i+1)
				if err := facade.Start(request, hop.ID); err != nil {
					t.Fatal(err)
				}
				status := orderedLatencyResult(t, facade, request)
				if status.Failure != "" || len(status.Results) != 1 {
					t.Fatal(status)
				}
				row := status.Results[0]
				if !row.Ready || row.ID != hop.ID || row.Role != hop.Role || row.Kind != "private-node" || row.Label != hop.Label || row.Idle != nil || row.Download != nil || row.Upload != nil || row.Benchmark == nil || row.Benchmark.Attempts != 50 || row.Benchmark.Failed != 0 || row.Benchmark.Distribution == nil || row.Benchmark.Distribution.Samples != 50 || seen[i].Load() != 50 {
					t.Fatal("ordinary fifty changed actual sample inventory", i, row, seen[i].Load())
				}
				var saved OrderedLatencyReceipt
				if json.Unmarshal([]byte(facade.SavedJSON(hop.ID)), &saved) != nil || saved.Position != i || saved.NodeID != hop.ID || saved.Result.Label != hop.Label || saved.Request != request {
					t.Fatal("history lost original position", saved)
				}
			}
			if engine.held.Load() {
				t.Fatal("fifty retained activity after drain")
			}
			if err := facade.Close(); err != nil {
				t.Fatal(err)
			}
			next, err := NewOrderedLatencyContext(t.Context(), original, strings.Repeat("a", 64), strings.Repeat("b", 64))
			if err != nil {
				t.Fatal("facade close retired borrowed service", err)
			}
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
