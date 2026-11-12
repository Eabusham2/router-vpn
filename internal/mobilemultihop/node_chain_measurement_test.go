package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

type nodeChainMeasurementFixture struct {
	chain    *NodeChain
	active   atomic.Bool
	released atomic.Int32
}

func (o *nodeChainMeasurementFixture) MeasurementChainContext(ctx context.Context) (*NodeChain, error) {
	return o.chain, ctx.Err()
}
func (o *nodeChainMeasurementFixture) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if ctx.Err() != nil || !o.active.CompareAndSwap(false, true) {
		return nil, errors.New("activity occupied")
	}
	return func() { o.released.Add(1); o.active.Store(false) }, nil
}

func TestNodeChainMeasurementsUseEveryCapturedPrivatePrefix(t *testing.T) {
	for _, count := range []int{3, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			chain := nodeChainFixture(t, count, "")
			owner := &nodeChainMeasurementFixture{chain: chain}
			if _, err := chain.NewHopMeasurementContext(context.Background(), owner); err == nil {
				t.Fatal("unproved chain acquired measurement")
			}
			engine := newNodeChainTestEngine(t, chain)
			if err := chain.Run(context.Background(), engine); err != nil {
				t.Fatal(err)
			}
			for position, proof := range chain.proofs {
				node := chain.nodes[position]
				api, _ := url.Parse(predecessorText(node.profile, "router_api"))
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Host != api.Host || r.Header.Get("Authorization") != "Bearer "+predecessorText(node.profile, "api_token") {
						t.Error("measurement substituted prefix credentials")
						w.WriteHeader(401)
						return
					}
					switch r.URL.Path {
					case "/health":
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
						w.WriteHeader(404)
					}
				}))
				t.Cleanup(server.Close)
				engine.mu.Lock()
				engine.peers[proof.Tag] = server.Listener.Addr().String()
				engine.mu.Unlock()
			}
			service, err := chain.NewHopMeasurementContext(context.Background(), owner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			request := strings.Repeat("a", 32)
			if err := service.Start(request, 65536); err != nil {
				t.Fatal(err)
			}
			if err := service.Drain(request); err != nil {
				t.Fatal(err)
			}
			var status hopmeasure.Status
			if err := json.Unmarshal([]byte(service.StatusJSON()), &status); err != nil {
				t.Fatal(err)
			}
			if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != count || owner.active.Load() || owner.released.Load() != 1 {
				t.Fatal("incomplete ordered measurement", status)
			}
			for position, result := range status.Results {
				if !result.Ready || result.ID != chain.proofs[position].ProfileID || result.Download == nil || result.Download.Bytes != 65536 || result.Upload == nil || result.Upload.Bytes != 65536 || result.Benchmark != nil || result.Response != nil {
					t.Fatal("ordered prefix lost its real byte/proof result", position, result)
				}
			}
			engine.mu.Lock()
			engine.identity.NetworkID = "replacement"
			engine.mu.Unlock()
			if err := service.Start(strings.Repeat("b", 32), 65536); err == nil {
				t.Fatal("stale original chain measured replacement")
			}
			if err := json.Unmarshal([]byte(service.StatusJSON()), &status); err != nil || status.Stage != "invalidated" || len(status.Results) != 0 {
				t.Fatal("stale result survived", status, err)
			}
		})
	}
}

func TestNodeChainMeasurementRejectsForeignDestination(t *testing.T) {
	chain := nodeChainFixture(t, 3, "")
	engine := newNodeChainTestEngine(t, chain)
	if err := chain.Run(context.Background(), engine); err != nil {
		t.Fatal(err)
	}
	owned := &nodeChainMeasurementEngine{source: chain, owner: &nodeChainMeasurementFixture{chain: chain}, identity: engine.identity}
	for _, input := range [][2]string{{chain.proofs[0].Tag, "127.0.0.1:1098"}, {chain.proofs[1].Tag, "1.1.1.1:443"}, {"proxy", "10.77.0.1:8787"}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := owned.Dial(ctx, input[0], input[1])
		cancel()
		if err == nil || conn != nil {
			t.Fatal("unowned measurement destination accepted", input)
		}
	}
}

// Neither invalid caller may dispatch into the native owner.
type rejectingNodeMeasurementOwner struct{ t *testing.T }

func (o rejectingNodeMeasurementOwner) MeasurementChainContext(context.Context) (*NodeChain, error) {
	o.t.Fatal("invalid caller reached owner")
	return nil, nil
}
func (o rejectingNodeMeasurementOwner) BeginMeasurementContext(context.Context) (func(), error) {
	o.t.Fatal("invalid caller acquired activity")
	return nil, nil
}
func TestNodeChainMeasurementRejectsInvalidCallerBeforeOwner(t *testing.T) {
	chain := nodeChainFixture(t, 3, "")
	owner := rejectingNodeMeasurementOwner{t}
	if _, err := chain.NewHopMeasurementContext(nil, owner); err == nil {
		t.Fatal("nil caller accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := chain.NewHopMeasurementContext(ctx, owner); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: %v", err)
	}
}
