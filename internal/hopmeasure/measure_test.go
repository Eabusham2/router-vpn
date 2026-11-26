package hopmeasure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testEngine struct {
	mu           sync.Mutex
	generation   string
	servers      map[string]*httptest.Server
	destinations map[string]string
	requests     map[string]int
	wrongToken   bool
	badAck       bool
}

func (e *testEngine) Identity() string { e.mu.Lock(); defer e.mu.Unlock(); return e.generation }
func (e *testEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	e.mu.Lock()
	server, wanted := e.servers[tag], e.destinations[tag]
	e.requests[tag]++
	e.mu.Unlock()
	if server == nil || address != wanted {
		return nil, fmt.Errorf("unexpected native dial tag/destination")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
}
func fixture(t *testing.T) (*Service, *testEngine) {
	t.Helper()
	e := &testEngine{
		generation: "generation-one:local", servers: map[string]*httptest.Server{}, requests: map[string]int{},
		destinations: map[string]string{"entry-wg": "10.77.0.1:8787", "proxy": "10.88.0.1:8787"},
	}
	hops := []Hop{
		{ID: "one", Role: "entry", Tag: "entry-wg", API: "http://10.77.0.1:8787", Token: "token-one", Proof: strings.Repeat("a", 64)},
		{ID: "two", Role: "exit", Tag: "proxy", API: "http://10.88.0.1:8787", Token: "token-two", Proof: strings.Repeat("b", 64)},
	}
	for _, h := range hops {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.mu.Lock()
			e.wrongToken = e.wrongToken || r.Header.Get("Authorization") != "Bearer "+h.Token
			badAck := e.badAck && h.Tag == "proxy"
			e.mu.Unlock()
			switch r.URL.Path {
			case "/health":
				json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": h.Proof, "proof": "router-vpn-private-agent-v1"})
			case "/api/benchmark/download":
				var n int
				if _, err := fmt.Sscanf(r.URL.Query().Get("bytes"), "%d", &n); err != nil || n != 65536 {
					t.Error("unexpected download size")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Length", fmt.Sprint(n))
				w.Header().Set("X-Routervpn-Benchmark", "download-v1")
				w.Header().Set("X-Routervpn-Benchmark-Bytes", fmt.Sprint(n))
				w.Write(make([]byte, n))
			case "/api/benchmark/upload":
				n, err := io.Copy(io.Discard, r.Body)
				if err != nil {
					return
				}
				if badAck {
					n--
				}
				json.NewEncoder(w).Encode(map[string]any{"ok": true, "bytes": n, "direction": "upload", "server_receive_ms": 1, "peer": "10.77.0.2", "proof": "authenticated tunnel-peer private throughput sink"})
			default:
				t.Error("unexpected private API")
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		e.servers[h.Tag] = server
		t.Cleanup(server.Close)
	}
	s, err := New(e, hops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, e
}
func status(t *testing.T, s *Service) Status {
	t.Helper()
	var result Status
	if err := json.Unmarshal([]byte(s.StatusJSON()), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func wait(t *testing.T, s *Service) Status {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if result := status(t, s); result.Complete {
			return result
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("measurement did not terminate")
	return Status{}
}

func TestMeasuresActualSeparateHopBytesAndLatency(t *testing.T) {
	s, engine := fixture(t)
	id := strings.Repeat("1", 32)
	if err := s.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	result := wait(t, s)
	if result.Request != id || len(result.Results) != 2 || result.Failure != "" {
		t.Fatal(result)
	}
	for i, row := range result.Results {
		if !row.Ready || row.ID != s.hops[i].ID || row.Idle == nil || row.Idle.Samples != 6 || row.Download == nil || row.Upload == nil {
			t.Fatal(row)
		}
		for _, transfer := range []*Transfer{row.Download, row.Upload} {
			if transfer.Bytes != 65536 || transfer.Seconds <= 0 ||
				transfer.Mbps != float64(transfer.Bytes)*8/transfer.Seconds/1e6 {
				t.Fatal("measured bytes/timing were lost or a rate was invented", transfer)
			}
		}
	}
	engine.mu.Lock()
	bad := engine.requests["entry-wg"] == 0 || engine.requests["proxy"] == 0 || engine.wrongToken
	engine.mu.Unlock()
	if bad {
		t.Fatal("measurement substituted another hop or credential")
	}
	for _, secret := range []string{"token-one", "token-two", "10.77.0.1", "generation-one"} {
		if strings.Contains(s.StatusJSON(), secret) {
			t.Fatal("private control details leaked")
		}
	}
	engine.mu.Lock()
	engine.generation = "different-original-owner"
	engine.mu.Unlock()
	if current := status(t, s); len(current.Results) != 0 || current.Stage != "invalidated" {
		t.Fatal("retired owner's results survived", current)
	}
}

func TestFailedPrivateTransferNeverBecomesZeroSpeed(t *testing.T) {
	s, engine := fixture(t)
	engine.mu.Lock()
	engine.badAck = true
	engine.mu.Unlock()
	if err := s.Start(strings.Repeat("2", 32), 65536); err != nil {
		t.Fatal(err)
	}
	result := wait(t, s)
	if len(result.Results) != 2 || !result.Results[0].Ready || result.Results[1].Ready ||
		result.Results[1].Failure == "" || result.Results[1].Download != nil || result.Results[1].Upload != nil {
		t.Fatal("unproved transfer was retained as a measurement", result)
	}
}

type heldCandidateTestEngine struct {
	*testEngine
	held atomic.Bool
}

func (e *heldCandidateTestEngine) IdentityContext(ctx context.Context) (string, error) {
	return e.Identity(), ctx.Err()
}
func (e *heldCandidateTestEngine) VerifyMeasurement(ctx context.Context) error { return ctx.Err() }
func (e *heldCandidateTestEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if !e.held.CompareAndSwap(false, true) {
		return nil, ErrStale
	}
	return func() { e.held.Store(false) }, nil
}

type heldCandidateResponse struct {
	attempts         int
	entered, release chan struct{}
}

func (r *heldCandidateResponse) Respond(ctx context.Context, complete func() error) error {
	r.attempts++
	return errors.Join(ctx.Err(), complete())
}
func (r *heldCandidateResponse) Close() error {
	close(r.entered)
	<-r.release
	return nil
}

func TestCandidateCancellationWaitsForOriginalTransportRetirement(t *testing.T) {
	engine := &heldCandidateTestEngine{testEngine: &testEngine{generation: "original"}}
	run := &heldCandidateResponse{entered: make(chan struct{}), release: make(chan struct{})}
	target := CandidateTarget{ID: "replacement", SourceSHA256: strings.Repeat("1", 64), Address: "192.0.2.17:51820"}
	prefix := CandidatePrefix{ID: "entry", Tag: "routervpn-chain-0-123456789abc-node-123456789abc", CaptureSHA256: strings.Repeat("2", 64)}
	service, err := NewCapturedResponseRunContext(context.Background(), engine, prefix, []CandidateTarget{target}, CandidateInventoryBytes,
		func(_ context.Context, selected CandidateTarget) (CandidateResponseRun, error) {
			if selected != target {
				return nil, ErrStale
			}
			return run, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { close(run.release) }) }
	t.Cleanup(func() {
		release()
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	id := strings.Repeat("3", 32)
	if err := service.Start(id, target.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-run.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("candidate did not reach original transport retirement")
	}
	service.Cancel(strings.Repeat("9", 32))
	var blocked CandidateStatus
	if err := json.Unmarshal([]byte(service.StatusJSON()), &blocked); err != nil {
		t.Fatal(err)
	}
	if blocked.Request != id || blocked.Stage == "cancelled" || !engine.held.Load() || blocked.Drained || len(blocked.Results) != 0 {
		t.Fatal("original scope or result escaped blocked retirement")
	}
	service.Cancel(id)
	release()
	if err := service.Drain(id); err != nil {
		t.Fatal(err)
	}
	var done CandidateStatus
	if err := json.Unmarshal([]byte(service.StatusJSON()), &done); err != nil {
		t.Fatal(err)
	}
	if !done.Drained || len(done.Results) != 0 || engine.held.Load() || run.attempts != LatencyBenchmarkSamples {
		t.Fatal("cancellation lost its exact response count or joined cleanup", done)
	}
}
