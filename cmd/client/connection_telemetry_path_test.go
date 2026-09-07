package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectionTelemetryRejectsMissingGraphBeforeHTTP(t *testing.T) {
	for _, endpoint := range []string{"latency", "speed"} {
		t.Run(endpoint, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Error(w, "must not be reached without a graph", http.StatusBadGateway)
			}))
			defer server.Close()
			a, _, _ := asyncPathFixture(t, server.URL)
			clearActiveMultihopGraph(a)
			handler := a.connectionLiveLatency
			if endpoint == "speed" {
				handler = a.connectionSpeedTest
			}
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest(http.MethodPost, "/connection/"+endpoint, strings.NewReader(`{"bytes":1048576,"samples":1}`)))
			if w.Code != http.StatusConflict || requests.Load() != 0 {
				t.Fatalf("missing graph reached network: status=%d requests=%d body=%s", w.Code, requests.Load(), w.Body.String())
			}
		})
	}
}

func TestConnectionTelemetryKeepsExactExitAndResponseShape(t *testing.T) {
	for _, route := range []string{"single", "exit"} {
		for _, endpoint := range []string{"latency", "speed"} {
			t.Run(route+"/"+endpoint, func(t *testing.T) {
				a, _, _ := routedSpeedPathFixture(t, route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api/benchmark/download" {
						io.WriteString(w, strings.Repeat("x", 1<<20))
						return
					}
					n, _ := io.Copy(io.Discard, r.Body)
					fmt.Fprintf(w, `{"bytes":%d,"server_receive_ms":1}`, n)
				}))
				handler := a.connectionLiveLatency
				if endpoint == "speed" {
					handler = a.connectionSpeedTest
				}
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest(http.MethodPost, "/connection/"+endpoint, strings.NewReader(`{"bytes":1048576,"samples":1}`)))
				var result struct {
					Connected    bool    `json:"connected"`
					RouterID     string  `json:"router_id"`
					Mode         string  `json:"mode"`
					Bytes        int64   `json:"bytes"`
					Samples      int     `json:"samples"`
					DownloadMbps float64 `json:"download_mbps"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 {
					t.Fatalf("working path failed: %d %s err=%v", w.Code, w.Body.String(), err)
				}
				if !result.Connected || result.RouterID != "exit" || result.Mode != a.state.Mode {
					t.Fatalf("connection response lost live identity: %+v", result)
				}
				if endpoint == "latency" && result.Samples != 1 {
					t.Fatalf("missing measured RTT: %+v", result)
				}
				if endpoint == "speed" && (result.Bytes != 1<<20 || result.DownloadMbps <= 0) {
					t.Fatalf("missing measured throughput: %+v", result)
				}
				if a.profiles.SelectedID != "entry" || !a.state.Connected {
					t.Fatal("telemetry mutated connection choices")
				}
			})
		}
	}
}

func TestConnectionTelemetryCancelsOnDisconnect(t *testing.T) {
	for _, endpoint := range []string{"latency", "speed"} {
		t.Run(endpoint, func(t *testing.T) {
			started := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				started <- struct{}{}
				<-r.Context().Done()
			}))
			defer server.Close()
			a, _, _ := asyncPathFixture(t, server.URL)
			a.state.Mode = "wg"
			clearActiveMultihopGraph(a)
			handler := a.connectionLiveLatency
			if endpoint == "speed" {
				handler = a.connectionSpeedTest
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest(http.MethodPost, "/connection/"+endpoint, strings.NewReader(`{"samples":1,"bytes":1048576}`)).WithContext(ctx))
				done <- w
			}()
			select {
			case <-started:
			case w := <-done:
				t.Fatalf("request did not start: %d %s", w.Code, w.Body.String())
			case <-time.After(time.Second):
				t.Fatal("request did not start")
			}
			a.mu.Lock()
			a.state.Connected = false
			a.state.Phase = "stopping"
			a.mu.Unlock()
			select {
			case w := <-done:
				if w.Code != http.StatusConflict {
					t.Fatalf("bad status: %d %s", w.Code, w.Body.String())
				}
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("telemetry continued after disconnect")
			}
		})
	}
}

func TestConnectedMultihopLatencyRequiresRequestedGraphAndUsesBothLanes(t *testing.T) {
	for _, pair := range []string{"correct", "wrong", "missing"} {
		t.Run(pair, func(t *testing.T) {
			a, _, _ := routedSpeedPathFixture(t, "pair", http.NotFoundHandler())
			if pair == "wrong" {
				graph, _ := getActiveMultihopGraph(a)
				graph.EntryID = "different-entry"
				activeMultihopGraphs.Store(a, graph)
			}
			if pair == "missing" {
				clearActiveMultihopGraph(a)
			}
			w := httptest.NewRecorder()
			a.multihopLiveLatency(w, httptest.NewRequest(http.MethodPost, "/api/multihop/live-latency", strings.NewReader(`{"entry_id":"entry","exit_id":"exit","samples":1}`)))
			if pair != "correct" {
				if w.Code != http.StatusConflict {
					t.Fatalf("unproved graph accepted: %d %s", w.Code, w.Body.String())
				}
				return
			}
			var result struct {
				Entry liveLatencyResult       `json:"entry"`
				Exit  liveLatencyResult       `json:"exit"`
				Path  connectionLatencyResult `json:"current_path"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 {
				t.Fatalf("valid graph failed: %d %s %v", w.Code, w.Body.String(), err)
			}
			if result.Entry.ID != "entry" || result.Exit.ID != "exit" || result.Entry.Samples != 1 || result.Exit.Samples != 1 || result.Path.RouterID != "exit" {
				t.Fatalf("hop measurement misattributed: %+v", result)
			}
			if !strings.Contains(result.Entry.Description, "1098") || !strings.Contains(result.Exit.Description, "1099") {
				t.Fatal("node RTTs did not use distinct proof lanes")
			}
		})
	}
}

func TestDisconnectedMultihopLatencyKeepsCatalogProbesWithoutFakePath(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:8388")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	defer func() { listener.Close(); <-done }()
	a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	a.state.Connected = false
	a.state.Mode = ""
	a.state.Phase = "off"
	clearActiveMultihopGraph(a)
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].Endpoint = "127.0.0.1"
	}
	w := httptest.NewRecorder()
	a.multihopLiveLatency(w, httptest.NewRequest(http.MethodPost, "/api/multihop/live-latency", strings.NewReader(`{"entry_id":"entry","exit_id":"exit","samples":1}`)))
	var result map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 {
		t.Fatalf("catalog probes failed: %d %s %v", w.Code, w.Body.String(), err)
	}
	if result["entry"] == nil || result["exit"] == nil || result["current_path"] != nil {
		t.Fatalf("catalog falsely claimed a connected graph: %s", w.Body.String())
	}
}

func TestMultihopLatencyCannotSalvageSamplesAfterWrongNodeProof(t *testing.T) {
	_, p, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	var calls atomic.Int32
	asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
			return
		}
		io.WriteString(w, `{"ok":true,"node_id":"other-node","proof":"other-proof"}`)
	}))
	value, err := measureRoutedProfileLatencyViaProxyContext(context.Background(), p, 2, multihopProofProxy)
	if err == nil || value.Connected || value.Samples != 0 {
		t.Fatalf("mixed-node RTT survived wrong identity: result=%+v err=%v calls=%d", value, err, calls.Load())
	}
}
