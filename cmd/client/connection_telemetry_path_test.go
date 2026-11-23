package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"router-vpn/internal/hopmeasure"
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

func TestWholePathRTTFullOriginalGraphIdentity(t *testing.T) {
	original := activeMultihopGraph{EntryID: "entry", ExitID: "exit", Execution: "server", EntryMode: "wg", ExitMode: "shadowsocks", Base: "wg", SourceSHA: strings.Repeat("a", 64), ChainNodes: 9, Started: time.Now()}
	for i := range original.ChainNodes {
		original.orderedIDs[i] = fmt.Sprintf("member-%d", i)
	}
	original.orderedIDs[0], original.orderedIDs[8] = "entry", "exit"
	equivalent := original
	equivalent.Started = original.Started.In(time.FixedZone("offset", 3600))
	if !sameActiveMultihopGraph(original, equivalent) || original.mapRouteID() != equivalent.mapRouteID() {
		t.Fatal("equal instant changed original route identity")
	}
	for _, mutate := range []func(*activeMultihopGraph){
		func(g *activeMultihopGraph) { g.orderedIDs[7] = "replacement" },
		func(g *activeMultihopGraph) { g.Execution = "local" },
		func(g *activeMultihopGraph) { g.SourceSHA = strings.Repeat("b", 64) },
		func(g *activeMultihopGraph) { g.EntryMode = "awg2-fast" },
		func(g *activeMultihopGraph) { g.ImportedEntry = true },
		func(g *activeMultihopGraph) { g.ChainNodes-- },
	} {
		other := original
		mutate(&other)
		if sameActiveMultihopGraph(original, other) || original.mapRouteID() == other.mapRouteID() {
			t.Fatal("a different ordered route reused the original identity")
		}
	}
}

// The first derived observer subscribes to its caller before it synchronously
// validates the original path. Change the graph at the subsequent caller
// cancellation check, after that validation and before the handler dispatches.
type graphChangeAfterCapture struct {
	context.Context
	subscribed atomic.Bool
	changed    atomic.Bool
	replace    func()
}

func (c *graphChangeAfterCapture) Done() <-chan struct{} {
	c.subscribed.Store(true)
	return c.Context.Done()
}

func (c *graphChangeAfterCapture) Err() error {
	if c.subscribed.Load() && c.changed.CompareAndSwap(false, true) {
		c.replace()
	}
	return c.Context.Err()
}

func TestWholePathRTTGraphChangeBeforeDispatch(t *testing.T) {
	a, exit, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	entry := exit
	entry.ID, entry.APIToken = "entry", "entry-test-token"
	entry.NodeProofID = writeTestWGIdentity(t, getenv("HOMEVPN_ROOT", ""), entry.ID)
	a.profiles.Profiles[0] = entry
	ordinary, _ := getActiveMultihopGraph(a)
	ordered := ordinary
	ordered.ChainNodes, ordered.Execution = 2, "server"
	ordered.orderedIDs[0], ordered.orderedIDs[1] = entry.ID, exit.ID
	ordered.SourceSHA = strings.Repeat("a", 64)
	var calls atomic.Int32
	for _, port := range []string{"1098", "1099"} {
		target := entry
		if port == "1099" {
			target = exit
		}
		listener, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.URL.Path != "/health" || r.Header.Get("Authorization") != "Bearer "+target.APIToken {
				t.Error("legacy probe changed its private endpoint or authorization")
			}
			fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, target.NodeProofID, desktopNodeProofKind)
		}))
		server.Listener.Close()
		server.Listener = listener
		server.Start()
		t.Cleanup(server.Close)
	}
	for _, screen := range []string{"connect", "map"} {
		handler, expected := a.connectionLiveLatency, int32(1)
		if screen == "map" {
			handler, expected = a.multihopLiveLatency, 2
		}
		run := func(ctx context.Context) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader(`{"entry_id":"entry","exit_id":"exit","samples":1}`)))
			return w
		}
		activeMultihopGraphs.Store(a, ordinary)
		calls.Store(0)
		if w := run(t.Context()); w.Code != http.StatusOK || calls.Load() != expected {
			t.Fatalf("%s legacy witness did not authenticate: status=%d calls=%d", screen, w.Code, calls.Load())
		}
		for _, original := range []activeMultihopGraph{ordered, ordinary} {
			replacement := ordinary
			if original.ChainNodes == 0 {
				replacement = ordered
			}
			activeMultihopGraphs.Store(a, original)
			calls.Store(0)
			ctx := &graphChangeAfterCapture{Context: context.Background(), replace: func() { activeMultihopGraphs.Store(a, replacement) }}
			w := run(ctx)
			if !ctx.changed.Load() || w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "active multihop graph changed") || calls.Load() != 0 {
				t.Fatalf("%s dispatched after replacing %d-node graph: status=%d calls=%d body=%s", screen, original.ChainNodes, w.Code, calls.Load(), w.Body.String())
			}
		}
	}
}

func TestWholePathRTTSelectedController(t *testing.T) {
	for _, layout := range desktopIndependentSelectedLayouts()[3:] {
		for _, fault := range []string{"", "late-member", "winner"} {
			t.Run(layout.name+"/"+fault, func(t *testing.T) {
				f, view := desktopMultipleImportedSelectedLatencyFixture(t, layout, "auto", "server")
				original, _ := getActiveMultihopGraph(f.a)
				body := fmt.Sprintf(`{"entry_id":%q,"exit_id":%q,"samples":2}`, original.EntryID, original.ExitID)
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					w := httptest.NewRecorder()
					f.a.multihopLiveLatency(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/multihop/live-latency", strings.NewReader(body)))
					done <- w
				}()
				raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedLatencyRequestFile, done)
				var request desktopSelectedLatencyRequest
				if json.Unmarshal(raw, &request) != nil || request.Schema != 3 || request.Operation != "selected-private-response" || request.Samples != 2 || request.Bytes != 0 || request.Position != layout.count-1 || request.Selected != view.Capture.SelectedCaptureJSON {
					t.Fatal("whole-path RTT changed the original selected owner")
				}
				status := hopmeasure.Status{Request: request.Request, Stage: "complete", Complete: true, Drained: true}
				for _, pos := range []int{0, layout.count - 1} {
					node := view.Nodes[pos]
					v := float64(pos + 1)
					status.Results = append(status.Results, hopmeasure.Result{ID: node.NodeID, Kind: node.Kind, Role: node.Role, Label: fmt.Sprintf("Cumulative server path through node %d of %d", pos+1, layout.count), Ready: true,
						Response: &hopmeasure.PathResponse{Schema: 1, Measurement: "routed-private-response-including-connection", Attempts: 2, Distribution: &hopmeasure.Latency{Samples: 2, Min: v, Median: v, Average: v, P90: v, Max: v}}})
				}
				if fault != "" {
					changed := original
					if fault == "winner" {
						changed.Execution = "local"
					} else {
						changed.orderedIDs[layout.count-2] = "another-late-original"
					}
					activeMultihopGraphs.Store(f.a, changed)
					defer activeMultihopGraphs.Store(f.a, original)
				}
				selectedThroughputParentReply(t, f, request, status)
				w := <-done
				if fault != "" {
					if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "active_route_id") || strings.Contains(w.Body.String(), "current_path") {
						t.Fatal("stale ordered RTT escaped", w.Code, w.Body.String())
					}
					return
				}
				var reply struct {
					Route       string `json:"active_route_id"`
					Entry, Exit liveLatencyResult
					Path        connectionLatencyResult `json:"current_path"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Route != original.mapRouteID() || reply.Entry.ID != original.EntryID || reply.Exit.ID != original.ExitID || reply.Path.RouterID != original.ExitID || reply.Path.Samples != 2 || reply.Path.MedianMs != float64(layout.count) || mtuSuspended(f.a) {
					t.Fatal("whole-path RTT lost its joined native endpoint", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestWholePathRTTLocalConnect(t *testing.T) {
	for _, layout := range []desktopIndependentImportedLayout{{"mixed", 3, []int{0, 1}}, desktopIndependentSelectedLayouts()[3], desktopIndependentSelectedLayouts()[4]} {
		t.Run(layout.name, func(t *testing.T) {
			a, selection := desktopOrderedIndependentSelection(t, layout)
			f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
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
			sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "original-ordered-private-response", Connected: true, Phase: "connected", PathProof: "passed", RouterID: selection.Control.ID}})
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				a.connectionLiveLatency(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/connection/live-latency", strings.NewReader(`{"samples":3}`)))
				done <- w
			}()
			raw := waitDesktopSelectedCandidateParentFile(t, t.Context(), f, "node-chain-measure-request.json", done)
			var request desktopNodeChainMeasurementRequest
			if json.Unmarshal(raw, &request) != nil || request.Schema != 3 || request.Operation != "ordered-private-response" || request.Bytes != 0 || request.Samples != 3 || request.Capture.Identity.SourceSHA256 != selection.Native.source {
				t.Fatal("lost original local request")
			}
			status := hopmeasure.Status{Request: request.Request, Stage: "complete", Complete: true, Drained: true}
			for _, i := range []int{0, layout.count - 1} {
				if selection.Nodes[i].Profile.NodeKind == "external" {
					continue
				}
				role := "entry"
				if i == layout.count-1 {
					role = "exit"
				}
				n := float64(i + 1)
				status.Results = append(status.Results, hopmeasure.Result{ID: selection.Nodes[i].Profile.ID, Role: role, Kind: "private-node", Label: fmt.Sprintf("Cumulative path through node %d of %d", i+1, layout.count), Ready: true, Response: &hopmeasure.PathResponse{Schema: 1, Measurement: "routed-private-response-including-connection", Attempts: 3, Distribution: &hopmeasure.Latency{Samples: 3, Min: n, Median: n, Average: n, P90: n, Max: n}}})
			}
			raw, err := json.Marshal(desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: request, CompletedAt: time.Now().UnixMilli(), Status: status})
			if err != nil {
				t.Fatal(err)
			}
			if err = writeDesktopRuntimeFile(f.launch, "node-chain-measure-result.json", raw, false); err != nil {
				t.Fatal(err)
			}
			if err = f.launch.directoryRoot.Remove("node-chain-measure-request.json"); err != nil {
				t.Fatal(err)
			}
			w := <-done
			var reply connectionLatencyResult
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.RouterID != selection.Exit.ID || reply.Samples != 3 || reply.MedianMs != float64(layout.count) || mtuSuspended(a) {
				t.Fatal("Connect lost the original local fresh final response", w.Code, w.Body.String())
			}
		})
	}
}
