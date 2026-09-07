package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func asyncPathFixture(t *testing.T, api string) (*app, common.RouterProfile, connectionSession) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	p := common.RouterProfile{ID: "exit", NodeKind: "router-vpn", RouterAPI: api, APIToken: "exit-test-token", DNSMode: "custom", DNSHost: "9.9.9.9", FastestDNSHost: "old-result"}
	p.NodeProofID = writeTestWGIdentity(t, root, p.ID)
	a := &app{
		cfg:      common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")},
		profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: "entry", Profiles: []common.RouterProfile{{ID: "entry", RouterAPI: api}, p}},
		state:    state{Connected: true, Phase: "connected", RouterID: p.ID, Mode: "multihop", RuntimeMode: "shadowsocks", Base: "wg"},
	}
	session := connectionSession{ID: "test-session", RouterID: p.ID, Connected: true, Phase: "connected", PathProof: "passed", ActualMode: "shadowsocks", ActualBase: "wg"}
	// Install a stable tracker without starting a background observation loop.
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &session})
	setActiveMultihopGraph(a, multihopSelection{Entry: a.profiles.Profiles[0], Exit: p, Base: "wg", ExitMode: "shadowsocks"})
	t.Cleanup(func() { sessionTrackers.Delete(a); clearActiveMultihopGraph(a) })
	return a, p, session
}

func asyncExitLaneServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:1099")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestRetestDNSRejectsMissingMultihopGraphBeforeHTTP(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, `{"winner":{"address":"1.1.1.1"},"results":[]}`)
	}))
	defer server.Close()
	a, _, _ := asyncPathFixture(t, server.URL)
	clearActiveMultihopGraph(a)
	w := httptest.NewRecorder()
	a.retestDNS(w, httptest.NewRequest(http.MethodPost, "/api/dns/retest", nil))
	if w.Code != http.StatusConflict || requests.Load() != 0 {
		t.Fatalf("unproved graph issued HTTP: status=%d requests=%d body=%s", w.Code, requests.Load(), w.Body.String())
	}
	if a.profiles.Profiles[1].FastestDNSHost != "old-result" {
		t.Fatal("missing graph changed DNS measurement state")
	}
}

func TestRetestDNSUsesProvenExitLaneWithOverlappingNodeAddresses(t *testing.T) {
	a, p, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	var proofs, benchmarks atomic.Int32
	asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() || r.URL.Host != "10.77.0.1:8787" || r.Header.Get("Authorization") != "Bearer exit-test-token" {
			t.Error("request did not preserve the exit's exact private endpoint and token")
		}
		switch r.URL.Path {
		case "/health":
			proofs.Add(1)
			fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
		case "/api/dns/benchmark":
			benchmarks.Add(1)
			if proofs.Load() == 0 {
				t.Error("benchmark preceded exit identity proof")
			}
			io.WriteString(w, `{"winner":{"address":"1.1.1.1","name":"measured","latency_ms":2.5},"results":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	w := httptest.NewRecorder()
	a.retestDNS(w, httptest.NewRequest(http.MethodPost, "/api/dns/retest", nil))
	if w.Code != http.StatusOK || benchmarks.Load() != 1 {
		t.Fatalf("exit-lane DNS test failed: %d %s", w.Code, w.Body.String())
	}
	got := a.profiles.Profiles[1]
	if got.FastestDNSHost != "1.1.1.1" || got.DNSHost != "9.9.9.9" || a.profiles.SelectedID != "entry" {
		t.Fatalf("measurement changed policy or selected node: %+v", got)
	}
}

func TestRetestDNSWrongExitProofCannotStartBenchmark(t *testing.T) {
	a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	var benchmarks atomic.Int32
	asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/dns/benchmark" {
			benchmarks.Add(1)
		}
		io.WriteString(w, `{"ok":true,"node_id":"wrong-node","proof":"wrong-proof"}`)
	}))
	w := httptest.NewRecorder()
	a.retestDNS(w, httptest.NewRequest(http.MethodPost, "/api/dns/retest", nil))
	if w.Code != http.StatusConflict || benchmarks.Load() != 0 || a.profiles.Profiles[1].FastestDNSHost != "old-result" {
		t.Fatalf("wrong exit was accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestRetestDNSCancelsInFlightWorkOnRequestOrGraphChange(t *testing.T) {
	for _, cause := range []string{"request", "graph", "disconnect"} {
		t.Run(cause, func(t *testing.T) {
			a, p, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
			started := make(chan struct{}, 1)
			asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
					return
				}
				io.Copy(io.Discard, r.Body)
				started <- struct{}{}
				<-r.Context().Done()
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				a.retestDNS(w, httptest.NewRequest(http.MethodPost, "/api/dns/retest", nil).WithContext(ctx))
				done <- w
			}()
			select {
			case <-started:
			case w := <-done:
				t.Fatalf("did not start HTTP: %d %s", w.Code, w.Body.String())
			case <-time.After(2 * time.Second):
				t.Fatal("benchmark never started")
			}
			want := http.StatusConflict
			switch cause {
			case "request":
				cancel()
				want = http.StatusRequestTimeout
			case "graph":
				graph, _ := getActiveMultihopGraph(a)
				graph.Started = graph.Started.Add(time.Second)
				activeMultihopGraphs.Store(a, graph)
			case "disconnect":
				a.mu.Lock()
				a.state.Connected = false
				a.state.Phase = "off"
				a.mu.Unlock()
			}
			select {
			case w := <-done:
				if w.Code != want {
					t.Fatalf("wrong cancellation status: %d %s", w.Code, w.Body.String())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("stale benchmark did not stop")
			}
			if a.profiles.Profiles[1].FastestDNSHost != "old-result" {
				t.Fatal("stale benchmark persisted a result")
			}
		})
	}
}

func TestAsyncMeasurementPathSynchronouslyRejectsGraphReplacement(t *testing.T) {
	a, p, session := asyncPathFixture(t, "http://10.77.0.1:8787")
	_, stop, validate, err := asyncMeasurementPathContext(context.Background(), a, p, a.state, session, asyncMeasurementProfileToken(p))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	graph, _ := getActiveMultihopGraph(a)
	graph.Started = graph.Started.Add(time.Second)
	activeMultihopGraphs.Store(a, graph)
	if err := validate(); err == nil {
		t.Fatal("same node IDs but new graph generation was accepted before observer tick")
	}
	if !a.state.Connected {
		t.Fatal("measurement observer disconnected the VPN")
	}
}

func TestAsyncMeasurementHTTPClientUsesExactExitOrOSRoute(t *testing.T) {
	for _, mode := range []string{"wg", "multihop"} {
		client, err := newAsyncMeasurementHTTPClient(state{Mode: mode}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		transport := client.Transport.(*http.Transport)
		if mode == "wg" && transport.Proxy != nil {
			t.Fatal("single-hop request inherited a proxy")
		}
		if mode == "multihop" {
			req, _ := http.NewRequest(http.MethodGet, "https://api.ipify.org", nil)
			proxy, err := transport.Proxy(req)
			if err != nil || proxy.String() != multihopProofProxy {
				t.Fatalf("exit identity lost: %v %v", proxy, err)
			}
		}
		if client.CheckRedirect == nil || !transport.DisableCompression {
			t.Fatal("route HTTP protections were weakened")
		}
		client.CloseIdleConnections()
	}
}

func TestPublicExitRejectsMissingMultihopGraphBeforeNetwork(t *testing.T) {
	a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	clearActiveMultihopGraph(a)
	w := httptest.NewRecorder()
	a.publicIP(w, httptest.NewRequest(http.MethodGet, "/api/public-ip", nil))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "graph") {
		t.Fatalf("public exit did not fail before contacting providers: %d %s", w.Code, w.Body.String())
	}
}
