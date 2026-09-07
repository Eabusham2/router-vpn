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

func routedSpeedPathFixture(t *testing.T, route string, handler http.Handler) (*app, http.HandlerFunc, string) {
	t.Helper()
	a, p, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	entry := p
	entry.ID = "entry"
	entry.APIToken = "entry-test-token"
	entry.NodeProofID = writeTestWGIdentity(t, getenv("HOMEVPN_ROOT", ""), entry.ID)
	a.profiles.Profiles[0] = entry
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			node := p
			if r.Header.Get("Authorization") == "Bearer entry-test-token" {
				node = entry
			}
			fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, node.NodeProofID, desktopNodeProofKind)
			return
		}
		handler.ServeHTTP(w, r)
	})
	if route == "single" {
		server := httptest.NewServer(wrapped)
		t.Cleanup(server.Close)
		a.profiles.Profiles[1].RouterAPI = server.URL
		a.state.Mode, a.state.RuntimeMode = "wg", "wg"
		tracker := sessionTrackerFor(a)
		tracker.mu.Lock()
		tracker.session.ActualMode = "wg"
		tracker.mu.Unlock()
		clearActiveMultihopGraph(a)
		return a, a.profileSpeedTest, `{"id":"exit","bytes":1048576}`
	}
	// Both endpoints deliberately share one private address. Only the reserved
	// loopback lanes distinguish which node an authenticated request reaches.
	for _, address := range []string{"127.0.0.1:1098", "127.0.0.1:1099"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(wrapped)
		server.Listener.Close()
		server.Listener = listener
		server.Start()
		t.Cleanup(server.Close)
	}
	if route == "pair" {
		return a, a.multihopSpeedTest, `{"entry_id":"entry","exit_id":"exit","bytes":1048576}`
	}
	return a, a.profileSpeedTest, fmt.Sprintf(`{"id":%q,"bytes":1048576}`, route)
}

func TestRoutedSpeedRequestsCancelInFlightAfterPathChange(t *testing.T) {
	for _, route := range []string{"single", "entry", "exit", "pair"} {
		t.Run(route, func(t *testing.T) {
			for _, change := range []string{"disconnect", "session", "request", "graph"} {
				if route == "single" && change == "graph" {
					continue
				}
				t.Run(change, func(t *testing.T) {
					started := make(chan struct{}, 1)
					var uploads atomic.Int32
					a, handle, body := routedSpeedPathFixture(t, route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/api/benchmark/upload" {
							uploads.Add(1)
						}
						io.Copy(io.Discard, r.Body)
						select {
						case started <- struct{}{}:
						default:
						}
						<-r.Context().Done()
					}))
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					done := make(chan *httptest.ResponseRecorder, 1)
					go func() {
						w := httptest.NewRecorder()
						handle(w, httptest.NewRequest(http.MethodPost, "/speed-test", strings.NewReader(body)).WithContext(ctx))
						done <- w
					}()
					select {
					case <-started:
					case w := <-done:
						t.Fatalf("measurement did not start: %d %s", w.Code, w.Body.String())
					case <-time.After(2 * time.Second):
						t.Fatal("measurement never reached its owned endpoint")
					}
					want := http.StatusConflict
					switch change {
					case "disconnect":
						a.mu.Lock()
						a.state.Connected, a.state.Phase = false, "stopping"
						a.mu.Unlock()
					case "session":
						tracker := sessionTrackerFor(a)
						tracker.mu.Lock()
						tracker.session.ID = "new-session"
						tracker.mu.Unlock()
					case "graph":
						graph, _ := getActiveMultihopGraph(a)
						graph.Started = graph.Started.Add(time.Second)
						activeMultihopGraphs.Store(a, graph)
					case "request":
						cancel()
						want = http.StatusRequestTimeout
					}
					select {
					case w := <-done:
						if w.Code != want {
							t.Fatalf("wrong cancellation response: %d %s", w.Code, w.Body.String())
						}
					case <-time.After(1500 * time.Millisecond):
						cancel()
						<-done
						t.Fatal("obsolete speed test continued after its request or VPN path changed")
					}
					if uploads.Load() != 0 {
						t.Fatal("obsolete test started the next upload phase")
					}
					if change != "request" && ctx.Err() != nil {
						t.Fatal("measurement cleanup cancelled its independent owner")
					}
					a.mu.Lock()
					connected := a.state.Connected
					a.mu.Unlock()
					if change != "disconnect" && !connected {
						t.Fatal("stopping a measurement disconnected the VPN")
					}
				})
			}
		})
	}
}

func TestRoutedSpeedRequestsRejectUnprovedSessionBeforeNetwork(t *testing.T) {
	for _, route := range []string{"single", "entry", "exit", "pair"} {
		t.Run(route, func(t *testing.T) {
			var requests atomic.Int32
			a, handle, body := routedSpeedPathFixture(t, route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Error(w, "must not start", http.StatusBadGateway)
			}))
			tracker := sessionTrackerFor(a)
			tracker.mu.Lock()
			tracker.session.PathProof = "failed"
			tracker.mu.Unlock()
			w := httptest.NewRecorder()
			handle(w, httptest.NewRequest(http.MethodPost, "/speed-test", strings.NewReader(body)))
			if w.Code != http.StatusConflict || requests.Load() != 0 {
				t.Fatalf("unproved session started transfers: status=%d requests=%d body=%s", w.Code, requests.Load(), w.Body.String())
			}
		})
	}
}

// The stricter preflight must preserve all four real measurement choices, not
// merely make stale-path tests green by disabling working speed tests.
func TestRoutedSpeedRequestsKeepWorkingOnProvedPaths(t *testing.T) {
	for _, route := range []string{"single", "entry", "exit", "pair"} {
		t.Run(route, func(t *testing.T) {
			a, handle, body := routedSpeedPathFixture(t, route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/benchmark/download":
					io.WriteString(w, strings.Repeat("x", 1<<20))
				case "/api/benchmark/upload":
					n, err := io.Copy(io.Discard, r.Body)
					if err != nil {
						t.Error(err)
					}
					fmt.Fprintf(w, `{"bytes":%d,"server_receive_ms":1}`, n)
				default:
					http.NotFound(w, r)
				}
			}))
			w := httptest.NewRecorder()
			handle(w, httptest.NewRequest(http.MethodPost, "/speed-test", strings.NewReader(body)))
			if w.Code != http.StatusOK {
				t.Fatalf("proved path failed: %d %s", w.Code, w.Body.String())
			}
			var payload struct {
				Result  routedSpeedResult `json:"result"`
				Entry   routedSpeedResult `json:"entry"`
				Exit    routedSpeedResult `json:"exit"`
				Current routedSpeedResult `json:"current_path"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if route == "pair" {
				if payload.Entry.RouterID != "entry" || payload.Exit.RouterID != "exit" || payload.Current.RouterID != "exit" {
					t.Fatalf("hop identity was lost: %+v", payload)
				}
			} else {
				want := route
				if route == "single" {
					want = "exit"
				}
				if payload.Result.RouterID != want || payload.Result.Bytes != 1<<20 || payload.Result.DownloadMbps <= 0 || payload.Result.UploadMbps <= 0 {
					t.Fatalf("invalid real transfer result: %+v", payload.Result)
				}
			}
			if !a.state.Connected || a.profiles.SelectedID != "entry" {
				t.Fatal("measurement changed the VPN or selected node")
			}
		})
	}
}
