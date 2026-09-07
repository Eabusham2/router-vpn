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

// Keep HTTPS certificate verification and the production transport factory.
// Only substitute loopback test dial targets; multihop must request its exact
// reserved proxy, never dial a provider directly or honor an environment proxy.
func installPublicExitTestTransport(t *testing.T, multihop bool, handler http.Handler) {
	t.Helper()
	origin := httptest.NewTLSServer(handler)
	t.Cleanup(origin.Close)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || (r.Host != "api64.ipify.org:443" && r.Host != "api.ipify.org:443") {
			t.Errorf("unexpected exit proxy request: %s %s", r.Method, r.Host)
			http.Error(w, "unexpected request", 502)
			return
		}
		upstream, err := net.DialTimeout("tcp", origin.Listener.Addr().String(), time.Second)
		if err != nil { t.Error(err); http.Error(w, "test dial failed", 502); return }
		defer upstream.Close()
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil { t.Error(err); return }
		defer client.Close()
		fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := rw.Flush(); err != nil { return }
		done := make(chan struct{})
		go func() { io.Copy(upstream, rw); upstream.Close(); close(done) }()
		io.Copy(client, upstream)
		client.Close()
		<-done
	}))
	t.Cleanup(proxy.Close)
	transport := origin.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		target := origin.Listener.Addr().String()
		if multihop {
			if address != "127.0.0.1:1099" { return nil, fmt.Errorf("multihop bypassed its exit lane: %s", address) }
			target = proxy.Listener.Addr().String()
		} else if address != "api64.ipify.org:443" && address != "api.ipify.org:443" {
			return nil, fmt.Errorf("single hop used an unowned proxy: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
}

func TestHomeExitProofRequiresOwnedPathBeforeHTTP(t *testing.T) {
	for _, reason := range []string{"missing-graph", "disconnected", "cancelled"} {
		t.Run(reason, func(t *testing.T) {
			var requests atomic.Int32
			installPublicExitTestTransport(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				io.WriteString(w, "203.0.113.12")
			}))
			a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
			t.Cleanup(func() { homeExitProofs.Delete(a) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := http.StatusConflict
			switch reason {
			case "missing-graph": clearActiveMultihopGraph(a)
			case "disconnected": a.state.Connected = false
			case "cancelled": cancel(); want = http.StatusRequestTimeout
			}
			w := httptest.NewRecorder()
			a.proveHomeExit(w, httptest.NewRequest(http.MethodPost, "/api/home-summary/prove-exit", nil).WithContext(ctx))
			if w.Code != want || requests.Load() != 0 { t.Fatalf("status=%d requests=%d body=%s", w.Code, requests.Load(), w.Body.String()) }
			if _, ok := homeExitProofs.Load(a); ok { t.Fatal("unowned path published an exit proof") }
		})
	}
}

func TestPublicExitEndpointsKeepOwnedTransportAndNode(t *testing.T) {
	for _, mode := range []string{"wg", "multihop"} {
		for _, home := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/home=%t", mode, home), func(t *testing.T) {
				var requests atomic.Int32
				installPublicExitTestTransport(t, mode == "multihop", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "identity" { t.Error("unsafe public provider request") }
					io.WriteString(w, "203.0.113.12")
				}))
				a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
				a.state.Mode = mode
				t.Cleanup(func() { homeExitProofs.Delete(a) })
				handler, method := a.publicIP, http.MethodGet
				if home { handler, method = a.proveHomeExit, http.MethodPost }
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest(method, "/exit", nil))
				if w.Code != 200 || requests.Load() != 1 { t.Fatalf("status=%d requests=%d body=%s", w.Code, requests.Load(), w.Body.String()) }
				if a.profiles.Profiles[1].PublicIP != "203.0.113.12" || a.profiles.Profiles[0].PublicIP != "" || a.profiles.SelectedID != "entry" { t.Fatal("public exit attached to the selected node, not the live node") }
				if home {
					var summary homeSummaryResponse
					if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil { t.Fatal(err) }
					if summary.ActualExitStatus != "proved" || summary.ActualExitIP != "203.0.113.12" { t.Fatalf("valid proof not displayed: %+v", summary) }
				}
			})
		}
	}
}

func TestHomeExitProofCancelsInFlightWithoutMutatingVPN(t *testing.T) {
	for _, change := range []string{"request", "disconnect", "session", "graph", "policy"} {
		t.Run(change, func(t *testing.T) {
			started := make(chan struct{}, 2)
			installPublicExitTestTransport(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { started <- struct{}{}; <-r.Context().Done() }))
			a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
			t.Cleanup(func() { homeExitProofs.Delete(a) })
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { w := httptest.NewRecorder(); a.proveHomeExit(w, httptest.NewRequest(http.MethodPost, "/exit", nil).WithContext(ctx)); done <- w }()
			select { case <-started: case w := <-done: t.Fatalf("did not start: %d %s", w.Code, w.Body.String()); case <-ctx.Done(): t.Fatal("request did not reach owned lane") }
			want := http.StatusConflict
			switch change {
			case "request": cancel(); want = http.StatusRequestTimeout
			case "disconnect": a.mu.Lock(); a.state.Connected = false; a.state.Phase = "stopping"; a.mu.Unlock()
			case "session": tr := sessionTrackerFor(a); tr.mu.Lock(); tr.session.ID = "new-session"; tr.mu.Unlock()
			case "graph": graph, _ := getActiveMultihopGraph(a); graph.Started = graph.Started.Add(time.Second); activeMultihopGraphs.Store(a, graph)
			case "policy": a.mu.Lock(); a.profiles.Profiles[1].DNSHost = "8.8.8.8"; a.mu.Unlock()
			}
			select { case w := <-done: if w.Code != want { t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String()) }; case <-time.After(time.Second): cancel(); <-done; t.Fatal("stale Home exit request kept running") }
			if a.profiles.Profiles[1].PublicIP != "" { t.Fatal("stale exit persisted") }
			if _, ok := homeExitProofs.Load(a); ok { t.Fatal("stale exit proof adopted") }
			if change != "disconnect" && !a.state.Connected { t.Fatal("stopping a proof disconnected the VPN") }
		})
	}
}

func TestHomeExitProofRefusesProviderRedirects(t *testing.T) {
	var redirected atomic.Int32
	installPublicExitTestTransport(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/other") { redirected.Add(1); io.WriteString(w, "203.0.113.12"); return }
		http.Redirect(w, r, "https://api.ipify.org/other", http.StatusFound)
	}))
	a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	a.state.Mode = "wg"
	w := httptest.NewRecorder()
	a.proveHomeExit(w, httptest.NewRequest(http.MethodPost, "/exit", nil))
	if w.Code != http.StatusBadGateway || redirected.Load() != 0 { t.Fatalf("redirect followed: %d %s hits=%d", w.Code, w.Body.String(), redirected.Load()) }
}
