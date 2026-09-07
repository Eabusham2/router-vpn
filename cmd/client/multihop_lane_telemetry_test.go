package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestMultihopLaneHTTPClientOnlyAllowsReservedLoopbackLanes(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:1097",
		"http://127.0.0.1:1100",
		"http://localhost:1098",
		"http://10.77.0.1:1098",
		"https://127.0.0.1:1098",
		"socks5://127.0.0.1:1099",
		"not-a-url",
		"http://user:secret@127.0.0.1:1098",
		"http://127.0.0.1:1098/path",
		"http://127.0.0.1:1098/?other=1",
		"http://127.0.0.1:1098?",
		"http://127.0.0.1:1098#other",
	} {
		client, closeIdle, err := newMultihopLaneHTTPClient(raw, time.Second)
		if err == nil {
			if closeIdle != nil {
				closeIdle()
			}
			t.Fatalf("unsafe/non-reserved hop proxy %q was accepted: %#v", raw, client)
		}
	}

	for _, raw := range []string{multihopEntryProofProxy, multihopProofProxy} {
		client, closeIdle, err := newMultihopLaneHTTPClient(raw, time.Second)
		if err != nil {
			t.Fatalf("reserved hop proxy %q was rejected: %v", raw, err)
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok || transport.Proxy == nil {
			closeIdle()
			t.Fatalf("reserved hop proxy %q did not install an HTTP proxy transport", raw)
		}
		req := &http.Request{URL: &url.URL{Scheme: "http", Host: "10.77.0.1:8787", Path: "/health"}}
		proxyURL, err := transport.Proxy(req)
		closeIdle()
		if err != nil {
			t.Fatalf("reserved hop proxy %q could not resolve transport proxy: %v", raw, err)
		}
		if proxyURL == nil || proxyURL.String() != raw {
			t.Fatalf("reserved hop proxy changed identity: got %v want %q", proxyURL, raw)
		}
	}
}

// Different ports on one host can receive forwarded Authorization headers from
// Go's default redirect policy. A hop probe must never follow such a redirect.
func TestMultihopLaneHTTPClientRefusesCredentialRedirect(t *testing.T) {
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/health" {
			if r.Header.Get("Authorization") != "Bearer test-node-token" {
				t.Error("initial proof request lost its node token")
			}
			http.Redirect(w, r, "http://10.77.0.1:9999/redirected", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	client, closeIdle, err := newMultihopLaneHTTPClient(multihopEntryProofProxy, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIdle()
	transport := client.Transport.(*http.Transport)
	// Map the reserved proxy dial to a local test server; never use the real
	// 1098/1099 listeners or any external network while testing.
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "127.0.0.1:1098" {
			t.Errorf("unexpected proxy dial: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, proxy.Listener.Addr().String())
	}
	req, err := http.NewRequest(http.MethodGet, "http://10.77.0.1:8787/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-node-token")
	resp, err := client.Do(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("private hop proof followed a redirect to a different service")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("redirect forwarded a second request; got %d requests", got)
	}
}
