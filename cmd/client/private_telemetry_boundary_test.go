package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPrivateTelemetryBoundaryAcceptsOwnedBenchmarkEndpoints(t *testing.T) {
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "http://10.77.0.1:8787/api/benchmark/download"},
		{http.MethodGet, "http://10.77.0.1:8787/api/benchmark/download?bytes=1"},
		{http.MethodGet, "http://10.77.0.1:8787/api/benchmark/download?bytes=16777216"},
		{http.MethodPost, "http://10.77.0.1:8787/api/benchmark/upload"},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			if err := validatePrivateBenchmarkTarget(tc.method, tc.target); err != nil {
				t.Fatalf("owned benchmark endpoint rejected: %v", err)
			}
		})
	}
}

func TestPrivateTelemetryBoundaryRejectsTargetsBeforeAttachingCredentials(t *testing.T) {
	const download = "http://10.77.0.1:8787/api/benchmark/download"
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "https://1.1.1.1/api/benchmark/download"},
		{http.MethodGet, "https://example.invalid/api/benchmark/download"},
		{http.MethodGet, "ftp://10.77.0.1:8787/api/benchmark/download"},
		{http.MethodGet, "http://user:password@10.77.0.1:8787/api/benchmark/download"},
		{http.MethodGet, "http://10.77.0.1:8787/api/benchmark/%64ownload"},
		{http.MethodGet, "http://10.77.0.1:8787/health"},
		{http.MethodGet, download + "/"},
		{http.MethodGet, download + "#"},
		{http.MethodGet, download + "#other"},
		{http.MethodGet, download + "?"},
		{http.MethodGet, download + "?bytes=0"},
		{http.MethodGet, download + "?bytes=-1"},
		{http.MethodGet, download + "?bytes=16777217"},
		{http.MethodGet, download + "?bytes=invalid"},
		{http.MethodGet, download + "?bytes=1&bytes=2"},
		{http.MethodGet, download + "?bytes=1&other=2"},
		{http.MethodGet, download + "?other=1"},
		{http.MethodGet, download + "?bytes=%zz"},
		{http.MethodPost, download},
		{http.MethodDelete, download},
		{http.MethodGet, "http://10.77.0.1:8787/api/benchmark/upload"},
		{http.MethodPost, "http://10.77.0.1:8787/api/benchmark/upload?bytes=1"},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			req, err := privateBenchmarkRequest(tc.method, tc.target, "fixture-node-token", nil)
			if err == nil || req != nil {
				t.Fatalf("unsafe target produced an authenticated request: request=%v error=%v", req, err)
			}
		})
	}
}

func TestPrivateTelemetryBoundaryPreservesPrivateUploadHeaders(t *testing.T) {
	req, err := privateBenchmarkRequest(http.MethodPost,
		"http://10.77.0.1:8787/api/benchmark/upload", "fixture-node-token", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer req.Body.Close()
	for name, want := range map[string]string{
		"Authorization":   "Bearer fixture-node-token",
		"Accept-Encoding": "identity",
		"Cache-Control":   "no-store",
		"Content-Type":    "application/octet-stream",
	} {
		if got := req.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestPrivateTelemetryBoundaryIgnoresAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client := newPrivateTelemetryHTTPClient(2 * time.Second)
	defer client.CloseIdleConnections()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected private telemetry transport: %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("private node telemetry may be redirected through an ambient environment proxy")
	}
	if !transport.DisableCompression {
		t.Fatal("private throughput measurement enabled transparent compression")
	}
	if client.Timeout != 2*time.Second || client.CheckRedirect == nil {
		t.Fatal("private telemetry lost its bounded timeout or redirect policy")
	}
}

func TestPrivateTelemetryBoundaryDoesNotForwardTokenAcrossRedirect(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-node-token" {
			t.Error("original benchmark request lost its private node credential")
		}
		http.Redirect(w, r, "http://10.77.0.1:9999/other-service", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := newPrivateTelemetryHTTPClient(time.Second)
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "10.77.0.1:8787" {
			t.Errorf("request escaped the selected private benchmark endpoint: %s", address)
		}
		// All sockets remain local to the test; no VPN or household service is used.
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	req, err := privateBenchmarkRequest(http.MethodGet,
		"http://10.77.0.1:8787/api/benchmark/download?bytes=1", "fixture-node-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("authenticated private benchmark followed a redirect")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("node credential was forwarded in a redirected request: got %d requests", got)
	}
}
