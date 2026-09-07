package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestQuickProfileLatencyContextRejectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err := quickProfileLatencyContext(ctx, common.RouterProfile{ID: "node-a", Endpoint: "127.0.0.1"}, 5)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled quick latency = %v, want context.Canceled", err)
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("cancelled quick latency kept probing ports")
	}
}

func TestFastestProfileCancelledRequestCannotSelectWinner(t *testing.T) {
	a := &app{
		profiles: common.RouterProfileStore{SelectedID: "node-a", Profiles: []common.RouterProfile{
			{ID: "node-a", Name: "A", NodeKind: "router-vpn", Endpoint: "127.0.0.1"},
			{ID: "node-b", Name: "B", NodeKind: "router-vpn", Endpoint: "127.0.0.1"},
		}},
		state: state{RouterID: "node-a"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{"samples":5}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	a.fastestProfile(w, req)
	if w.Code != http.StatusRequestTimeout {
		t.Fatalf("cancelled fastest = HTTP %d %q", w.Code, w.Body.String())
	}
	if a.profiles.SelectedID != "node-a" || a.state.RouterID != "node-a" {
		t.Fatalf("cancelled fastest changed selection: selected=%q router=%q", a.profiles.SelectedID, a.state.RouterID)
	}
}

func TestMultihopLiveLatencyCancelledRequestStopsBeforeProbes(t *testing.T) {
	a := &app{profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{
		{ID: "entry", Name: "Entry", NodeKind: "router-vpn", Endpoint: "127.0.0.1"},
		{ID: "exit", Name: "Exit", NodeKind: "router-vpn", Endpoint: "127.0.0.1"},
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/multihop/live-latency", strings.NewReader(`{"entry_id":"entry","exit_id":"exit","samples":5}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	started := time.Now()
	a.multihopLiveLatency(w, req)
	if w.Code != http.StatusRequestTimeout || !strings.Contains(w.Body.String(), "cancelled") {
		t.Fatalf("cancelled multihop latency = HTTP %d %q", w.Code, w.Body.String())
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("cancelled multihop latency kept probing nodes")
	}
}

func TestClampSpeedBytes(t *testing.T) {
	cases := []struct {
		in, want int64
	}{
		{0, 8 << 20},
		{1, 1 << 20},
		{(1 << 20) - 1, 1 << 20},
		{1 << 20, 1 << 20},
		{8 << 20, 8 << 20},
		{16 << 20, 16 << 20},
		{32 << 20, 16 << 20},
	}
	for _, tc := range cases {
		if got := clampSpeedBytes(tc.in); got != tc.want {
			t.Fatalf("clampSpeedBytes(%d)=%d want %d", tc.in, got, tc.want)
		}
	}
}

func TestClampLiveSamples(t *testing.T) {
	cases := []struct{ in, fallback, want int }{
		{0, 3, 3},
		{-1, 5, 5},
		{1, 3, 1},
		{10, 3, 10},
		{11, 3, 10},
	}
	for _, tc := range cases {
		if got := clampLiveSamples(tc.in, tc.fallback); got != tc.want {
			t.Fatalf("clampLiveSamples(%d,%d)=%d want %d", tc.in, tc.fallback, got, tc.want)
		}
	}
}

func TestPrivateBenchmarkRequestHeaders(t *testing.T) {
	payload := bytes.NewReader([]byte("payload"))
	req, err := privateBenchmarkRequest(http.MethodPost, "http://10.77.0.1:8787/api/benchmark/upload", "secret-token", payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer secret-token" {
		t.Fatalf("authorization=%q", got)
	}
	if got := req.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control=%q", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("content-type=%q", got)
	}

	getReq, err := privateBenchmarkRequest(http.MethodGet, "http://10.77.0.1:8787/api/benchmark/download", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := getReq.Header.Get("Authorization"); got != "" {
		t.Fatalf("unexpected authorization=%q", got)
	}
	if got := getReq.Header.Get("Content-Type"); got != "" {
		t.Fatalf("unexpected content-type=%q", got)
	}
}

func TestFastestProfileSnapshotTokenTracksSelectionInputs(t *testing.T) {
	base := []common.RouterProfile{{ID: "a", NodeKind: "router-vpn", Endpoint: "home.example:51820", RouterAPI: "http://10.0.0.1", NodeProofID: "proof-a"}}
	token := fastestProfileSnapshotToken(base)
	if token == "" {
		t.Fatal("empty fastest profile snapshot token")
	}
	mutations := []common.RouterProfile{
		{ID: "b", NodeKind: "router-vpn", Endpoint: "home.example:51820", RouterAPI: "http://10.0.0.1", NodeProofID: "proof-a"},
		{ID: "a", NodeKind: "external", Endpoint: "home.example:51820", RouterAPI: "http://10.0.0.1", NodeProofID: "proof-a"},
		{ID: "a", NodeKind: "router-vpn", Endpoint: "other.example:51820", RouterAPI: "http://10.0.0.1", NodeProofID: "proof-a"},
		{ID: "a", NodeKind: "router-vpn", Endpoint: "home.example:51820", RouterAPI: "http://10.0.0.2", NodeProofID: "proof-a"},
		{ID: "a", NodeKind: "router-vpn", Endpoint: "home.example:51820", RouterAPI: "http://10.0.0.1", NodeProofID: "proof-b"},
	}
	for _, changed := range mutations {
		if got := fastestProfileSnapshotToken([]common.RouterProfile{changed}); got == token {
			t.Fatalf("snapshot token did not change for mutation: %+v", changed)
		}
	}
}
