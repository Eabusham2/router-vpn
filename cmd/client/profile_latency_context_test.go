package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestProfileLatencyCancelledRequestCannotProbeOrPersist(t *testing.T) {
	a := &app{profiles: common.RouterProfileStore{SelectedID: "node-a", Profiles: []common.RouterProfile{{
		ID: "node-a", Name: "A", NodeKind: "router-vpn", Endpoint: "127.0.0.1",
		LatencySamples: 50, LatencyMedianMs: 99,
	}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/profile/latency", strings.NewReader(`{"id":"node-a","samples":200}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	started := time.Now()
	a.profileLatency(w, req)
	if w.Code != http.StatusRequestTimeout || !strings.Contains(w.Body.String(), "cancelled") {
		t.Fatalf("cancelled durable latency = HTTP %d %q", w.Code, w.Body.String())
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("cancelled durable latency kept probing ports")
	}
	got := a.profiles.Profiles[0]
	if got.LatencySamples != 50 || got.LatencyMedianMs != 99 {
		t.Fatalf("cancelled durable latency changed persisted fields: samples=%d median=%v", got.LatencySamples, got.LatencyMedianMs)
	}
}
