package mobiletor

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func serverPaddingClientFixture(t *testing.T, enabled bool) *serverTorClientFixture {
	t.Helper()
	f := newServerTorClientFixture(t)
	source := serverTorSource("tor-bridge")
	source["padding"] = map[string]any{"enabled": enabled, "rate_kbps": 192}
	policy := serverTorPolicy(t, source)
	f.mu.Lock()
	f.policy, f.client.policy = policy, policy
	f.mu.Unlock()
	return f
}

func serverPaddingClientReceipt(object map[string]any, cells uint64, lifetime time.Duration) map[string]any {
	now := time.Now()
	padding := map[string]any{"direction": "outgoing", "accounting": "tor-link-cell", "generation": 1, "rate_kbps": 192,
		"channel_cells": cells, "channel_cell_bytes": cells * 514, "observed_at": now.UnixMilli(), "expires_at": now.Add(lifetime).UnixMilli()}
	receipt := object["receipt"].(map[string]any)
	receipt["heartbeat_at"], receipt["proof_at"], receipt["padding"] = now.UnixMilli(), now.UnixMilli(), padding
	return padding
}

func TestServerTorClientRequiresRequestedNativePaddingReceiptAndMonotonicCounters(t *testing.T) {
	for _, scenario := range []string{"valid", "missing", "wrong-rate", "wrong-generation", "rollback", "same-count-other-bytes", "impossible-byte-delta", "stale", "off-unrequested"} {
		t.Run(scenario, func(t *testing.T) {
			f := serverPaddingClientFixture(t, scenario != "off-unrequested")
			f.mu.Lock()
			f.mutate = func(method string, object map[string]any) {
				if method == http.MethodPost {
					serverPaddingClientReceipt(object, 10, 4*time.Second)
				}
			}
			f.mu.Unlock()
			if err := f.client.Acquire(t.Context()); err != nil {
				t.Fatal(err)
			}
			if scenario == "off-unrequested" {
				if _, err := f.client.Status(t.Context()); err == nil || f.client.Ready() {
					t.Fatal("Off silently accepted unrequested server cover", err)
				}
				return
			}
			first, err := f.client.Status(t.Context())
			if err != nil || first.Padding == nil || first.Padding.ChannelCells != 10 || !f.client.Ready() {
				t.Fatal("actual authenticated API did not retain captured channel proof", err)
			}
			f.mu.Lock()
			f.mutate = func(method string, object map[string]any) {
				if method != http.MethodPost {
					return
				}
				p := serverPaddingClientReceipt(object, 20, 4*time.Second)
				switch scenario {
				case "missing":
					delete(object["receipt"].(map[string]any), "padding")
				case "wrong-rate":
					p["rate_kbps"] = 64
				case "wrong-generation":
					p["generation"] = 2
				case "rollback":
					p["channel_cells"], p["channel_cell_bytes"] = 5, 5*514
				case "same-count-other-bytes":
					p["channel_cells"], p["channel_cell_bytes"] = 10, 10*512
				case "impossible-byte-delta":
					p["channel_cells"], p["channel_cell_bytes"] = 20, 20*512
				case "stale":
					p["observed_at"] = time.Now().Add(-6 * time.Second).UnixMilli()
				}
			}
			f.mu.Unlock()
			second, err := f.client.Status(t.Context())
			if scenario == "valid" {
				if err != nil || second.Padding == nil || second.Padding.ChannelCells != 20 || !f.client.Ready() {
					t.Fatal("valid fresh native counter growth failed", err)
				}
			} else if err == nil || f.client.Ready() || f.client.ctx.Err() == nil || strings.Contains(err.Error(), "private-captured-token") {
				t.Fatal("invalid server cover retained data authority or exposed credentials", err)
			}
		})
	}
}

func TestServerTorPaddingExpiryClosesExistingDataWithoutAnotherStatusCall(t *testing.T) {
	f := serverPaddingClientFixture(t, true)
	f.mu.Lock()
	f.mutate = func(method string, object map[string]any) {
		if method == http.MethodPost {
			serverPaddingClientReceipt(object, 10, 500*time.Millisecond)
		}
	}
	f.mu.Unlock()
	if err := f.client.Acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Status(t.Context()); err != nil {
		t.Fatal(err)
	}
	connection, err := f.client.DialContext(t.Context(), "tcp", "service.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case <-f.client.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("expired native cover left an existing data owner running")
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil || f.client.Ready() {
		t.Fatal("expired cover left an owned application socket usable", err)
	}
}

func TestServerTorPaddingOldExpiryCannotCancelFreshReceipt(t *testing.T) {
	policy, err := serverPaddingSource(t, map[string]any{"enabled": true, "rate_kbps": 192}, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	old := &multihoprelay.TorPaddingReceipt{Generation: 1, RateKbps: 192, ChannelCells: 1, ChannelBytes: 514, ObservedAt: time.Now().Add(-6 * time.Second).UnixMilli(), ExpiresAt: time.Now().Add(-time.Second).UnixMilli()}
	client := &ServerTorClient{ctx: ctx, cancel: cancel, policy: policy, padding: old}
	client.mu.Lock()
	entered, done := make(chan struct{}), make(chan struct{})
	go func() { close(entered); client.expirePadding(old); close(done) }()
	<-entered
	current := &multihoprelay.TorPaddingReceipt{Generation: 1, RateKbps: 192, ChannelCells: 2, ChannelBytes: 1028, ObservedAt: time.Now().UnixMilli(), ExpiresAt: time.Now().Add(3 * time.Second).UnixMilli()}
	if !client.adoptPaddingLocked(multihoprelay.TorReceipt{Phase: multihoprelay.TorReady, Padding: current}) {
		client.mu.Unlock()
		t.Fatal("fresh receipt failed adoption")
	}
	client.mu.Unlock()
	<-done
	if ctx.Err() != nil {
		t.Fatal("obsolete timer canceled the refreshed exact client")
	}
	client.mu.Lock()
	client.paddingExpiry.Stop()
	client.mu.Unlock()
}
