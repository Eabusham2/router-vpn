package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestPrivateLatencyRejectsHTTPWithoutNodeIdentity(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	p := common.RouterProfile{ID: "latency-home", NodeKind: "router-vpn", APIToken: "fixture-token"}
	p.NodeProofID = writeTestWGIdentity(t, root, p.ID)
	for name, body := range map[string]string{
		"empty":            "",
		"generic-health":   `{"ok":true}`,
		"wrong-node":       fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":%q}`, strings.Repeat("0", 64), desktopNodeProofKind),
		"wrong-proof-kind": fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":"other"}`, p.NodeProofID),
		"failed-proof":     fmt.Sprintf(`{"ok":false,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind),
		"malformed":        "not json",
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("node token missing")
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			profile := p
			profile.RouterAPI = server.URL
			got, err := privatePathLatency(profile, state{Connected: true, Mode: "wg", RouterID: p.ID}, 1)
			if err == nil || got.Connected || got.Samples != 0 {
				t.Fatalf("unproved HTTP response was accepted as selected-node RTT: result=%+v error=%v", got, err)
			}
		})
	}
}

func TestPrivateLatencyEverySampleProvesSameNode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	p := common.RouterProfile{ID: "latency-home", NodeKind: "router-vpn", APIToken: "fixture-token"}
	p.NodeProofID = writeTestWGIdentity(t, root, p.ID)
	good := fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
	var calls atomic.Int32
	var switchNode atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if switchNode.Load() && n > 1 {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		_, _ = w.Write([]byte(good))
	}))
	defer server.Close()
	p.RouterAPI = server.URL
	st := state{Connected: true, Mode: "wg", RouterID: p.ID}
	got, err := privatePathLatency(p, st, 2)
	if err != nil || got.Samples != 2 || got.Failed != 0 || !got.Connected || got.RouterID != p.ID {
		t.Fatalf("valid paired-node RTT was rejected: result=%+v error=%v", got, err)
	}
	calls.Store(0)
	switchNode.Store(true)
	got, err = privatePathLatency(p, st, 2)
	if err == nil || got.Samples != 0 || got.Connected {
		t.Fatalf("mixed-node RTT was accepted: result=%+v error=%v", got, err)
	}
}

func TestPrivateLatencyMissingIdentityDoesNotSendToken(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	p := common.RouterProfile{ID: "unpaired", RouterAPI: server.URL, APIToken: "fixture-token"}
	if _, err := privatePathLatency(p, state{Connected: true, RouterID: p.ID}, 1); err == nil {
		t.Fatal("unpaired node accepted by private RTT measurement")
	}
	if calls.Load() != 0 {
		t.Fatal("node token was sent before paired identity could be verified")
	}
}

func TestPrivateLatencyPreCancelledRequestNeverConnects(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := common.RouterProfile{ID: "unpaired", RouterAPI: server.URL, APIToken: "fixture-token"}
	got, err := privatePathLatencyContext(ctx, p, state{Connected: true}, 2)
	if !errors.Is(err, context.Canceled) || got.Connected || got.Samples != 0 || calls.Load() != 0 {
		t.Fatalf("cancelled request did work or reported a measurement: %+v, %v, calls=%d", got, err, calls.Load())
	}
}

func TestPrivateLatencyCancellationClosesBlockedResponse(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	p := common.RouterProfile{ID: "latency-home", NodeKind: "router-vpn", APIToken: "fixture-token"}
	p.NodeProofID = writeTestWGIdentity(t, root, p.ID)
	bodyStarted, serverCancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("{"))
		w.(http.Flusher).Flush()
		close(bodyStarted)
		select {
		case <-r.Context().Done():
			close(serverCancelled)
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	p.RouterAPI = server.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		value connectionLatencyResult
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		value, err := privatePathLatencyContext(ctx, p, state{Connected: true, RouterID: p.ID}, 2)
		done <- outcome{value, err}
	}()
	select {
	case <-bodyStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("latency request did not reach the test server")
	}
	cancel()
	select {
	case result := <-done:
		if !errors.Is(result.err, context.Canceled) || result.value.Connected || result.value.Samples != 0 {
			t.Fatalf("cancellation was converted into latency success: %+v, %v", result.value, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled latency reader did not stop promptly")
	}
	select {
	case <-serverCancelled:
	case <-time.After(time.Second):
		t.Fatal("cancelled latency request left its HTTP connection active")
	}
}

func TestPrivateLatencyProofBodyLimitAndHTTPStatus(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	p := common.RouterProfile{ID: "latency-home", NodeKind: "router-vpn", APIToken: "fixture-token"}
	p.NodeProofID = writeTestWGIdentity(t, root, p.ID)
	proof := fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
	for _, tc := range []struct {
		name string
		body string
		code int
		want bool
	}{
		{"exact-limit", proof + strings.Repeat(" ", (16<<10)-len(proof)), 200, true},
		{"over-limit", proof + strings.Repeat(" ", (16<<10)+1-len(proof)), 200, false},
		{"error-with-valid-proof", proof, 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("latency request permits caching or compression")
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			profile := p
			profile.RouterAPI = server.URL
			got, err := privatePathLatency(profile, state{Connected: true, RouterID: p.ID}, 1)
			if (err == nil) != tc.want || got.Connected != tc.want {
				t.Fatalf("proof boundary: result=%+v error=%v wantSuccess=%t", got, err, tc.want)
			}
		})
	}
}

func TestPrivateLatencyExternalProfileCannotUseNodeToken(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	p := common.RouterProfile{ID: "external-node", NodeKind: "external", RouterAPI: server.URL, APIToken: "fixture-token"}
	got, err := privatePathLatencyContext(context.Background(), p, state{Connected: true}, 1)
	if err == nil || got.Connected || calls.Load() != 0 {
		t.Fatalf("external profile inherited private-node telemetry: %+v %v calls=%d", got, err, calls.Load())
	}
}
