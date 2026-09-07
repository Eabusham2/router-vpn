package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestSpeedLabPathContextRejectsInvalidPreflight(t *testing.T) {
	stale := errors.New("session changed before first request")
	ctx, stop, err := speedLabPathContext(context.Background(), func() error { return stale })
	if !errors.Is(err, stale) || ctx != nil || stop != nil {
		t.Fatalf("stale preflight returned a usable measurement context: %v", err)
	}
	if _, _, err := speedLabPathContext(context.Background(), nil); err == nil {
		t.Fatal("measurement was allowed without path validation")
	}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, _, err = speedLabPathContext(parent, func() error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancelled request started validation: called=%t err=%v", called, err)
	}
}

func TestSpeedLabPathContextCancelsOnlyMeasurementOnPathChange(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	stale := errors.New("running graph changed")
	var changed atomic.Bool
	ctx, stop, err := speedLabPathContext(parent, func() error {
		if changed.Load() {
			return stale
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	changed.Store(true)
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight measurement was not cancelled after its path changed")
	}
	if err := speedLabPathResultError(ctx, context.Canceled); !errors.Is(err, stale) || !errors.Is(err, context.Canceled) {
		t.Fatalf("lost measurement cancellation or the real stale-path reason: %v", err)
	}
	if parent.Err() != nil {
		t.Fatal("measurement path observer cancelled its caller/VPN owner")
	}
}

func TestSpeedLabPathContextStopsBeforeTemporaryCleanup(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	releaseValidation := make(chan struct{})
	ctx, stop, err := speedLabPathContext(context.Background(), func() error {
		if calls.Add(1) > 1 {
			entered <- struct{}{}
			<-releaseValidation
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(releaseValidation)
		t.Fatal("observer never validated its owned path")
	}
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	// Cancellation has occurred, but stop must still wait for the old callback.
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		close(releaseValidation)
		t.Fatal("observer stop did not cancel its request context")
	}
	select {
	case <-stopped:
		close(releaseValidation)
		t.Fatal("temporary cleanup could run while its old validator was still active")
	default:
	}
	close(releaseValidation)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not join after validation finished")
	}
	stop() // Idempotent deferred cleanup is safe after explicit teardown ordering.
	if calls.Load() != 2 {
		t.Fatalf("observer made unexpected post-stop calls: %d", calls.Load())
	}
}

// Exercise the real current-config pipeline with a stalled loopback HTTP server,
// not just a source marker or a fake measurement implementation. Only the test
// transport dial is redirected; production's fixed provider URL is unchanged.
func TestSpeedLabCurrentCancelsStalledProbeWhenVPNStops(t *testing.T) {
	a := &app{
		state: state{Connected: true, Phase: "connected", Mode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: "node-a"},
		profiles: common.RouterProfileStore{SelectedID: "node-a", Profiles: []common.RouterProfile{{ID: "node-a", NodeKind: "router-vpn"}}},
	}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "test-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: "node-a"}}
	sessionTrackers.Store(a, tracker)
	defer sessionTrackers.Delete(a)

	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	oldTransport := http.DefaultTransport
	transport := oldTransport.(*http.Transport).Clone()
	// HTTPS connections normally arrive TLS-ready from DialTLSContext. The
	// isolated test sends HTTP directly to our loopback handler instead; no
	// public server, VPN, certificate setting, or real interface is changed.
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "speed.cloudflare.com:443" {
			return nil, errors.New("unexpected speed provider address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = oldTransport; transport.CloseIdleConnections() }()
	parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil).WithContext(parent)
	done := make(chan error, 1)
	go func() {
		_, _, _, err := a.speedLabCurrent(req, speedLabDuration{Mode: "auto"}, time.Second, time.Second)
		done <- err
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("current-path probe did not start: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("current-path probe never reached its fixed provider")
	}
	a.mu.Lock()
	a.state.Connected = false
	a.state.Phase = "stopping"
	a.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("path loss did not cancel the in-flight request: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("current-config traffic kept running after the VPN entered stopping")
	}
	if parent.Err() != nil {
		t.Fatal("measurement cleanup cancelled the independent request owner")
	}
}
