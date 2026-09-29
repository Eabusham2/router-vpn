package mobileperf

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCoverEngine struct {
	identity atomic.Int32
	server   *httptest.Server
	mu       sync.Mutex
	lengths  []int
	badUDP   bool
	mute     atomic.Bool
	dialUDP  int
}

func (e *fakeCoverEngine) Identity() string {
	if e.identity.Load() != 1 {
		return ""
	}
	return "captured-runtime"
}
func (e *fakeCoverEngine) Dial(ctx context.Context, network, tag, address string) (net.Conn, error) {
	if e.Identity() == "" || tag != "proxy" {
		return nil, errors.New("unowned engine")
	}
	if network == "tcp" {
		if address != "10.77.0.1:8787" {
			return nil, errors.New("unowned proof address")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(e.server.URL, "http://"))
	}
	if network != "udp" || address != "10.77.0.1:45999" {
		return nil, errors.New("unowned cover address")
	}
	e.mu.Lock()
	e.dialUDP++
	e.mu.Unlock()
	if e.badUDP {
		return nil, errors.New("unavailable sink")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		packet := make([]byte, 1201)
		for {
			n, err := server.Read(packet)
			if err != nil {
				return
			}
			e.mu.Lock()
			e.lengths = append(e.lengths, n)
			e.mu.Unlock()
			if e.mute.Load() {
				continue
			}
			if _, err = server.Write(packet[:n]); err != nil {
				return
			}
		}
	}()
	return client, nil
}
func fixtureCover(t *testing.T, handler http.HandlerFunc) (*Cover, *fakeCoverEngine) {
	t.Helper()
	engine := &fakeCoverEngine{}
	engine.identity.Store(1)
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" || r.Header.Get("Authorization") != "" {
				t.Error("unowned proof request")
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": strings.Repeat("a", 64), "proof": "router-vpn-private-agent-v1"})
		}
	}
	engine.server = httptest.NewServer(handler)
	t.Cleanup(engine.server.Close)
	options := CoverOptions{NodeID: strings.Repeat("a", 64), API: "http://10.77.0.1:8787", Sink: "10.77.0.1", RateKbps: 192, ProofTag: "proxy", PacketTag: "proxy"}
	cover, err := NewCover(engine, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cover.Close() })
	return cover, engine
}
func TestCoverBoundedPayloadAndJoinedTeardown(t *testing.T) {
	cover, engine := fixtureCover(t, nil)
	if err := cover.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !cover.Healthy() {
		t.Fatal("cover activated without confirming UDP")
	}
	time.Sleep(225 * time.Millisecond)
	if err := cover.Close(); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	lengths := append([]int{}, engine.lengths...)
	engine.mu.Unlock()
	if len(lengths) < 3 || len(lengths) > 7 {
		t.Fatal("unbounded or absent cover cadence", lengths)
	}
	for i, n := range lengths {
		if i == 0 && n != 128 || i > 0 && (n < 900 || n > 1200) {
			t.Fatal("cover violated payload bound", n)
		}
	}
	before := cover.StatusJSON()
	time.Sleep(65 * time.Millisecond)
	if cover.StatusJSON() != before || cover.Healthy() {
		t.Fatal("cover survived shutdown")
	}
	if strings.Contains(before, "10.77") || strings.Contains(before, strings.Repeat("a", 64)) {
		t.Fatal("public status exposes private routing metadata")
	}
	if err := cover.Start(context.Background()); err == nil {
		t.Fatal("closed service restarted")
	}
}
func TestCoverRequiresExactPrivateProofAndRealSink(t *testing.T) {
	for _, body := range []string{`{"ok":true}`, `{"ok":true,"node_id":"wrong","proof":"router-vpn-private-agent-v1"}`, `{"ok":true,"ok":false}`, strings.Repeat(" ", 16385)} {
		t.Run(body[:min(len(body), 30)], func(t *testing.T) {
			cover, engine := fixtureCover(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
			if err := cover.Start(context.Background()); err == nil {
				t.Fatal("invalid proof accepted")
			}
			engine.mu.Lock()
			defer engine.mu.Unlock()
			if engine.dialUDP != 0 {
				t.Fatal("cover sent before proof")
			}
		})
	}
	cover, engine := fixtureCover(t, nil)
	engine.badUDP = true
	if err := cover.Start(context.Background()); err == nil || cover.Healthy() {
		t.Fatal("failed sink called active")
	}
}
func TestCoverRedirectCancellationAndPathChanges(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		cover, engine := fixtureCover(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://192.168.1.2/health", 302) })
		if err := cover.Start(context.Background()); err == nil {
			t.Fatal("redirect accepted")
		}
		if engine.dialUDP != 0 {
			t.Fatal("redirect enabled UDP")
		}
	})
	t.Run("cancel-proof", func(t *testing.T) {
		entered := make(chan struct{})
		cover, _ := fixtureCover(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() })
		done := make(chan error, 1)
		go func() { done <- cover.Start(context.Background()) }()
		<-entered
		cover.Invalidate()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("cancelled proof accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("proof cancellation did not join")
		}
	})
	t.Run("path-changed", func(t *testing.T) {
		cover, engine := fixtureCover(t, nil)
		if err := cover.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		engine.identity.Store(2)
		time.Sleep(80 * time.Millisecond)
		cover.Close()
		if cover.Healthy() {
			t.Fatal("stale runtime remained healthy")
		}
		engine.mu.Lock()
		defer engine.mu.Unlock()
		if len(engine.lengths) != 1 {
			t.Fatal("sent to changed path", engine.lengths)
		}
	})
}
func TestCoverRejectsUnboundedAndNonPrivateConfiguration(t *testing.T) {
	good := CoverOptions{NodeID: strings.Repeat("a", 64), API: "http://10.77.0.1:8787", Sink: "10.77.0.1", RateKbps: 192, ProofTag: "proxy", PacketTag: "proxy"}
	for _, host := range []string{"127.0.0.1", "0.0.0.0", "192.0.2.1", "example.com", "fe80::1", "::ffff:10.77.0.1", "fd77::1%en0"} {
		o := good
		o.Sink = host
		if o.Validate() == nil {
			t.Fatal("unsafe cover sink", host)
		}
	}
	for _, rate := range []int{0, 31, 193, 1000000} {
		o := good
		o.RateKbps = rate
		if o.Validate() == nil {
			t.Fatal("unbounded cover rate", rate)
		}
	}
	for _, api := range []string{"http://127.0.0.1:8787", "http://host.test:8787", "http://10.77.0.1", "http://user:secret@10.77.0.1:8787", "http://10.77.0.1:8787/arbitrary", "http://10.77.0.1:8787?token=x"} {
		o := good
		o.API = api
		if o.Validate() == nil {
			t.Fatal("unowned proof", api)
		}
	}

}

func TestCoverCannotRemainActiveWithoutReplies(t *testing.T) {
	cover, engine := fixtureCover(t, nil)
	if err := cover.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine.mute.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for cover.Healthy() && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if cover.Healthy() {
		t.Fatal("cover remained active with a one-way dead UDP path")
	}
	time.Sleep(80 * time.Millisecond)
	cover.Close()
	if !strings.Contains(cover.StatusJSON(), "replies stopped") {
		t.Fatal("dead reply path was not reported", cover.StatusJSON())
	}
}
