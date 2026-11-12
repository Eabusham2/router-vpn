package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func nodeChainExecutionStopTestFixture(t *testing.T, reply func(http.ResponseWriter, NodeChainExecutionStopCapture) bool) (*ownedNodeChainExecutionStop, *nodeChainExecutionDiscoveryTestEngine, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	_, policy, projection := nodeChainExecutionProjectionFixture(t)
	request, err := policy.NewAttempt(startJSON(t, nodeChainExecutionDiscoveryFixture(policy, time.Now())))
	if err != nil {
		t.Fatal(err)
	}
	identity := NodeChainIdentity{EngineID: "original-box", SessionID: "original-session", NetworkID: "original-network", SourceSHA256: projection.SourceSHA256(), ConfigSHA256: projection.ConfigSHA256()}
	capture, err := projection.stopCapture(request, identity)
	if err != nil {
		t.Fatal(err)
	}
	var requests, discards atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Method != "DELETE" || r.URL.Path != nodeChainExecutionLeasePath || r.URL.RawQuery != "" || r.Host != capture.address || r.Header.Get("Authorization") != "Bearer "+capture.token || string(body) != capture.body || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("stop changed its fixed original operation", err)
			http.Error(w, "bad", 400)
			return
		}
		if reply != nil && reply(w, capture) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"node_id": capture.node, "session_id": capture.session, "stopped": true})
	}))
	t.Cleanup(server.Close)
	engine := &nodeChainExecutionDiscoveryTestEngine{identity: identity, tag: capture.entryTag, address: capture.address, local: server.Listener.Addr().String()}
	stop, err := NewOwnedNodeChainExecutionStop(capture, func(ctx context.Context) (net.Conn, error) {
		return engine.Dial(ctx, capture.entryTag, capture.address)
	}, func(ctx context.Context) error { return ctx.Err() }, func() { discards.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	owner := stop.(*ownedNodeChainExecutionStop)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = owner.io.close(ctx)
	})
	return owner, engine, &requests, &discards
}

func TestNodeChainExecutionStopRetainsExactPreAcquisitionRequest(t *testing.T) {
	s, e, requests, discards := nodeChainExecutionStopTestFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal("joined exact receipt was lost", err)
	}
	if requests.Load() != 1 || e.dials.Load() != 1 || e.closes.Load() != 1 || discards.Load() != 0 {
		t.Fatal("positive ACK did not join exactly one owned control stream")
	}
	s.Discard()
	s.Discard()
	if discards.Load() != 1 {
		t.Fatal("original native stop capability not released exactly once")
	}
	if err := s.Stop(ctx); err == nil {
		t.Fatal("discarded stop capability reopened")
	}
	if requests.Load() != 1 {
		t.Fatal("joined/discarded cleanup recreated a socket")
	}
}

func TestNodeChainExecutionStopRejectsChangedRequestOrNativeCapture(t *testing.T) {
	_, policy, projection := nodeChainExecutionProjectionFixture(t)
	request, err := policy.NewAttempt(startJSON(t, nodeChainExecutionDiscoveryFixture(policy, time.Now())))
	if err != nil {
		t.Fatal(err)
	}
	identity := NodeChainIdentity{"engine", "session", "network", projection.SourceSHA256(), projection.ConfigSHA256()}
	capture, err := projection.stopCapture(request, identity)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*multihoprelay.NodeChainRequest){
		"port":        func(q *multihoprelay.NodeChainRequest) { q.Port++ },
		"credential":  func(q *multihoprelay.NodeChainRequest) { q.Users[0].Password = strings.Repeat("a", 48) },
		"username":    func(q *multihoprelay.NodeChainRequest) { q.Users[0].Username = strings.Repeat("a", 48) },
		"peer":        func(q *multihoprelay.NodeChainRequest) { q.Peer = "10.80.0.3" },
		"dns":         func(q *multihoprelay.NodeChainRequest) { q.DNSPolicySHA256 = strings.Repeat("a", 64) },
		"source":      func(q *multihoprelay.NodeChainRequest) { q.SourceSHA256 = strings.Repeat("a", 64) },
		"missing-key": func(q *multihoprelay.NodeChainRequest) { q.LocalPacketPublicKeys = q.LocalPacketPublicKeys[1:] },
	} {
		t.Run(name, func(t *testing.T) {
			q := request.Clone()
			mutate(&q)
			if _, err := projection.stopCapture(q, identity); err == nil {
				t.Fatal("changed acquisition sealed cleanup authority")
			}
		})
	}
	for name, mutate := range map[string]func(*NodeChainIdentity){"source": func(i *NodeChainIdentity) { i.SourceSHA256 = policy.local.SourceSHA256() }, "unprojected": func(i *NodeChainIdentity) { i.ConfigSHA256 = policy.ConfigSHA256() }, "missing-engine": func(i *NodeChainIdentity) { i.EngineID = "" }, "missing-network": func(i *NodeChainIdentity) { i.NetworkID = "" }} {
		t.Run(name, func(t *testing.T) {
			i := identity
			mutate(&i)
			if _, err := projection.stopCapture(request, i); err == nil {
				t.Fatal("foreign native identity sealed cleanup authority")
			}
		})
	}
	var decoded multihoprelay.NodeChainRequest
	if json.Unmarshal([]byte(capture.body), &decoded) != nil || !reflect.DeepEqual(decoded, request) || capture.Identity() != identity {
		t.Fatal("sealed DELETE lost full original acquisition")
	}
	request.Users[0].Password = "changed"
	if strings.Contains(capture.body, "changed") {
		t.Fatal("stop capture aliases mutable request")
	}
	if _, err := NewOwnedNodeChainExecutionStop(NodeChainExecutionStopCapture{}, func(context.Context) (net.Conn, error) { return nil, nil }, func(context.Context) error { return nil }, func() {}); err == nil {
		t.Fatal("zero/unproved capture gained deletion capability")
	}
}

func TestNodeChainExecutionStopWithholdsDiscardUntilExactJoinedAcknowledgement(t *testing.T) {
	for _, fault := range []string{"node", "session", "not-stopped", "extra", "status", "encoding", "truncated"} {
		t.Run(fault, func(t *testing.T) {
			var fixed atomic.Bool
			s, _, requests, discards := nodeChainExecutionStopTestFixture(t, func(w http.ResponseWriter, c NodeChainExecutionStopCapture) bool {
				if fixed.Load() {
					return false
				}
				receipt := map[string]any{"node_id": c.node, "session_id": c.session, "stopped": true}
				switch fault {
				case "node":
					receipt["node_id"] = strings.Repeat("a", 64)
				case "session":
					receipt["session_id"] = strings.Repeat("a", 32)
				case "not-stopped":
					receipt["stopped"] = false
				case "extra":
					receipt["new_owner"] = true
				case "status":
					w.WriteHeader(409)
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "truncated":
					w.Header().Set("Content-Length", "999")
				}
				_ = json.NewEncoder(w).Encode(receipt)
				return true
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := s.Stop(ctx); err == nil {
				t.Fatal("unproved cleanup accepted")
			}
			s.Discard()
			if discards.Load() != 0 {
				t.Fatal("failed cleanup dropped original native entry authority")
			}
			fixed.Store(true)
			if err := s.Stop(ctx); err != nil {
				t.Fatal("exact failed cleanup could not retry", err)
			}
			s.Discard()
			if discards.Load() != 1 || requests.Load() != 2 {
				t.Fatal("retry substituted or abandoned captured request")
			}
		})
	}
}

func TestNodeChainExecutionStopRetainsLateDialAndCloseAcrossCallerTimeout(t *testing.T) {
	for _, stage := range []string{"dial", "close"} {
		t.Run(stage, func(t *testing.T) {
			s, e, _, discards := nodeChainExecutionStopTestFixture(t, nil)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			pause := func() { once.Do(func() { close(entered); <-release }) }
			if stage == "dial" {
				e.dialBefore = func(context.Context) { pause() }
			} else {
				e.closeBefore = func(int32) error { pause(); return nil }
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- s.Stop(ctx) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("fixed cleanup did not enter original operation")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled cleanup acknowledged")
				}
			case <-time.After(time.Second):
				t.Fatal("cleanup caller exceeded cancellation")
			}
			s.Discard()
			if discards.Load() != 0 {
				t.Fatal("late cleanup owner discarded")
			}
			short, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
			if err := s.Stop(short); err == nil {
				t.Fatal("new DELETE replaced unjoined original")
			}
			stop()
			close(release)
			joined, finish := context.WithTimeout(context.Background(), 2*time.Second)
			defer finish()
			if err := s.Stop(joined); err != nil {
				t.Fatal("same captured DELETE could not recover after original join", err)
			}
			s.Discard()
			if e.dials.Load() != e.closes.Load() || discards.Load() != 1 {
				t.Fatal("late original stream escaped joined cleanup", e.dials.Load(), e.closes.Load())
			}
		})
	}
}

func TestNodeChainExecutionStopFailedOriginalCloseDoesNotAcknowledge(t *testing.T) {
	s, e, _, discards := nodeChainExecutionStopTestFixture(t, nil)
	var allowed atomic.Bool
	e.closeBefore = func(int32) error {
		if !allowed.Load() {
			return errors.New("original close refused")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err == nil {
		t.Fatal("valid remote ACK substituted for original stream join")
	}
	s.Discard()
	if discards.Load() != 0 {
		t.Fatal("failed original close lost native cleanup authority")
	}
	allowed.Store(true)
	if err := s.Stop(ctx); err != nil {
		t.Fatal("failed original close not retryable", err)
	}
	s.Discard()
	if e.dials.Load() != e.closes.Load() || discards.Load() != 1 {
		t.Fatal("cleanup retired foreign/unfinished resources")
	}
}
