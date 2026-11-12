package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nodeChainExecutionDiscoveryTestEngine struct {
	mu                  sync.Mutex
	identity            NodeChainIdentity
	tag, address, local string
	dials, closes       atomic.Int32
	observe             func(context.Context)
	dialBefore          func(context.Context)
	closeBefore         func(int32) error
}

func (e *nodeChainExecutionDiscoveryTestEngine) ObserveChainContext(ctx context.Context) (NodeChainIdentity, error) {
	if e.observe != nil {
		e.observe(ctx)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.identity, ctx.Err()
}
func (e *nodeChainExecutionDiscoveryTestEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if tag != e.tag || address != e.address {
		return nil, errors.New("fixture refuses any uncaptured route/socket")
	}
	if e.dialBefore != nil {
		e.dialBefore(ctx)
	}
	// The single original literal destination is replaced only at this
	// explicit native boundary. Production HTTP/TLS/framing and joins run.
	connection, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", e.local)
	if err != nil {
		return nil, err
	}
	e.dials.Add(1)
	return &nodeChainExecutionDiscoveryTestConn{Conn: connection, engine: e}, nil
}

type nodeChainExecutionDiscoveryTestConn struct {
	net.Conn
	engine *nodeChainExecutionDiscoveryTestEngine
	count  atomic.Int32
}

func (c *nodeChainExecutionDiscoveryTestConn) Close() error {
	n := c.count.Add(1)
	if c.engine.closeBefore != nil {
		if err := c.engine.closeBefore(n); err != nil {
			return err
		}
	}
	err := c.Conn.Close()
	if err == nil {
		c.engine.closes.Add(1)
	}
	return err
}

func nodeChainExecutionDiscoveryTestFixture(t *testing.T, mutate func(*NodeChainExecutionDiscovery), handler func(http.ResponseWriter, *http.Request) bool) (*NodeChainExecutionDiscoveryOwner, *nodeChainExecutionDiscoveryTestEngine, *NodeChainExecutionPolicy, *atomic.Int32) {
	t.Helper()
	source := nodeChainExecutionFixtureSource(t, 3, "", "auto")
	policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewNodeChainExecutionPreparation(source.LocalSource, source.Execution)
	if err != nil {
		t.Fatal(err)
	}
	capture, _ := prep.Discovery()
	discovery := nodeChainExecutionDiscoveryFixture(policy, time.Now())
	if mutate != nil {
		mutate(&discovery)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+capture.Token || r.Host != capture.Address || r.Method != "GET" || r.URL.RawQuery != "" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("request changed original route/authentication/method", r.Method, r.URL)
			http.Error(w, "bad", 400)
			return
		}
		if handler != nil && handler(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": capture.Entry.NodeID, "proof": "router-vpn-private-agent-v1"})
			return
		}
		if r.URL.Path != nodeChainExecutionLeasePath {
			http.Error(w, "bad", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(discovery)
	}))
	t.Cleanup(server.Close)
	engine := &nodeChainExecutionDiscoveryTestEngine{identity: NodeChainIdentity{EngineID: "original-box", SessionID: "original-session", NetworkID: "original-network", SourceSHA256: prep.SourceSHA256(), ConfigSHA256: prep.ConfigSHA256()}, tag: capture.Entry.Tag, address: capture.Address, local: server.Listener.Addr().String()}
	owner, err := NewNodeChainExecutionDiscoveryOwner(prep, engine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := owner.Close(ctx); err != nil {
			t.Error("fixture cleanup", err)
		}
	})
	return owner, engine, policy, &requests
}

func TestNodeChainExecutionDiscoveryOwnsAuthenticatedOriginalEntry(t *testing.T) {
	o, e, expected, requests := nodeChainExecutionDiscoveryTestFixture(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	discovery, err := o.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || e.dials.Load() != 2 || e.closes.Load() != 2 || o.Identity() != e.identity || discovery.FirstPort != 32000 || discovery.LastPort != 32007 {
		t.Fatal("discovery bypassed original private proof or joined source", requests.Load(), e.dials.Load(), e.closes.Load())
	}
	// Detached returned values cannot replace the captured GET or credential.
	discovery.Sources[0].SourceSHA256 = strings.Repeat("a", 64)
	discovery.Challenge.Peer = "10.80.0.3"
	projection, err := o.PlanContext(ctx, "", 32003)
	if err != nil {
		t.Fatal(err)
	}
	p := projection.policy
	if !reflect.DeepEqual(p.Descriptor(), expected.Descriptor()) || p.Front().Host != "10.80.0.1" || p.Front().Port != 32003 || p.Request().Peer != "10.80.0.2" || p.Request().SessionID == expected.Request().SessionID || p.Request().Users[0].Username == expected.Request().Users[0].Username {
		t.Fatal("plan silently replaced source, pool or independent proposal")
	}
	if _, err = o.PlanContext(ctx, "", 32003); err == nil {
		t.Fatal("one successful discovery adopted another graph")
	}
	if _, err = o.Discover(ctx); err == nil {
		t.Fatal("captured discovery replaced in place")
	}
	if err = o.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = o.PlanContext(ctx, "", 32003); err == nil {
		t.Fatal("closed discovery authorized new native adoption")
	}
	if projection.validateCapture() != nil {
		t.Fatal("joining discovery invalidated immutable projected source")
	}
}

func TestNodeChainExecutionDiscoveryRequiresUniqueCompleteSourceChoice(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			o, _, expected, _ := nodeChainExecutionDiscoveryTestFixture(t, func(d *NodeChainExecutionDiscovery) {
				other := d.Sources[0].Clone()
				other.SourceSHA256 = strings.Repeat("a", 64)
				d.Sources = append(d.Sources, other)
				d.Sources[0], d.Sources[1] = d.Sources[1], d.Sources[0]
			}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := o.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			wanted := ""
			if explicit {
				wanted = expected.Descriptor().SourceSHA256
			}
			projection, err := o.PlanContext(ctx, wanted, 32003)
			if !explicit {
				if err == nil {
					t.Fatal("first catalog item silently won an ambiguous complete path")
				}
				return
			}
			if err != nil || projection.policy.Descriptor().SourceSHA256 != wanted {
				t.Fatal("explicit captured source ignored", err)
			}
		})
	}
	// An unrelated first registry entry is not an ambiguous matching source.
	o, _, expected, _ := nodeChainExecutionDiscoveryTestFixture(t, func(d *NodeChainExecutionDiscovery) {
		other := d.Sources[0].Clone()
		other.SourceSHA256 = strings.Repeat("a", 64)
		other.Members[0].ProfileID = "unrelated"
		d.Sources = append(d.Sources, other)
		d.Sources[0], d.Sources[1] = d.Sources[1], d.Sources[0]
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := o.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	projection, err := o.PlanContext(ctx, "", 32003)
	if err != nil || projection.policy.Descriptor().SourceSHA256 != expected.Descriptor().SourceSHA256 {
		t.Fatal("complete original identity matching failed", err)
	}
}

func TestNodeChainExecutionDiscoveryRejectsChangedAuthorityAndFraming(t *testing.T) {
	for name, mutate := range map[string]func(*NodeChainExecutionDiscovery){
		"expired":        func(d *NodeChainExecutionDiscovery) { d.Challenge.ExpiresAt = time.Now().Unix() },
		"extended":       func(d *NodeChainExecutionDiscovery) { d.Challenge.ExpiresAt = time.Now().Add(2 * time.Minute).Unix() },
		"entry":          func(d *NodeChainExecutionDiscovery) { d.NodeID = strings.Repeat("a", 64) },
		"empty":          func(d *NodeChainExecutionDiscovery) { d.Sources = nil },
		"duplicate":      func(d *NodeChainExecutionDiscovery) { d.Sources = append(d.Sources, d.Sources[0].Clone()) },
		"unbounded-pool": func(d *NodeChainExecutionDiscovery) { d.LastPort = d.FirstPort + 64 },
		"invalid-member": func(d *NodeChainExecutionDiscovery) { d.Sources[0].Members[0].Mode = "direct" },
	} {
		t.Run(name, func(t *testing.T) {
			o, _, _, _ := nodeChainExecutionDiscoveryTestFixture(t, mutate, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := o.Discover(ctx); err == nil {
				t.Fatal("invalid authenticated metadata adopted")
			}
			if o.raw != "" {
				t.Fatal("failed discovery persisted a source")
			}
		})
	}
	for _, fault := range []string{"wrong-proof", "wrong-node", "redirect", "oversized", "encoding", "unknown", "duplicate", "truncated"} {
		t.Run(fault, func(t *testing.T) {
			o, _, _, _ := nodeChainExecutionDiscoveryTestFixture(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
				if fault == "wrong-proof" && r.URL.Path == "/health" {
					_, _ = w.Write([]byte(`{"ok":true,"node_id":"x","proof":"wrong"}`))
					return true
				}
				if fault == "wrong-node" && r.URL.Path == "/health" {
					_, _ = w.Write([]byte(`{"ok":true,"node_id":"` + strings.Repeat("a", 64) + `","proof":"router-vpn-private-agent-v1"}`))
					return true
				}
				if r.URL.Path != nodeChainExecutionLeasePath {
					return false
				}
				switch fault {
				case "redirect":
					w.Header().Set("Location", "http://10.80.0.99:8787/foreign")
					w.WriteHeader(302)
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat(" ", (512<<10)+1)))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write([]byte(`{}`))
				case "unknown":
					_, _ = w.Write([]byte(`{"unknown":true}`))
				case "duplicate":
					_, _ = w.Write([]byte(`{"node_id":"a","node_id":"b"}`))
				case "truncated":
					w.Header().Set("Content-Length", "100")
					_, _ = w.Write([]byte(`{}`))
				default:
					return false
				}
				return true
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := o.Discover(ctx); err == nil || o.raw != "" {
				t.Fatal("unproved response granted source authority", err)
			}
		})
	}
}

func TestNodeChainExecutionDiscoveryPlanRejectsChangedNativeIdentityOrProposal(t *testing.T) {
	for _, fault := range []string{"engine", "session", "network", "source", "config", "foreign-port", "unknown-source", "foreign-peer"} {
		t.Run(fault, func(t *testing.T) {
			o, e, _, _ := nodeChainExecutionDiscoveryTestFixture(t, func(d *NodeChainExecutionDiscovery) {
				if fault == "foreign-peer" {
					d.Challenge.Peer = "10.80.0.3"
				}
			}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := o.Discover(ctx); err != nil {
				t.Fatal(err)
			}
			e.mu.Lock()
			switch fault {
			case "engine":
				e.identity.EngineID = "replacement"
			case "session":
				e.identity.SessionID = "replacement"
			case "network":
				e.identity.NetworkID = "replacement"
			case "source":
				e.identity.SourceSHA256 = strings.Repeat("a", 64)
			case "config":
				e.identity.ConfigSHA256 = strings.Repeat("a", 64)
			}
			e.mu.Unlock()
			port := 32003
			source := ""
			if fault == "foreign-port" {
				port = 26240
			}
			if fault == "unknown-source" {
				source = strings.Repeat("a", 64)
			}
			if _, err := o.PlanContext(ctx, source, port); err == nil {
				t.Fatal("late identity/proposal replacement planned a graph")
			}
		})
	}
}

func TestNodeChainExecutionDiscoveryCancellationRetainsLateOriginalOperations(t *testing.T) {
	for _, stage := range []string{"observation", "dial", "close"} {
		t.Run(stage, func(t *testing.T) {
			o, e, _, _ := nodeChainExecutionDiscoveryTestFixture(t, nil, nil)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			pause := func() { once.Do(func() { close(entered); <-release }) }
			switch stage {
			case "observation":
				e.observe = func(context.Context) { pause() }
			case "dial":
				e.dialBefore = func(context.Context) { pause() }
			case "close":
				e.closeBefore = func(int32) error { pause(); return nil }
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { _, err := o.Discover(ctx); done <- err }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("original operation not entered")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled operation succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("caller cancellation waited unbounded on original operation")
			}
			short, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
			if err := o.Close(short); err == nil {
				t.Fatal("late original operation was abandoned by Close")
			}
			stop()
			if o.raw != "" {
				t.Fatal("cancelled worker published discovery")
			}
			close(release)
			joined, finish := context.WithTimeout(context.Background(), time.Second)
			defer finish()
			if err := o.Close(joined); err != nil {
				t.Fatal("original retained cleanup could not retry", err)
			}
			if e.dials.Load() != e.closes.Load() {
				t.Fatal("late original socket escaped cleanup", e.dials.Load(), e.closes.Load())
			}
			if _, err := o.PlanContext(joined, "", 32003); err == nil {
				t.Fatal("late completion reopened cancelled owner")
			}
		})
	}
}

func TestNodeChainExecutionDiscoveryFailedOriginalCloseRemainsRetryable(t *testing.T) {
	o, e, _, _ := nodeChainExecutionDiscoveryTestFixture(t, nil, nil)
	var allowed atomic.Bool
	e.closeBefore = func(int32) error {
		if !allowed.Load() {
			return errors.New("original close refused")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := o.Discover(ctx); err == nil {
		t.Fatal("failed original socket close granted source")
	}
	if o.raw != "" {
		t.Fatal("failed close retained a successful discovery")
	}
	if err := o.Close(ctx); err == nil {
		t.Fatal("unclosed original socket claimed joined cleanup")
	}
	allowed.Store(true)
	if err := o.Close(ctx); err != nil {
		t.Fatal("same original socket close did not retry", err)
	}
	if e.dials.Load() != 1 || e.closes.Load() != 1 {
		t.Fatal("cleanup replaced original socket or repeated acquisition", e.dials.Load(), e.closes.Load())
	}
}
