package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Only the native route boundary is doubled here. Prefix HTTP authentication,
// exact response identities, TLS verification, cancellation and joined sockets
// are executed. Independent encrypted native acceptance is a separate gate.
type nodeChainTestEngine struct {
	mu            sync.Mutex
	identity      NodeChainIdentity
	selected      string
	chain         *NodeChain
	peers         map[string]string
	expected      map[string]string
	calls         []string
	wrong         int
	dead          int
	dnsFail       bool
	dnsCalls      int
	changeOnDNS   bool
	publicBody    string
	publicPeer    string
	beforeObserve func(context.Context)
	beforeDial    func(context.Context, string) (net.Conn, bool)
	observations  atomic.Int32
}

func newNodeChainTestEngine(t *testing.T, chain *NodeChain) *nodeChainTestEngine {
	t.Helper()
	e := &nodeChainTestEngine{identity: NodeChainIdentity{"engine-original", "session-original", "network-original", chain.SourceSHA256(), chain.ConfigSHA256()},
		chain: chain, peers: map[string]string{}, expected: map[string]string{}, wrong: -1, dead: -1, publicBody: "ip=203.0.113.88\n"}
	for position, proof := range chain.ProofInventory() {
		node := chain.nodes[position]
		api, _ := url.Parse(predecessorText(node.profile, "router_api"))
		e.expected[proof.Tag] = api.Host
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" || r.Host != api.Host || r.Header.Get("Authorization") != "Bearer "+predecessorText(node.profile, "api_token") ||
				r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept-Encoding") != "identity" {
				t.Error("prefix proof changed original API/token/policy ownership")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			e.mu.Lock()
			e.calls = append(e.calls, proof.Tag)
			wrong := e.wrong == position
			e.mu.Unlock()
			identity := proof.NodeID
			if wrong {
				identity = chain.proofs[(position+1)%len(chain.proofs)].NodeID
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": identity, "proof": "router-vpn-private-agent-v1"})
		}))
		t.Cleanup(server.Close)
		e.peers[proof.Tag] = server.Listener.Addr().String()
	}
	server, trust := externalMTUTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "1.1.1.1" || r.URL.Path != "/cdn-cgi/trace" || len(r.URL.Query().Get("routervpn_proof")) != 32 ||
			r.Header.Get("Authorization") != "" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("public proof lost literal origin, nonce or credential separation")
		}
		e.mu.Lock()
		body := e.publicBody
		e.mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	e.publicPeer, chain.runtime.testTLS = server.Listener.Addr().String(), trust
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := chain.CloseContext(ctx); err != nil {
			t.Error("proof cleanup did not join", err)
		}
	})
	return e
}

func (e *nodeChainTestEngine) ObserveChainContext(ctx context.Context) (NodeChainIdentity, error) {
	e.observations.Add(1)
	if e.beforeObserve != nil {
		e.beforeObserve(ctx)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.identity, ctx.Err()
}
func (e *nodeChainTestEngine) SelectContext(ctx context.Context, tag string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || tag != e.chain.FinalTag() {
		return errors.New("foreign selected prefix")
	}
	e.selected = tag
	return nil
}
func (e *nodeChainTestEngine) SelectedContext(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.selected, ctx.Err()
}
func (e *nodeChainTestEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if e.beforeDial != nil {
		if conn, handled := e.beforeDial(ctx, tag); handled {
			return conn, nil
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	peer := e.peers[tag]
	if tag == e.chain.FinalTag() && address == "1.1.1.1:443" {
		peer = e.publicPeer
	} else if e.expected[tag] != address {
		return nil, errors.New("foreign prefix destination")
	}
	if peer == "" || e.dead >= 0 && tag == e.chain.proofs[e.dead].Tag {
		return nil, errors.New("captured middle peer stopped")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", peer)
}
func (e *nodeChainTestEngine) DNSProofContext(ctx context.Context, capture NodeChainDNSCapture) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || capture != e.chain.DNSCapture() || e.dnsFail {
		return errors.New("captured final DNS failed")
	}
	e.dnsCalls++
	if e.changeOnDNS {
		e.identity.NetworkID = "replacement-network"
	}
	return nil
}

func TestNodeChainRuntimeProvesEveryOriginalPrefix(t *testing.T) {
	for _, count := range []int{3, 4} {
		chain := nodeChainFixture(t, count, "")
		engine := newNodeChainTestEngine(t, chain)
		ctx, cancel := context.WithCancel(context.Background())
		if err := chain.Run(ctx, engine); err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := chain.HealthyContext(ctx); err != nil {
			t.Fatal(err)
		}
		engine.mu.Lock()
		calls, dns := append([]string(nil), engine.calls...), engine.dnsCalls
		engine.mu.Unlock()
		want := append(chain.PrefixTags(), chain.PrefixTags()...)
		progress := chain.Progress()
		if !reflect.DeepEqual(calls, want) || dns != 1 || !progress.Ready || !progress.DNSProven || !progress.PublicProven || len(progress.Prefixes) != count {
			t.Fatal("first/final success replaced a complete ordered proof", calls, want, progress)
		}
		cancel()
		closeCtx, finish := context.WithTimeout(context.Background(), time.Second)
		if err := chain.CloseContext(closeCtx); err != nil {
			t.Fatal(err)
		}
		finish()
		if chain.Progress().Ready || chain.HealthyContext(context.Background()) == nil || chain.Run(context.Background(), engine) == nil {
			t.Fatal("retired chain was reused or remained ready")
		}
	}
}

func TestNodeChainRuntimeRejectsMiddleAndNativeChanges(t *testing.T) {
	for _, fault := range []string{"middle-identity", "middle-death", "dns", "network-on-dns", "public-body", "tls", "source", "config", "engine", "session", "network"} {
		t.Run(fault, func(t *testing.T) {
			chain := nodeChainFixture(t, 3, "")
			engine := newNodeChainTestEngine(t, chain)
			switch fault {
			case "middle-identity":
				engine.wrong = 1
			case "middle-death":
				engine.dead = 1
			case "dns":
				engine.dnsFail = true
			case "network-on-dns":
				engine.changeOnDNS = true
			case "public-body":
				engine.publicBody = "ip=10.0.0.1\n"
			case "tls":
				chain.runtime.testTLS = nil
			case "source":
				engine.identity.SourceSHA256 = "foreign-source"
			case "config":
				engine.identity.ConfigSHA256 = "foreign-config"
			default:
				if err := chain.Run(context.Background(), engine); err != nil {
					t.Fatal(err)
				}
				engine.mu.Lock()
				switch fault {
				case "engine":
					engine.identity.EngineID = "replacement"
				case "session":
					engine.identity.SessionID = "replacement"
				case "network":
					engine.identity.NetworkID = "replacement"
				}
				engine.mu.Unlock()
				if chain.HealthyContext(context.Background()) == nil || chain.Progress().Ready {
					t.Fatal("changed native owner retained admission", fault)
				}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if chain.Run(ctx, engine) == nil || chain.Progress().Ready {
				t.Fatal("incomplete chain became connected", fault)
			}
		})
	}
}

func TestNodeChainRetainedObserverRetiresDeadMiddle(t *testing.T) {
	chain := nodeChainFixture(t, 3, "")
	engine := newNodeChainTestEngine(t, chain)
	if err := chain.Run(context.Background(), engine); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.dead = 1
	engine.mu.Unlock()
	deadline := time.NewTimer(7 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for chain.Progress().Ready {
		select {
		case <-deadline.C:
			t.Fatal("middle process death retained complete-path admission")
		case <-tick.C:
		}
	}
	if chain.HealthyContext(context.Background()) == nil {
		t.Fatal("failed middle observer still looked healthy")
	}
}

type nodeChainCloseCount struct {
	net.Conn
	closes *atomic.Int32
}

func (c *nodeChainCloseCount) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestNodeChainCancellationJoinsLateOriginalCallbacks(t *testing.T) {
	for _, phase := range []string{"observation", "middle-dial"} {
		t.Run(phase, func(t *testing.T) {
			chain := nodeChainFixture(t, 3, "")
			engine := newNodeChainTestEngine(t, chain)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var closes atomic.Int32
			if phase == "observation" {
				engine.beforeObserve = func(context.Context) { once.Do(func() { close(entered); <-release }) }
			} else {
				engine.beforeDial = func(_ context.Context, tag string) (net.Conn, bool) {
					if tag != chain.proofs[1].Tag {
						return nil, false
					}
					once.Do(func() { close(entered); <-release })
					client, server := net.Pipe()
					_ = server.Close()
					return &nodeChainCloseCount{client, &closes}, true
				}
			}
			parent, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- chain.Run(parent, engine) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("original callback was not reached")
			}
			cancel()
			short, finish := context.WithTimeout(context.Background(), 20*time.Millisecond)
			if err := chain.CloseContext(short); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("close discarded a pending original callback", err)
			}
			finish()
			if chain.Progress().Ready {
				t.Fatal("cancelled pending owner became ready")
			}
			close(release)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("late callback revived the cancelled chain")
				}
			case <-time.After(time.Second):
				t.Fatal("late original callback was abandoned")
			}
			joined, finish := context.WithTimeout(context.Background(), time.Second)
			if err := chain.CloseContext(joined); err != nil {
				t.Fatal("retry did not join the same original work", err)
			}
			finish()
			if phase == "middle-dial" && closes.Load() != 1 {
				t.Fatal("late original socket close was lost or repeated", closes.Load())
			}
		})
	}
}
