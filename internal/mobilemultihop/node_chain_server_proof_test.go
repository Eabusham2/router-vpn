package mobilemultihop

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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

// Only native routing/DNS ownership is doubled. Actual authenticated private
// HTTP, verified public TLS, exact response parsing and joined close execute.
// This is not encrypted native-server or physical-network acceptance.
type nodeChainServerProofTestEngine struct {
	mu                                   sync.Mutex
	policy                               *NodeChainServerPolicy
	capture                              multihoprelay.NodeChainCapture
	binding                              NodeChainServerBinding
	peers                                map[string]string
	publicPeer                           string
	trust                                *tls.Config
	calls                                []string
	dnsCalls                             int
	wrongPrefix, deadPrefix              int
	privateExtra                         bool
	publicBody                           string
	publicStatus                         int
	dnsFail, changeOnDNS, changeOnPublic bool
	beforeObserve                        func(context.Context)
	beforeDial                           func(context.Context, string, string) (net.Conn, error, bool)
	beforeDNS                            func(context.Context)
}

func newNodeChainServerProofTestEngine(t *testing.T, p *NodeChainServerPolicy, c multihoprelay.NodeChainCapture) *nodeChainServerProofTestEngine {
	t.Helper()
	binding, err := p.binding(c)
	if err != nil {
		t.Fatal(err)
	}
	e := &nodeChainServerProofTestEngine{policy: p, capture: c.Clone(), binding: binding, peers: map[string]string{}, wrongPrefix: -1, deadPrefix: -1, publicBody: "ip=203.0.113.88\n", publicStatus: 200}
	for index, target := range p.proofTargets {
		if target.Proof.NodeKind == "external" {
			continue
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" || r.Host != target.Address || r.Header.Get("Authorization") != "Bearer "+target.Token || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept-Encoding") != "identity" {
				t.Error("proof changed captured API/authentication/request policy")
				w.WriteHeader(401)
				return
			}
			e.mu.Lock()
			e.calls = append(e.calls, target.Proof.Tag)
			wrong, extra := e.wrongPrefix == index, e.privateExtra
			e.mu.Unlock()
			id := target.Proof.NodeID
			if wrong {
				id = strings.Repeat("a", 64)
			}
			response := map[string]any{"ok": true, "node_id": id, "proof": "router-vpn-private-agent-v1"}
			if extra {
				response["unbound"] = true
			}
			_ = json.NewEncoder(w).Encode(response)
		}))
		t.Cleanup(server.Close)
		e.peers[target.Proof.Tag] = server.Listener.Addr().String()
	}
	public, trust := externalMTUTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "1.1.1.1" || r.URL.Path != "/cdn-cgi/trace" || len(r.URL.Query().Get("routervpn_proof")) != 32 || r.Header.Get("Authorization") != "" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("public proof changed literal TLS origin, nonce or credential scope")
			w.WriteHeader(401)
			return
		}
		e.mu.Lock()
		body, status := e.publicBody, e.publicStatus
		if e.changeOnPublic {
			e.binding.CaptureSHA256 = strings.Repeat("b", 64)
		}
		e.calls = append(e.calls, "public")
		e.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	e.publicPeer, e.trust = public.Listener.Addr().String(), trust
	for _, target := range p.proofTargets {
		if target.Proof.NodeKind == "external" {
			e.peers[target.Proof.Tag] = e.publicPeer
		}
	}
	return e
}

func (e *nodeChainServerProofTestEngine) ObserveServerContext(ctx context.Context) (NodeChainServerBinding, error) {
	if e.beforeObserve != nil {
		e.beforeObserve(ctx)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.binding, ctx.Err()
}
func (e *nodeChainServerProofTestEngine) DialServerContext(ctx context.Context, tag, network, address string) (net.Conn, error) {
	if e.beforeDial != nil {
		if c, err, handled := e.beforeDial(ctx, tag, address); handled {
			return c, err
		}
	}
	e.mu.Lock()
	peer := ""
	for i, target := range e.policy.proofTargets {
		if target.Proof.Tag == tag && target.Network == network && target.Address == address && i != e.deadPrefix {
			peer = e.peers[tag]
		}
	}
	if tag == e.policy.dns.FinalTag && network == "tcp" && address == "1.1.1.1:443" {
		peer = e.publicPeer
	}
	e.mu.Unlock()
	if peer == "" {
		return nil, errors.New("unowned proof tuple")
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", peer)
}
func (e *nodeChainServerProofTestEngine) ProveServerDNSContext(ctx context.Context, capture NodeChainServerDNSCapture) error {
	if e.beforeDNS != nil {
		e.beforeDNS(ctx)
	}
	want, err := e.policy.DNSCapture(e.capture)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil || !reflect.DeepEqual(capture, want) || e.dnsFail || ctx.Err() != nil {
		return errors.New("captured DNS proof failed")
	}
	e.dnsCalls++
	if e.changeOnDNS {
		e.binding.ConfigSHA256 = strings.Repeat("b", 64)
	}
	return nil
}

func TestNodeChainServerProofUsesEveryOriginalSuffixAndDNSOwner(t *testing.T) {
	for _, count := range []int{2, 4} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			p, c := nodeChainServerFixture(t, count, "aes-256-gcm+xor-whitening")
			// The immutable original bootstrap time may precede a refresh. This
			// caller owns the current proof-expiry bound; no capture is rewritten.
			c.BootstrapDeadline = time.Now().Add(-time.Minute).UTC()
			e := newNodeChainServerProofTestEngine(t, p, c)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			started := time.Now()
			result, err := p.prove(ctx, c, e, e.trust)
			if err != nil {
				t.Fatal(err)
			}
			if result.Binding != e.binding || len(result.Prefixes) != count-1 || !result.DNSProven || !result.PublicProven || result.ExitIP != "203.0.113.88" || result.ProvenAt.Before(started) || result.ProvenAt.After(time.Now()) {
				t.Fatal("incomplete or restamped proof result", result)
			}
			want := []string{}
			for i, row := range result.Prefixes {
				if row.Proof != p.proofs[i] || row.ResponseMS <= 0 {
					t.Fatal("routed proof identity/measurement changed")
				}
				want = append(want, row.Proof.Tag)
			}
			want = append(want, "public")
			e.mu.Lock()
			calls, dns := append([]string(nil), e.calls...), e.dnsCalls
			e.mu.Unlock()
			if !reflect.DeepEqual(calls, want) || dns != 1 {
				t.Fatal("an original middle or selected DNS was omitted", calls, dns)
			}
			result.Prefixes[0].Proof.Tag = "mutated-result"
			if p.proofs[0].Tag == "mutated-result" {
				t.Fatal("proof result aliases retained source")
			}
		})
	}
}

func TestNodeChainServerProofRejectsUnprovedOrChangedPath(t *testing.T) {
	for _, fault := range []string{"wrong-middle", "dead-middle", "private-extra", "dns-failure", "dns-replacement", "public-replacement", "private-public-ip", "duplicate-public-ip", "redirect", "untrusted-tls", "initial-owner", "unbounded", "cancelled", "foreign-capture"} {
		t.Run(fault, func(t *testing.T) {
			p, c := nodeChainServerFixture(t, 4, "")
			e := newNodeChainServerProofTestEngine(t, p, c)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			trust := e.trust
			switch fault {
			case "wrong-middle":
				e.wrongPrefix = 1
			case "dead-middle":
				e.deadPrefix = 1
			case "private-extra":
				e.privateExtra = true
			case "dns-failure":
				e.dnsFail = true
			case "dns-replacement":
				e.changeOnDNS = true
			case "public-replacement":
				e.changeOnPublic = true
			case "private-public-ip":
				e.publicBody = "ip=10.1.2.3\n"
			case "duplicate-public-ip":
				e.publicBody = "ip=203.0.113.88\nip=203.0.113.89\n"
			case "redirect":
				e.publicStatus = 302
			case "untrusted-tls":
				trust = nil
			case "initial-owner":
				e.binding.CaptureSHA256 = strings.Repeat("a", 64)
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "foreign-capture":
				c.OwnerID = strings.Repeat("a", 64)
			}
			result, err := p.prove(ctx, c, e, trust)
			if err == nil || !reflect.DeepEqual(result, NodeChainServerProofResult{}) {
				t.Fatal("unproved path returned partial or ready evidence", result, err)
			}
			if fault == "initial-owner" || fault == "unbounded" || fault == "cancelled" || fault == "foreign-capture" {
				e.mu.Lock()
				calls, dns := len(e.calls), e.dnsCalls
				e.mu.Unlock()
				if calls != 0 || dns != 0 {
					t.Fatal("invalid original authority reached native proof I/O")
				}
			}
		})
	}
}

func TestNodeChainServerProofCancellationJoinsLateOriginalCallbacks(t *testing.T) {
	for _, phase := range []string{"observation", "middle-dial", "dns"} {
		t.Run(phase, func(t *testing.T) {
			p, c := nodeChainServerFixture(t, 4, "")
			e := newNodeChainServerProofTestEngine(t, p, c)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var closes atomic.Int32
			pause := func(context.Context) { once.Do(func() { close(entered); <-release }) }
			switch phase {
			case "observation":
				e.beforeObserve = pause
			case "dns":
				e.beforeDNS = pause
			case "middle-dial":
				e.beforeDial = func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
					if tag != p.proofs[1].Tag {
						return nil, nil, false
					}
					pause(ctx)
					client, peer := net.Pipe()
					_ = peer.Close()
					return &nodeChainCloseCount{client, &closes}, nil, true
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := p.prove(ctx, c, e, e.trust); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("owned callback not reached")
			}
			cancel()
			select {
			case <-done:
				t.Fatal("cancel abandoned an unjoined original callback")
			case <-time.After(20 * time.Millisecond):
			}
			close(release)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("late callback revived cancelled proof")
				}
			case <-time.After(time.Second):
				t.Fatal("late owned callback did not join")
			}
			if phase == "middle-dial" && closes.Load() != 1 {
				t.Fatal("late original connection was lost or double closed", closes.Load())
			}
		})
	}
}

type nodeChainServerUnprovedClose struct {
	net.Conn
	closes *atomic.Int32
}

func (c *nodeChainServerUnprovedClose) Close() error {
	c.closes.Add(1)
	return errors.Join(c.Conn.Close(), errors.New("original proof close not acknowledged"))
}

func TestNodeChainServerProofRejectsUnprovedOriginalSocketClose(t *testing.T) {
	for _, failure := range []string{"after-http", "dial-error-with-connection"} {
		t.Run(failure, func(t *testing.T) {
			p, capture := nodeChainServerFixture(t, 3, "")
			engine := newNodeChainServerProofTestEngine(t, p, capture)
			var closes atomic.Int32
			engine.beforeDial = func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
				if tag != p.proofs[0].Tag {
					return nil, nil, false
				}
				if failure == "dial-error-with-connection" {
					client, peer := net.Pipe()
					_ = peer.Close()
					return &nodeChainCloseCount{client, &closes}, errors.New("late failed original dial"), true
				}
				var dialer net.Dialer
				connection, err := dialer.DialContext(ctx, "tcp", engine.peers[tag])
				if err != nil {
					return nil, err, true
				}
				return &nodeChainServerUnprovedClose{connection, &closes}, nil, true
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := p.prove(ctx, capture, engine, engine.trust)
			if err == nil || !reflect.DeepEqual(result, NodeChainServerProofResult{}) || closes.Load() != 1 {
				t.Fatal("unproved/failed original socket was accepted, lost or closed twice", result, err, closes.Load())
			}
		})
	}
}
