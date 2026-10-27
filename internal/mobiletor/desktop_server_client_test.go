package mobiletor

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

type serverTorClientFixture struct {
	t          *testing.T
	ctx        context.Context
	cancel     context.CancelFunc
	client     *ServerTorClient
	policy     *ServerTorPolicy
	api        *httptest.Server
	front      *ServerTorFront
	current    atomic.Bool
	mu         sync.Mutex
	lease      multihoprelay.TorLease
	methods    []string
	sequence   uint64
	mutate     func(string, map[string]any)
	putEntered chan struct{}
	putRelease chan struct{}
	deleteFail bool
}

func newServerTorClientFixture(t *testing.T) *serverTorClientFixture {
	t.Helper()
	f := &serverTorClientFixture{t: t, policy: serverTorPolicy(t, serverTorSource("tor-bridge"))}
	f.current.Store(true)
	f.ctx, f.cancel = context.WithCancel(context.Background())
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.front, err = newServerTorFront(context.Background(), listener, netip.MustParseAddr("127.0.0.1"), strings.Repeat("a", 48), strings.Repeat("b", 48), func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "service.example:443" {
			return nil, errServerTorClient
		}
		client, server := net.Pipe()
		go func() { defer server.Close(); _, _ = io.Copy(server, server) }()
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.front.Enable(); err != nil {
		t.Fatal(err)
	}
	f.api = httptest.NewServer(http.HandlerFunc(f.serve))
	entryJSON, _ := json.Marshal(map[string]any{"id": "private-router", "node_kind": "router-vpn", "node_proof_id": serverTorNode, "router_api": "http://10.77.0.1:8787", "api_token": "private-captured-token"})
	entry, err := NewPredecessorProof(string(entryJSON))
	if err != nil {
		t.Fatal(err)
	}
	f.client, err = NewServerTorClient(f.ctx, f.policy, entry, strings.Repeat("c", 32), func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errServerTorClient
		}
		switch address {
		case "10.77.0.1:8787":
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(f.api.URL, "http://"))
		case "10.77.0.1:26240":
			return (&net.Dialer{}).DialContext(ctx, network, f.front.Address())
		default:
			return nil, errServerTorClient
		}
	}, f.current.Load)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.current.Store(true)
		f.mu.Lock()
		f.deleteFail = false
		f.mu.Unlock()
		_ = f.client.Close(context.Background())
		f.cancel()
		f.api.Close()
		_ = f.front.Close(context.Background())
	})
	return f
}

func (f *serverTorClientFixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Host != "10.77.0.1:8787" || r.Header.Get("Authorization") != "Bearer private-captured-token" {
		http.Error(w, "wrong owner", 403)
		return
	}
	if r.URL.Path == "/health" {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": serverTorNode, "proof": "router-vpn-private-agent-v1"})
		return
	}
	if r.URL.Path != serverTorLeasePath || r.URL.RawQuery != "" {
		http.Error(w, "wrong origin", 403)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, r.Method)
	source := multihoprelay.TorExitSource{ID: f.policy.ID(), Mode: f.policy.Mode(), SourceSHA256: f.policy.SourceSHA256(), DNSPolicySHA256: f.policy.DNSPolicySHA256()}
	var response any
	if r.Method == http.MethodGet {
		response = map[string]any{"node_id": serverTorNode, "challenge": multihoprelay.ExternalPacketChallenge{Epoch: strings.Repeat("d", 64), Peer: "10.77.0.2", ExpiresAt: time.Now().Add(time.Minute).Unix()}, "sources": []multihoprelay.TorExitSource{source}}
	} else {
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		var nonce string
		_ = json.Unmarshal(body["status_nonce"], &nonce)
		delete(body, "status_nonce")
		raw, _ := json.Marshal(body)
		var request multihoprelay.TorRequest
		_ = json.Unmarshal(raw, &request)
		if f.lease.OwnerID != "" && request != f.lease.Request {
			http.Error(w, "replaced request", 403)
			return
		}
		switch r.Method {
		case http.MethodPut:
			if f.lease.OwnerID == "" {
				registry, _ := json.Marshal(struct {
					Node   string                      `json:"node_id"`
					Source multihoprelay.TorExitSource `json:"source"`
				}{serverTorNode, source})
				f.lease = multihoprelay.TorLease{Request: request, NodeID: serverTorNode, OwnerID: strings.Repeat("e", 64), Host: "10.77.0.1", Port: 26240, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48), RegistrySHA256: desktopDigest(registry), DNSPolicySHA256: source.DNSPolicySHA256, Phase: multihoprelay.TorPending, BootstrapDeadline: time.Now().Add(multihoprelay.TorBootstrapLimit)}
			}
			f.lease.ExpiresAt = time.Now().Add(time.Minute)
			response = f.lease
			if f.putEntered != nil {
				close(f.putEntered)
				release := f.putRelease
				f.mu.Unlock()
				<-release
				f.mu.Lock()
			}
		case http.MethodPost:
			f.sequence++
			f.lease.Phase = multihoprelay.TorReady
			capture := f.client.capture(f.lease)
			response = multihoprelay.TorLeaseStatus{Lease: f.lease, Receipt: multihoprelay.TorReceipt{Schema: 1, SessionID: request.SessionID, OwnerID: f.lease.OwnerID, Peer: request.Peer, SourceSHA256: source.SourceSHA256, RegistrySHA256: f.lease.RegistrySHA256, DNSPolicySHA256: source.DNSPolicySHA256, FrontSHA256: capture.FrontSHA256(), Nonce: nonce, Sequence: f.sequence, HeartbeatAt: time.Now().UnixMilli(), Phase: multihoprelay.TorReady, Bootstrap: 100, FrontReady: true, TrafficAllowed: true, ExitIP: "198.51.100.80", IsTor: true, DNSProven: true, ProofAt: time.Now().UnixMilli()}}
		case http.MethodDelete:
			if f.deleteFail {
				http.Error(w, "cleanup pending", 503)
				return
			}
			response = map[string]any{"node_id": serverTorNode, "session_id": request.SessionID, "stopped": true}
		default:
			http.Error(w, "method", 405)
			return
		}
	}
	raw, _ := json.Marshal(response)
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	if f.mutate != nil {
		f.mutate(r.Method, object)
	}
	_ = json.NewEncoder(w).Encode(object)
}

func TestServerTorClientCapturesAuthenticatedLeaseAndActualSOCKSTraffic(t *testing.T) {
	f := newServerTorClientFixture(t)
	if _, err := f.client.DialContext(t.Context(), "tcp", "service.example:443"); err == nil {
		t.Fatal("unproved lease carried traffic")
	}
	if err := f.client.Acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !f.client.Current() || f.client.Ready() {
		t.Fatal("pending lease became ready")
	}
	if _, err := f.client.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	connection, err := f.client.DialContext(t.Context(), "tcp", "service.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Write([]byte("captured route")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("captured route"))
	if _, err = io.ReadFull(connection, got); err != nil || string(got) != "captured route" {
		t.Fatal("leased SOCKS did not carry exact bytes", err)
	}
	_ = connection.Close()
	f.client.mu.Lock()
	f.client.lease.ExpiresAt = time.Now().Add(9 * time.Second)
	f.client.mu.Unlock()
	if _, err := f.client.Status(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.cancel()
	if f.client.Current() {
		t.Fatal("cancelled client stayed current")
	}
	if err := f.client.Close(t.Context()); err != nil {
		t.Fatal("cancelled owner could not DELETE through retained entry", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.methods, ",") != "GET,PUT,POST,PUT,POST,DELETE" {
		t.Fatal("lease did not retain discovery/acquire/status/renew/delete ownership", f.methods)
	}
}

func TestServerTorClientRejectsMismatchedDiscoveryLeaseAndReceipt(t *testing.T) {
	for _, fault := range []string{"source", "dns", "node", "front", "credentials", "nonce", "sequence", "proof"} {
		t.Run(fault, func(t *testing.T) {
			f := newServerTorClientFixture(t)
			f.mutate = func(method string, value map[string]any) {
				switch fault {
				case "source", "dns":
					if method == "GET" {
						key := "source_sha256"
						if fault == "dns" {
							key = "dns_policy_sha256"
						}
						value["sources"].([]any)[0].(map[string]any)[key] = strings.Repeat("f", 64)
					}
				case "node":
					if method == "GET" {
						value["node_id"] = strings.Repeat("f", 64)
					}
				case "front":
					if method == "PUT" {
						value["host"] = "10.77.0.9"
					}
				case "credentials":
					if method == "PUT" {
						value["password"] = value["username"]
					}
				case "nonce":
					if method == "POST" {
						value["receipt"].(map[string]any)["nonce"] = strings.Repeat("f", 64)
					}
				case "sequence":
					if method == "POST" {
						value["receipt"].(map[string]any)["sequence"] = 0
					}
				case "proof":
					if method == "POST" {
						value["receipt"].(map[string]any)["dns_proven"] = false
					}
				}
			}
			err := f.client.Acquire(t.Context())
			if err == nil {
				_, err = f.client.Status(t.Context())
			}
			if err == nil || f.client.Ready() {
				t.Fatal("changed server authority was accepted")
			}
		})
	}
}

func TestServerTorClientLostPUTAndEntryReplacementRetainExactCleanup(t *testing.T) {
	f := newServerTorClientFixture(t)
	f.putEntered, f.putRelease = make(chan struct{}), make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(f.putRelease) }) })
	acquired := make(chan error, 1)
	go func() { acquired <- f.client.Acquire(f.ctx) }()
	<-f.putEntered
	f.cancel()
	if err := <-acquired; err == nil {
		t.Fatal("cancelled PUT adopted its late lease")
	}
	f.current.Store(false)
	if err := f.client.Close(t.Context()); err == nil {
		t.Fatal("replacement entry was allowed to clean old lease")
	}
	f.mu.Lock()
	methods := strings.Join(f.methods, ",")
	f.mu.Unlock()
	if methods != "GET,PUT" {
		t.Fatal("retired physical entry sent a cleanup request", methods)
	}
	release.Do(func() { close(f.putRelease) })
	f.current.Store(true)
	if err := f.client.Close(t.Context()); err != nil {
		t.Fatal("retained original entry failed owned deletion", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.methods, ",") != "GET,PUT,DELETE" {
		t.Fatal("late acquisition changed cleanup owner", f.methods)
	}
}

func TestServerTorClientRequiresActualSOCKSAuthenticationAndPublicTCPDestination(t *testing.T) {
	f := newServerTorClientFixture(t)
	for _, fault := range []string{"username", "password", "private", "bad-port"} {
		t.Run(fault, func(t *testing.T) {
			user, password, destination := strings.Repeat("a", 48), strings.Repeat("b", 48), "service.example:443"
			switch fault {
			case "username":
				user = strings.Repeat("f", 48)
			case "password":
				password = strings.Repeat("f", 48)
			case "private":
				destination = "10.77.0.9:443"
			case "bad-port":
				destination = "service.example:0"
			}
			connection, err := dialServerTorSOCKS(t.Context(), f.front.Address(), user, password, destination, (&net.Dialer{}).DialContext)
			if connection != nil {
				_ = connection.Close()
			}
			if err == nil {
				t.Fatal("invalid captured front authentication or destination was accepted")
			}
		})
	}
}
