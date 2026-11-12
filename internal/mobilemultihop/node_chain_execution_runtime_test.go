package mobilemultihop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

// Shipping client HTTP/TLS, receipt validation, Manager and routechoice execute.
// Native routing, resolver and server worker receipts are explicit boundary
// doubles; these cases are not native encryption, TUN or UDP acceptance.
type nodeChainExecutionRuntimeWorker struct {
	capture      multihoprelay.NodeChainCapture
	alive, ready atomic.Bool
	sequence     atomic.Uint64
	proofAt      atomic.Int64
	runner       *nodeChainExecutionRuntimeRunner
}

func (p *nodeChainExecutionRuntimeWorker) Alive() bool { return p.alive.Load() }
func (p *nodeChainExecutionRuntimeWorker) Stop(context.Context) error {
	if p.runner.failStop.Load() {
		return errors.New("original native close is not joined")
	}
	p.alive.Store(false)
	return nil
}
func (p *nodeChainExecutionRuntimeWorker) Bootstrap(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.proofAt.Store(time.Now().UnixMilli())
	p.ready.Store(true)
	return nil
}
func (p *nodeChainExecutionRuntimeWorker) Snapshot(ctx context.Context, nonce string) (multihoprelay.NodeChainReceipt, error) {
	c := p.capture
	digest, _ := c.Digest()
	r := multihoprelay.NodeChainReceipt{Schema: 1, SessionID: c.Request.SessionID, OwnerID: c.OwnerID, Peer: c.Peer, SourceSHA256: c.Source.SourceSHA256, RegistrySHA256: c.RegistrySHA256, DNSPolicySHA256: c.Source.DNSPolicySHA256, CaptureSHA256: digest, Nonce: nonce, Sequence: p.sequence.Add(1), HeartbeatAt: time.Now().UnixMilli(), Phase: multihoprelay.NodeChainPending, FrontReady: true}
	if p.ready.Load() {
		r.Phase = multihoprelay.NodeChainReady
		r.TrafficAllowed = true
		r.DNSProven = true
		r.PublicProven = true
		r.ProofAt = p.proofAt.Load()
		for _, m := range c.Source.Members {
			r.Prefixes = append(r.Prefixes, multihoprelay.NodeChainPrefixReceipt{Position: m.Position, ProfileID: m.ProfileID, NodeID: m.NodeID, Mode: m.Mode, Proven: true, ResponseMS: 1.5})
		}
	}
	return r, ctx.Err()
}

type nodeChainExecutionRuntimeRunner struct {
	mu        sync.Mutex
	workers   []*nodeChainExecutionRuntimeWorker
	failStop  atomic.Bool
	startHook func()
}

func (r *nodeChainExecutionRuntimeRunner) Start(context.Context, []byte, multihoprelay.Lease) (multihoprelay.Process, error) {
	return nil, errors.New("ordinary fallback forbidden")
}
func (r *nodeChainExecutionRuntimeRunner) StartChain(ctx context.Context, c multihoprelay.NodeChainCapture) (multihoprelay.NodeChainProcess, error) {
	if r.startHook != nil {
		r.startHook()
	}
	p := &nodeChainExecutionRuntimeWorker{capture: c.Clone(), runner: r}
	p.alive.Store(true)
	r.mu.Lock()
	r.workers = append(r.workers, p)
	r.mu.Unlock()
	return p, ctx.Err()
}

func TestNodeChainExecutionRuntimeClosedTrialCannotRevokeNewWinner(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "auto")
	var original *nodeChainExecutionTrial
	var once sync.Once
	f.engine.beforeDNS = func(context.Context) {
		once.Do(func() { f.runtime.mu.Lock(); original = f.runtime.active; f.runtime.mu.Unlock() })
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if original == nil || original.execution != "local" {
		t.Fatal("original local trial not captured")
	}
	f.engine.mu.Lock()
	revokes := f.engine.revokes
	f.engine.mu.Unlock()
	if err := original.Close(ctx); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	open, after := f.engine.open, f.engine.revokes
	f.engine.mu.Unlock()
	if !open || after != revokes {
		t.Fatal("stale joined trial revoked new candidate ownership", revokes, after)
	}
	if err := f.runtime.HealthyContext(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNodeChainExecutionRuntimeKeepsLateUnacknowledgedPUTUntilExactStop(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	entered, release := make(chan struct{}), make(chan struct{})
	f.runner.startHook = func() { close(entered); <-release }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.runtime.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("native server startup did not enter")
	}
	cancel()
	short, finish := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if err := f.runtime.CloseContext(short); err == nil {
		t.Fatal("unacknowledged original PUT/native start was abandoned")
	}
	finish()
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled acquisition activated")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("late original native start did not join")
	}
	joined, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := f.runtime.CloseContext(joined); err != nil {
		t.Fatal("exact original cleanup could not finish", err)
	}
	f.mu.Lock()
	var original string
	deletes := 0
	for _, request := range f.requests {
		if request.method == "PUT" {
			if original != "" && original != request.session {
				t.Error("late PUT replaced original request")
			}
			original = request.session
		}
		if request.method == "DELETE" {
			deletes++
			if request.session != original {
				t.Error("cleanup changed original request")
			}
		}
	}
	f.mu.Unlock()
	if original == "" || deletes < 1 {
		t.Fatal("uncertain acquisition had no original DELETE")
	}
	f.runner.mu.Lock()
	for _, worker := range f.runner.workers {
		if worker.Alive() {
			t.Error("late native worker abandoned")
		}
	}
	f.runner.mu.Unlock()
	f.engine.mu.Lock()
	open, stops := f.engine.open, f.engine.stops
	f.engine.mu.Unlock()
	if open || stops != 0 {
		t.Fatal("late acquisition retained forwarding or lost cleanup", open, stops)
	}
}

func TestNodeChainExecutionRuntimeRetainsConnectionReturnedWithErrorAndFailedClose(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	proofs, _ := f.runtime.projection.ProofInventory("server")
	var injected, allowed atomic.Bool
	counts := &nodeChainExecutionDiscoveryTestEngine{}
	counts.closeBefore = func(int32) error {
		if !allowed.Load() {
			return errors.New("original returned-error socket close refused")
		}
		return nil
	}
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = client.Close() })
	owned := &nodeChainExecutionDiscoveryTestConn{Conn: client, engine: counts}
	f.engine.beforeDial = func(_ context.Context, tag, address string) (net.Conn, error, bool) {
		if tag == proofs[len(proofs)-1].Tag && injected.CompareAndSwap(false, true) {
			counts.dials.Add(1)
			return owned, errors.New("native validation changed after connection acquisition"), true
		}
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err == nil {
		t.Fatal("connection-plus-error granted path proof")
	}
	f.engine.mu.Lock()
	stops := f.engine.stops
	f.engine.mu.Unlock()
	if !injected.Load() || stops != 1 || counts.closes.Load() != 0 {
		t.Fatal("failed original close disappeared with its dial error", stops, counts.closes.Load())
	}
	if err := f.runtime.CloseContext(ctx); err == nil {
		t.Fatal("failed retained proof socket was treated as joined")
	}
	allowed.Store(true)
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("same original error socket could not retry", err)
	}
	f.engine.mu.Lock()
	stops = f.engine.stops
	f.engine.mu.Unlock()
	if counts.dials.Load() != 1 || counts.closes.Load() != 1 || stops != 0 {
		t.Fatal("retry replaced original connection or dropped cleanup", counts.dials.Load(), counts.closes.Load(), stops)
	}
}

type nodeChainExecutionRuntimeEngine struct {
	mu                      sync.Mutex
	projection              *NodeChainExecutionProjection
	identity                NodeChainIdentity
	selected                string
	epoch                   uint64
	open, alive             bool
	peers                   map[string]string
	publicPeer              string
	publicCalls             []string
	proofCalls              []string
	selections              []string
	opens, revokes, stops   int
	dnsCalls                []string
	wrongPrefix             int
	failDNS, wrongPublic    bool
	localDelay, serverDelay time.Duration
	beforeObserve           func(context.Context)
	beforeDial              func(context.Context, string, string) (net.Conn, error, bool)
	beforeDNS               func(context.Context)
	beforeOpen              func(context.Context)
	afterOpen               func()
	beforeStopCapture       func(context.Context)
}

func (e *nodeChainExecutionRuntimeEngine) ObserveChainContext(ctx context.Context) (NodeChainIdentity, error) {
	if e.beforeObserve != nil {
		e.beforeObserve(ctx)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.alive {
		return NodeChainIdentity{}, net.ErrClosed
	}
	return e.identity, ctx.Err()
}
func (e *nodeChainExecutionRuntimeEngine) SelectedContext(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.selected, ctx.Err()
}
func (e *nodeChainExecutionRuntimeEngine) SelectionEpochContext(ctx context.Context) (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.epoch, ctx.Err()
}
func (e *nodeChainExecutionRuntimeEngine) SelectContext(ctx context.Context, tag string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	local, _ := e.projection.ProofInventory("local")
	server, _ := e.projection.ProofInventory("server")
	if ctx.Err() != nil || e.open || tag != local[len(local)-1].Tag && tag != server[len(server)-1].Tag {
		return nodeChainExecutionError
	}
	e.selected = tag
	e.epoch++
	e.selections = append(e.selections, tag)
	return nil
}
func (e *nodeChainExecutionRuntimeEngine) RevokeApplicationContext(ctx context.Context) error {
	e.mu.Lock()
	e.open = false
	e.revokes++
	e.mu.Unlock()
	return ctx.Err()
}
func (e *nodeChainExecutionRuntimeEngine) ApplicationOpenContext(ctx context.Context) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.open, ctx.Err()
}
func (e *nodeChainExecutionRuntimeEngine) OpenApplicationContext(ctx context.Context, identity NodeChainIdentity, tag string) error {
	if e.beforeOpen != nil {
		e.beforeOpen(ctx)
	}
	e.mu.Lock()
	if ctx.Err() != nil || !e.alive || identity != e.identity || tag != e.selected {
		e.mu.Unlock()
		return nodeChainExecutionError
	}
	e.open = true
	e.opens++
	e.mu.Unlock()
	if e.afterOpen != nil {
		e.afterOpen()
	}
	return ctx.Err()
}
func (e *nodeChainExecutionRuntimeEngine) DNSExecutionProofContext(ctx context.Context, c NodeChainExecutionDNSCapture) error {
	if e.beforeDNS != nil {
		e.beforeDNS(ctx)
	}
	want, err := e.projection.DNSCapture(c.Execution)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil || c != want || e.failDNS || c.SelectedTag != e.selected || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	e.dnsCalls = append(e.dnsCalls, c.Execution)
	return nil
}
func (e *nodeChainExecutionRuntimeEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if e.beforeDial != nil {
		if c, err, handled := e.beforeDial(ctx, tag, address); handled {
			return c, err
		}
	}
	e.mu.Lock()
	peer := e.peers[tag+"/"+address]
	alive := e.alive
	for _, execution := range []string{"local", "server"} {
		proofs, _ := e.projection.ProofInventory(execution)
		if tag == proofs[len(proofs)-1].Tag && (address == "1.1.1.1:443" || address == "1.0.0.1:443") {
			peer = e.publicPeer
		}
	}
	e.mu.Unlock()
	if peer == "" || !alive {
		return nil, nodeChainExecutionError
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", peer)
}
func (e *nodeChainExecutionRuntimeEngine) CaptureExecutionStop(ctx context.Context, c NodeChainExecutionStopCapture) (LeaseStop, error) {
	if e.beforeStopCapture != nil {
		e.beforeStopCapture(ctx)
	}
	e.mu.Lock()
	if c.Identity() != e.identity || !e.alive || ctx.Err() != nil {
		e.mu.Unlock()
		return nil, nodeChainExecutionError
	}
	e.stops++
	e.mu.Unlock()
	tag, address := c.Route()
	return NewOwnedNodeChainExecutionStop(c, func(call context.Context) (net.Conn, error) { return e.Dial(call, tag, address) }, func(call context.Context) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		if !e.alive || e.open {
			return nodeChainExecutionError
		}
		return call.Err()
	}, func() { e.mu.Lock(); e.stops--; e.mu.Unlock() })
}

type nodeChainExecutionRuntimeFixture struct {
	runtime      *NodeChainExecutionRuntime
	engine       *nodeChainExecutionRuntimeEngine
	manager      *multihoprelay.Manager
	runner       *nodeChainExecutionRuntimeRunner
	mu           sync.Mutex
	requests     []struct{ method, session string }
	mutateLease  func(*multihoprelay.NodeChainLease)
	mutateStatus func(*multihoprelay.NodeChainLeaseStatus)
	beforePUT    func(context.Context, multihoprelay.NodeChainRequest)
	trust        *tls.Config
}

func nodeChainExecutionRuntimeTLS(t *testing.T, handler http.Handler) (*httptest.Server, *tls.Config) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(9), IPAddresses: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return server, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

func newNodeChainExecutionRuntimeFixture(t *testing.T, execution string) *nodeChainExecutionRuntimeFixture {
	t.Helper()
	source := nodeChainExecutionFixtureSource(t, 3, "", execution)
	policy, err := NewNodeChainExecutionPolicy(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewNodeChainExecutionPreparation(source.LocalSource, execution)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := prep.BindExecution(policy)
	if err != nil {
		t.Fatal(err)
	}
	e := &nodeChainExecutionRuntimeEngine{projection: projection, identity: NodeChainIdentity{"original-box", "original-session", "original-network", projection.SourceSHA256(), projection.ConfigSHA256()}, alive: true, epoch: 1, peers: map[string]string{}, wrongPrefix: -1, localDelay: 20 * time.Millisecond, serverDelay: time.Millisecond}
	local, _ := projection.ProofInventory("local")
	serverProofs, _ := projection.ProofInventory("server")
	e.selected = local[len(local)-1].Tag
	f := &nodeChainExecutionRuntimeFixture{engine: e, runner: &nodeChainExecutionRuntimeRunner{}}
	f.manager, err = multihoprelay.New(multihoprelay.Config{ListenIP: policy.Front().Host, FirstPort: source.FirstPort, LastPort: source.LastPort, TTLSeconds: 15, NodeChains: []multihoprelay.NodeChainDescriptor{source.Server}}, source.Server.EntryNodeID, f.runner)
	if err != nil {
		t.Fatal(err)
	}
	for position, node := range policy.local.nodes {
		api, _ := privateAPI(predecessorText(node.profile, "router_api"))
		token := predecessorText(node.profile, "api_token")
		endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != api.Host || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept-Encoding") != "identity" {
				http.Error(w, "unauthorized", 403)
				return
			}
			if position == 0 && r.URL.Path == nodeChainExecutionLeasePath {
				f.serveControl(w, r)
				return
			}
			if r.Method != "GET" || r.URL.Path != "/health" {
				http.Error(w, "bad", 400)
				return
			}
			e.mu.Lock()
			id := local[position].NodeID
			if e.wrongPrefix == position {
				id = strings.Repeat("a", 64)
			}
			e.proofCalls = append(e.proofCalls, e.selected+"/"+local[position].ProfileID)
			delay := e.localDelay
			if e.selected == serverProofs[len(serverProofs)-1].Tag {
				delay = e.serverDelay
			}
			e.mu.Unlock()
			if position == len(local)-1 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(delay):
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": id, "proof": "router-vpn-private-agent-v1"})
		}))
		t.Cleanup(endpoint.Close)
		e.peers[local[position].Tag+"/"+api.Host] = endpoint.Listener.Addr().String()
		e.peers[serverProofs[position].Tag+"/"+api.Host] = endpoint.Listener.Addr().String()
	}
	public, trust := nodeChainExecutionRuntimeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || (r.Host != "1.1.1.1" && r.Host != "1.0.0.1") || r.URL.Path != "/cdn-cgi/trace" || len(r.URL.Query().Get("routervpn_proof")) != 32 || r.Header.Get("Authorization") != "" {
			http.Error(w, "bad", 400)
			return
		}
		e.mu.Lock()
		e.publicCalls = append(e.publicCalls, e.selected+"/"+r.Host)
		body := "ip=203.0.113.88\n"
		if e.wrongPublic {
			body = "ip=10.0.0.1\n"
		}
		delay := e.localDelay
		if e.selected == serverProofs[len(serverProofs)-1].Tag {
			delay = e.serverDelay
		}
		e.mu.Unlock()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(delay):
		}
		_, _ = w.Write([]byte(body))
	}))
	e.publicPeer = public.Listener.Addr().String()
	f.trust = trust
	f.runtime, err = NewNodeChainExecutionRuntime(projection, e)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.testTLS = trust
	t.Cleanup(func() {
		f.runner.failStop.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.runtime.CloseContext(ctx); err != nil {
			t.Error("original runtime fixture cleanup", err)
		}
		if err := f.manager.Close(ctx); err != nil {
			t.Error("original manager fixture cleanup", err)
		}
	})
	return f
}

func (f *nodeChainExecutionRuntimeFixture) serveControl(w http.ResponseWriter, r *http.Request) {
	peer := netip.MustParseAddr("10.80.0.2")
	if r.URL.RawQuery != "" {
		http.Error(w, "bad", 400)
		return
	}
	if r.Method == "GET" {
		challenge, sources, err := f.manager.ChainAvailable(peer)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		first, last, err := f.manager.ChainPortRange(peer)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(NodeChainExecutionDiscovery{NodeID: f.engine.projection.policy.Descriptor().EntryNodeID, Challenge: challenge, Sources: sources, FirstPort: first, LastPort: last})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(body) > 4096 {
		http.Error(w, "bad", 400)
		return
	}
	request, nonce, err := multihoprelay.DecodeNodeChainLeaseRequest(body, r.Method == "POST")
	if err != nil {
		http.Error(w, "bad", 400)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, struct{ method, session string }{r.Method, request.SessionID})
	f.mu.Unlock()
	switch r.Method {
	case "PUT":
		if f.beforePUT != nil {
			f.beforePUT(r.Context(), request)
		}
		var lease multihoprelay.NodeChainLease
		lease, err = f.manager.CreateChain(r.Context(), peer, request)
		if err == nil {
			if f.mutateLease != nil {
				f.mutateLease(&lease)
			}
			_ = json.NewEncoder(w).Encode(lease)
			return
		}
	case "POST":
		var status multihoprelay.NodeChainLeaseStatus
		status, err = f.manager.ChainStatus(r.Context(), peer, request, nonce)
		if err == nil {
			if f.mutateStatus != nil {
				f.mutateStatus(&status)
			}
			_ = json.NewEncoder(w).Encode(status)
			return
		}
	case "DELETE":
		err = f.manager.DeleteChain(r.Context(), peer, request)
		if err == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": request.EntryNodeID, "session_id": request.SessionID, "stopped": true})
			return
		}
	default:
		http.Error(w, "bad", 400)
		return
	}
	http.Error(w, "rejected", 502)
}

func TestNodeChainExecutionRuntimeComparesExactPathsAndFreshWinner(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "auto")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	progress := f.runtime.Progress()
	if !progress.Ready || !progress.Complete || progress.Execution != "server" || !progress.DNSProven || !progress.PublicProven || len(progress.Prefixes) != 3 || len(progress.Comparison.Measurements) != 2 || progress.Comparison.Final == nil || progress.Comparison.Winner == nil || progress.Comparison.Winner.Execution != routechoice.Server {
		t.Fatal("comparison did not publish complete repeated winner", progress)
	}
	for _, m := range append(progress.Comparison.Measurements, *progress.Comparison.Final) {
		if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != (m.LastNodeMS+m.ExternalMS)/2 {
			t.Fatal("comparison lost required two-probe formula", m)
		}
	}
	if err := f.runtime.HealthyContext(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	requests := append([]struct{ method, session string }(nil), f.requests...)
	f.mu.Unlock()
	var puts, deletes []string
	for _, q := range requests {
		if q.method == "PUT" {
			puts = append(puts, q.session)
		}
		if q.method == "DELETE" {
			deletes = append(deletes, q.session)
		}
	}
	if len(puts) != 2 || puts[0] == puts[1] || len(deletes) != 1 || deletes[0] != puts[0] {
		t.Fatal("winner reused tombstoned trial or skipped its join", puts, deletes)
	}
	f.engine.mu.Lock()
	opens, stops := f.engine.opens, f.engine.stops
	calls := append([]string(nil), f.engine.publicCalls...)
	f.engine.mu.Unlock()
	if opens != 1 || stops != 1 {
		t.Fatal("unproved trial admitted application traffic or dropped stop capability", opens, stops)
	}
	targetHost := strings.Split(strings.TrimPrefix(progress.Comparison.Target, "https://"), "/")[0]
	// Each open has its fixed public proof plus the shared comparison target.
	if len(calls) != 6 {
		t.Fatal("missing trial/winner public proof or repeat probe", calls)
	}
	for _, index := range []int{1, 3, 5} {
		if !strings.HasSuffix(calls[index], "/"+targetHost) {
			t.Fatal("candidates measured different external endpoints", calls)
		}
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	open, stops := f.engine.open, f.engine.stops
	f.engine.mu.Unlock()
	if open || stops != 0 {
		t.Fatal("winner retirement retained forwarding/abandoned cleanup", open, stops)
	}
}

func TestNodeChainExecutionRuntimeServerIsSeparateFromLocalComparison(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	progress := f.runtime.Progress()
	if !progress.Ready || progress.Execution != "server" || len(progress.Comparison.Measurements) != 0 || progress.Comparison.Final == nil {
		t.Fatal("explicit Server silently reran comparison", progress)
	}
	f.engine.mu.Lock()
	dns := append([]string(nil), f.engine.dnsCalls...)
	selections := append([]string(nil), f.engine.selections...)
	f.engine.mu.Unlock()
	proofs, _ := f.runtime.projection.ProofInventory("server")
	if !reflect.DeepEqual(dns, []string{"server"}) || !reflect.DeepEqual(selections, []string{proofs[len(proofs)-1].Tag}) {
		t.Fatal("explicit server tested another selected route", dns, selections)
	}
}

func TestNodeChainExecutionRuntimeRejectsIncompleteLeaseAndProofReceipts(t *testing.T) {
	for _, fault := range []string{"host", "port", "credential", "owner", "source", "dns", "expiry", "bootstrap", "nonce", "sequence", "receipt-dns", "missing-prefix", "pending-traffic", "old-proof", "private-proof", "selected-dns", "public-ip", "epoch-away-back"} {
		t.Run(fault, func(t *testing.T) {
			f := newNodeChainExecutionRuntimeFixture(t, "server")
			f.mutateLease = func(l *multihoprelay.NodeChainLease) {
				switch fault {
				case "host":
					l.Host = "10.80.0.3"
				case "port":
					l.Port++
				case "credential":
					l.Users[0].Password = strings.Repeat("a", 48)
				case "owner":
					l.OwnerID = ""
				case "source":
					l.Request.SourceSHA256 = strings.Repeat("a", 64)
				case "dns":
					l.DNSPolicySHA256 = strings.Repeat("a", 64)
				case "expiry":
					l.ExpiresAt = time.Now().Add(time.Second)
				case "bootstrap":
					l.BootstrapDeadline = time.Now().Add(2 * time.Minute).UTC()
				}
			}
			f.mutateStatus = func(s *multihoprelay.NodeChainLeaseStatus) {
				switch fault {
				case "nonce":
					s.Receipt.Nonce = strings.Repeat("a", 64)
				case "sequence":
					s.Receipt.Sequence = 0
				case "receipt-dns":
					s.Receipt.DNSPolicySHA256 = strings.Repeat("a", 64)
				case "missing-prefix":
					s.Receipt.Prefixes = nil
				case "pending-traffic":
					s.Lease.Phase = multihoprelay.NodeChainPending
					s.Receipt.Phase = multihoprelay.NodeChainPending
					s.Receipt.TrafficAllowed = true
				case "old-proof":
					s.Receipt.ProofAt = time.Now().Add(-time.Hour).UnixMilli()
				}
			}
			switch fault {
			case "private-proof":
				f.engine.wrongPrefix = 1
			case "selected-dns":
				f.engine.failDNS = true
			case "public-ip":
				f.engine.wrongPublic = true
			case "epoch-away-back":
				f.engine.beforeDNS = func(context.Context) { f.engine.mu.Lock(); f.engine.epoch += 2; f.engine.mu.Unlock() }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err == nil {
				t.Fatal("unproved path activated", fault)
			}
			progress := f.runtime.Progress()
			f.engine.mu.Lock()
			open, opens, stops := f.engine.open, f.engine.opens, f.engine.stops
			f.engine.mu.Unlock()
			if progress.Ready || open || opens != 0 || stops != 0 {
				t.Fatal("failure admitted traffic or abandoned original cleanup", progress, open, opens, stops)
			}
			f.mu.Lock()
			var puts, deletes []string
			for _, q := range f.requests {
				if q.method == "PUT" {
					puts = append(puts, q.session)
				}
				if q.method == "DELETE" {
					deletes = append(deletes, q.session)
				}
			}
			f.mu.Unlock()
			if len(puts) != 1 || len(deletes) != 1 || puts[0] != deletes[0] {
				t.Fatal("failed acquisition did not retain exact original deletion", puts, deletes)
			}
		})
	}
}

func TestNodeChainExecutionRuntimeFailedCleanupBlocksEveryNewTrial(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "auto")
	f.runner.failStop.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := f.runtime.Run(ctx)
	if err == nil || !errors.Is(err, routechoice.ErrTeardown) {
		t.Fatal("unjoined server trial did not stop comparison", err)
	}
	f.engine.mu.Lock()
	selections, opens, stops := len(f.engine.selections), f.engine.opens, f.engine.stops
	f.engine.mu.Unlock()
	if selections != 2 || opens != 0 || stops != 1 {
		t.Fatal("failed cleanup started winner or dropped retained authority", selections, opens, stops)
	}
	if err := f.runtime.CloseContext(ctx); err == nil {
		t.Fatal("failed original native server close acknowledged")
	}
	f.runner.failStop.Store(false)
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("same original failed close could not retry", err)
	}
	f.engine.mu.Lock()
	stops = f.engine.stops
	f.engine.mu.Unlock()
	if stops != 0 {
		t.Fatal("joined original server stop capability leaked")
	}
}

func TestNodeChainExecutionRuntimeCancelsEnteredOpenWithoutLateActivation(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	entered, release := make(chan struct{}), make(chan struct{})
	f.engine.beforeOpen = func(context.Context) { close(entered); <-release }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.runtime.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("application admission never entered")
	}
	cancel()
	short, finish := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if err := f.runtime.CloseContext(short); err == nil {
		t.Fatal("entered original Open callback was abandoned")
	}
	finish()
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled activation succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late original activation did not join")
	}
	joined, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := f.runtime.CloseContext(joined); err != nil {
		t.Fatal(err)
	}
	f.engine.mu.Lock()
	open, opens, stops := f.engine.open, f.engine.opens, f.engine.stops
	f.engine.mu.Unlock()
	if open || opens != 0 || stops != 0 {
		t.Fatal("late cancelled callback reopened or lost cleanup", open, opens, stops)
	}
}

func TestNodeChainExecutionRuntimeObservedReplacementRevokesApplication(t *testing.T) {
	for _, field := range []string{"engine", "session", "network", "source", "config", "epoch"} {
		t.Run(field, func(t *testing.T) {
			f := newNodeChainExecutionRuntimeFixture(t, "server")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			f.engine.mu.Lock()
			switch field {
			case "engine":
				f.engine.identity.EngineID = "replacement"
			case "session":
				f.engine.identity.SessionID = "replacement"
			case "network":
				f.engine.identity.NetworkID = "replacement"
			case "source":
				f.engine.identity.SourceSHA256 = strings.Repeat("a", 64)
			case "config":
				f.engine.identity.ConfigSHA256 = strings.Repeat("a", 64)
			case "epoch":
				f.engine.epoch += 2
			}
			f.engine.mu.Unlock()
			if err := f.runtime.HealthyContext(ctx); err == nil {
				t.Fatal("replacement adopted original proof")
			}
			f.engine.mu.Lock()
			open := f.engine.open
			f.engine.mu.Unlock()
			if open || f.runtime.Progress().Ready {
				t.Fatal("observed replacement left application admission open")
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal("original fixed cleanup consulted replacement profile identity", err)
			}
		})
	}
}

func cloneNodeChainExecutionRuntimeEngine(e *nodeChainExecutionRuntimeEngine) *nodeChainExecutionRuntimeEngine {
	e.mu.Lock()
	defer e.mu.Unlock()
	peers := map[string]string{}
	for k, v := range e.peers {
		peers[k] = v
	}
	identity := e.identity
	identity.EngineID = "restored-box"
	identity.SessionID = "restored-session"
	return &nodeChainExecutionRuntimeEngine{projection: e.projection, identity: identity, selected: e.selected, epoch: 1, alive: true, peers: peers, publicPeer: e.publicPeer, wrongPrefix: -1, localDelay: e.localDelay, serverDelay: e.serverDelay}
}

func TestNodeChainExecutionRuntimeRestoreKeepsWinnerAndFreshAttempt(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "auto")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	capture, err := f.runtime.CaptureRestoreContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next := cloneNodeChainExecutionRuntimeEngine(f.engine)
	if _, err := capture.Source(); err == nil {
		t.Fatal("restore handoff preceded positive original cleanup")
	}
	if _, err := NewNodeChainExecutionRestoreRuntime(capture, next); err == nil {
		t.Fatal("restore reused unjoined original owner")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	// Native retirement is a separate platform responsibility in this fixture.
	f.engine.mu.Lock()
	f.engine.alive = false
	f.engine.mu.Unlock()
	source, err := capture.Source()
	if err != nil || source != f.runtime.projection.Source() {
		t.Fatal("restore changed original private source", err)
	}
	restored, err := NewNodeChainExecutionRestoreRuntime(capture, next)
	if err != nil {
		t.Fatal(err)
	}
	restored.testTLS = f.trust
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := restored.CloseContext(stop); err != nil {
			t.Error(err)
		}
	})
	f.mu.Lock()
	before := len(f.requests)
	f.mu.Unlock()
	if err := restored.Run(ctx); err != nil {
		t.Fatal(err)
	}
	progress := restored.Progress()
	if !progress.Ready || progress.Execution != capture.execution || progress.Comparison.Target != capture.result.Target || !reflect.DeepEqual(progress.Comparison.Measurements, capture.result.Measurements) {
		t.Fatal("restore reran comparison or replaced previous choice", progress)
	}
	next.mu.Lock()
	selections := append([]string(nil), next.selections...)
	next.mu.Unlock()
	if len(selections) != 1 {
		t.Fatal("restoration opened new trial candidates", selections)
	}
	f.mu.Lock()
	after := append([]struct{ method, session string }(nil), f.requests[before:]...)
	all := append([]struct{ method, session string }(nil), f.requests[:before]...)
	f.mu.Unlock()
	var session string
	puts := 0
	for _, q := range after {
		if q.method == "PUT" {
			puts++
			session = q.session
		}
	}
	if puts != 1 {
		t.Fatal("restoration created extra trials", after)
	}
	for _, q := range all {
		if q.method == "PUT" && q.session == session {
			t.Fatal("restoration reused a tombstoned acquisition")
		}
	}
	if err := restored.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNodeChainExecutionRuntimeRenewsSameAttemptWithoutRefreshingOldProof(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	f.runtime.mu.Lock()
	active := f.runtime.active
	f.runtime.mu.Unlock()
	active.attempt.mu.Lock()
	firstDeadline, proofAt := active.attempt.deadline, active.attempt.receipt.ProofAt
	request := active.attempt.request.Clone()
	active.attempt.mu.Unlock()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(6 * time.Second):
	}
	if err := f.runtime.HealthyContext(ctx); err != nil {
		t.Fatal(err)
	}
	active.attempt.mu.Lock()
	deadline, nowProofAt := active.attempt.deadline, active.attempt.receipt.ProofAt
	currentRequest := active.attempt.request.Clone()
	active.attempt.mu.Unlock()
	if !deadline.After(firstDeadline) || proofAt != nowProofAt || !reflect.DeepEqual(request, currentRequest) {
		t.Fatal("renewal replaced attempt or refreshed an old original proof timestamp")
	}
	f.runner.mu.Lock()
	workers := len(f.runner.workers)
	f.runner.mu.Unlock()
	if workers != 1 {
		t.Fatal("renewal reopened native server", workers)
	}
}

func TestNodeChainExecutionRuntimeStatusCannotRenewMonotonicLease(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	f.runtime.mu.Lock()
	s := f.runtime.active
	f.runtime.mu.Unlock()
	s.attempt.mu.Lock()
	lease := s.attempt.lease
	// Model an acknowledgement whose retained monotonic deadline is earlier
	// than the expiry now implied by the server's wall-clock timestamp. This
	// can occur after the client's wall clock moves backwards. Moving a Go
	// time with Add alone would move both clocks and would not model this.
	deadline := s.attempt.deadline.Add(-5 * time.Second)
	s.attempt.deadline = deadline
	s.attempt.mu.Unlock()
	if err := s.validateLease(lease, time.Now(), false); err != nil {
		t.Fatal("valid same acknowledgement refused", err)
	}
	s.attempt.mu.Lock()
	same := s.attempt.deadline
	s.attempt.mu.Unlock()
	if same != deadline {
		t.Fatal("status/clock movement prolonged the original monotonic lease")
	}
	lease.ExpiresAt = lease.ExpiresAt.Add(time.Second)
	if err := s.validateLease(lease, time.Now(), false); err == nil {
		t.Fatal("status reply silently renewed the original lease")
	}
}

func TestNodeChainExecutionRuntimeCloseOwnsEnteredInitialObservation(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.engine.beforeObserve = func(context.Context) { once.Do(func() { close(entered); <-release }) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.runtime.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("initial native observation not entered")
	}
	short, finish := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if err := f.runtime.CloseContext(short); err == nil {
		t.Fatal("original initial native callback was abandoned")
	}
	finish()
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("retired initial callback activated")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late initial callback did not join")
	}
	joined, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := f.runtime.CloseContext(joined); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	requests := len(f.requests)
	f.mu.Unlock()
	f.engine.mu.Lock()
	opens := f.engine.opens
	f.engine.mu.Unlock()
	if requests != 0 || opens != 0 {
		t.Fatal("retired initialization acquired or activated", requests, opens)
	}
	if err := f.runtime.Run(joined); err == nil {
		t.Fatal("retired runtime was reused")
	}
}

type nodeChainExecutionErrorStopEngine struct {
	*nodeChainExecutionRuntimeEngine
}

func (e nodeChainExecutionErrorStopEngine) CaptureExecutionStop(ctx context.Context, c NodeChainExecutionStopCapture) (LeaseStop, error) {
	stop, err := e.nodeChainExecutionRuntimeEngine.CaptureExecutionStop(ctx, c)
	if err != nil {
		return stop, err
	}
	return stop, errors.New("native validation failed after cleanup reservation")
}
func TestNodeChainExecutionRuntimeRetainsStopReturnedWithFactoryError(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	f.runtime.engine = nodeChainExecutionErrorStopEngine{f.engine}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err == nil {
		t.Fatal("failed native stop seal allowed acquisition")
	}
	f.mu.Lock()
	requests := len(f.requests)
	f.mu.Unlock()
	f.engine.mu.Lock()
	stops, opens := f.engine.stops, f.engine.opens
	f.engine.mu.Unlock()
	if requests != 0 || stops != 0 || opens != 0 {
		t.Fatal("unused late cleanup capability was lost or PUT ran before sealing", requests, stops, opens)
	}
}
