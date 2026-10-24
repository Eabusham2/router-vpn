package mobilemultihop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func externalExecutionFixture(t *testing.T, selection string) (string, string) {
	t.Helper()
	return externalExecutionProtocolFixture(t, "shadowsocks", selection, "")
}

func TestExternalExecutionCapturePreservesPolicyAndRestoresProvedWinner(t *testing.T) {
	for _, selection := range []string{"local", "server", "auto"} {
		for _, restored := range []string{"", "local", "server"} {
			source, capture := externalExecutionFixture(t, selection)
			prepared, err := PrepareExternalExecutionCapture(source, capture, restored)
			if restored != "" && selection != "auto" && restored != selection {
				if err == nil {
					t.Fatal("restore changed explicit selection")
				}
				continue
			}
			if err != nil {
				t.Fatal(selection, restored, err)
			}
			policy, err := NewExternalPolicy(source, prepared)
			if err != nil {
				t.Fatal(err)
			}
			again, err := NewExternalPolicy(source, prepared)
			if err != nil || again.Config() != policy.Config() || again.Metadata() != policy.Metadata() {
				t.Fatal("capture is not deterministic", err)
			}
			if selection == "local" && restored == "" {
				if prepared != capture || policy.capture.Execution != nil {
					t.Fatal("ordinary Local regressed")
				}
				continue
			}
			graph := externalTestRead(t, policy.Config())
			selector := externalTestFind(t, graph, ExternalFinalTag)
			local := externalTestFind(t, graph, LocalTag)
			server := externalTestFind(t, graph, ServerTag)
			if selector["type"] != "selector" || local["type"] != "shadowsocks" || local["detour"] != "entry-wg" || server["detour"] != "entry-wg" || (graph["route"].(map[string]any))["final"] != ExternalFinalTag {
				t.Fatal("candidate route lost its native owner")
			}
			if policy.capture.Profile["multihop_execution"] != selection {
				t.Fatal("runtime restoration mutated saved Compare")
			}
			want := selection
			if restored != "" {
				want = restored
			}
			if policy.capture.Execution.Selection != want {
				t.Fatal("restored runtime reran Compare")
			}
			if strings.Contains(policy.Metadata(), policy.capture.Execution.Request.Password) || strings.Contains(policy.Metadata(), policy.capture.Execution.Request.ExternalAuthentication) {
				t.Fatal("metadata exposed private lease proof")
			}
		}
	}
}

func TestExternalExecutionRejectsChangedProofSourceAndLease(t *testing.T) {
	source, capture := externalExecutionFixture(t, "auto")
	prepared, err := PrepareExternalExecutionCapture(source, capture, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]any){
		"different credentials": func(c map[string]any) {
			c["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)["password"] = "changed"
		},
		"different node response": func(c map[string]any) {
			c["profile"].(map[string]any)["external"].(map[string]any)["response_probe"].(map[string]any)["url"] = "https://1.1.1.1/node-response"
		},
		"private node response": func(c map[string]any) {
			c["profile"].(map[string]any)["external"].(map[string]any)["response_probe"].(map[string]any)["url"] = "https://192.168.50.1/node-response"
		},
		"no TLS node response": func(c map[string]any) {
			c["profile"].(map[string]any)["external"].(map[string]any)["response_probe"].(map[string]any)["url"] = "http://203.0.113.20/node-response"
		},
		"no node response": func(c map[string]any) {
			delete(c["profile"].(map[string]any)["external"].(map[string]any), "response_probe")
		},
		"different listener": func(c map[string]any) {
			c["execution"].(map[string]any)["request"].(map[string]any)["listener_password"] = strings.Repeat("f", 48)
		},
		"different entry": func(c map[string]any) {
			c["execution"].(map[string]any)["request"].(map[string]any)["entry_node_id"] = strings.Repeat("f", 64)
		},
		"other execution": func(c map[string]any) { c["execution"].(map[string]any)["selection"] = "invented" },
		"missing owner":   func(c map[string]any) { delete(c, "execution") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := externalTestRead(t, prepared)
			change(changed)
			if _, err := NewExternalPolicy(source, externalTestJSON(t, changed)); err == nil {
				t.Fatal("changed capture accepted")
			}
		})
	}
	if _, err := PrepareExternalExecutionCapture(source, prepared, ""); err == nil {
		t.Fatal("existing lease proposal reused as fresh connection")
	}
}

type externalExecutionProcess struct {
	mu       sync.Mutex
	alive    bool
	failStop bool
}

func (p *externalExecutionProcess) Alive() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.alive }
func (p *externalExecutionProcess) Stop(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failStop {
		return errors.New("test close blocked")
	}
	p.alive = false
	return nil
}

type externalExecutionRunner struct {
	mu        sync.Mutex
	processes []*externalExecutionProcess
}

func (r *externalExecutionRunner) Start(_ context.Context, _ []byte, _ multihoprelay.Lease) (multihoprelay.Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := &externalExecutionProcess{alive: true}
	r.processes = append(r.processes, p)
	return p, nil
}

type externalExecutionEngine struct {
	mu                         sync.Mutex
	identity, selected         string
	policy                     *ExternalPolicy
	manager                    *multihoprelay.Manager
	runner                     *externalExecutionRunner
	entry                      *httptest.Server
	public, node               map[string]*httptest.Server
	nodeCalls, dnsCalls        map[string]int
	probeTargets               map[string][]string
	badDNS, badPublic, badNode map[string]bool
	closeFailure               bool
	errors                     []string
	trust                      *tls.Config
}

func (e *externalExecutionEngine) Identity() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.identity
}
func (e *externalExecutionEngine) Selected() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.selected
}
func (e *externalExecutionEngine) Select(tag string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.identity == "" {
		return errors.New("retired")
	}
	e.selected = tag
	return nil
}
func (e *externalExecutionEngine) DNSProof(ctx context.Context, tag string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if tag != "tun-in" || ctx.Err() != nil || e.identity == "" {
		return errors.New("wrong owner")
	}
	e.dnsCalls[e.selected]++
	if e.badDNS[e.selected] {
		return errors.New("selected DNS failed")
	}
	return nil
}
func (e *externalExecutionEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	e.mu.Lock()
	if tag == ExternalFinalTag {
		tag = e.selected
	}
	identity := e.identity
	e.mu.Unlock()
	if identity == "" {
		return nil, errors.New("retired")
	}
	var server *httptest.Server
	if tag == e.policy.capture.EntryTag {
		if address != "10.77.0.1:8787" {
			return nil, errors.New("wrong control destination")
		}
		server = e.entry
	} else if address == "203.0.113.20:443" {
		server = e.node[tag]
	} else if address == "1.1.1.1:80" || address == "1.0.0.1:80" {
		server = e.public[tag]
	}
	if server == nil {
		return nil, errors.New("unowned test route")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
}

func newExternalExecutionEngine(t *testing.T, policy *ExternalPolicy) *externalExecutionEngine {
	t.Helper()
	exit, err := externalRelaySelection(policy.capture)
	if err != nil {
		t.Fatal(err)
	}
	runner := &externalExecutionRunner{}
	m, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26271, TTLSeconds: 90, Exits: []multihoprelay.Exit{exit}}, policy.capture.Execution.Request.EntryNodeID, runner)
	if err != nil {
		t.Fatal(err)
	}
	e := &externalExecutionEngine{identity: "one-external-box", selected: LocalTag, policy: policy, manager: m, runner: runner, public: map[string]*httptest.Server{}, node: map[string]*httptest.Server{}, nodeCalls: map[string]int{}, dnsCalls: map[string]int{}, probeTargets: map[string][]string{}, badDNS: map[string]bool{}, badPublic: map[string]bool{}, badNode: map[string]bool{}}
	e.entry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer captured-entry-token" {
			w.WriteHeader(403)
			return
		}
		node := policy.capture.Execution.Request.EntryNodeID
		if r.URL.Path == "/health" {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": node, "proof": "router-vpn-private-agent-v1"})
			return
		}
		if r.URL.Path != "/api/multihop/lease" {
			w.WriteHeader(404)
			return
		}
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": node, "execution": "server", "exits": m.Available()})
			return
		}
		var q multihoprelay.Request
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			w.WriteHeader(400)
			return
		}
		peer := netip.MustParseAddr("10.77.0.2")
		if r.Method == "PUT" {
			lease, err := m.Create(r.Context(), peer, q)
			if err != nil {
				w.WriteHeader(409)
				return
			}
			_ = json.NewEncoder(w).Encode(lease)
			return
		}
		e.mu.Lock()
		fail := e.closeFailure
		e.mu.Unlock()
		if fail {
			w.WriteHeader(500)
			return
		}
		if err := m.Delete(r.Context(), peer, q); err != nil {
			w.WriteHeader(409)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"node_id": node, "session_id": q.SessionID, "stopped": true})
	}))
	t.Cleanup(e.entry.Close)
	pool := x509.NewCertPool()
	for _, tag := range []string{LocalTag, ServerTag} {
		tag := tag
		e.node[tag] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.mu.Lock()
			e.nodeCalls[tag]++
			bad := e.badNode[tag]
			if r.Host != "example.com" || r.TLS == nil || r.TLS.ServerName != "example.com" {
				e.errors = append(e.errors, "captured HTTPS virtual host or TLS identity changed")
			}
			if r.Header.Get("Authorization") != "" {
				e.errors = append(e.errors, "private token leaked")
			}
			e.mu.Unlock()
			if tag == LocalTag {
				time.Sleep(20 * time.Millisecond)
			}
			if bad {
				w.WriteHeader(503)
				return
			}
			_, _ = w.Write([]byte("owned node response"))
		}))
		pool.AddCert(e.node[tag].Certificate())
		t.Cleanup(e.node[tag].Close)
		e.public[tag] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.mu.Lock()
			e.probeTargets[tag] = append(e.probeTargets[tag], r.Host+r.URL.Path)
			bad := e.badPublic[tag]
			if r.Header.Get("Authorization") != "" {
				e.errors = append(e.errors, "private token leaked")
			}
			e.mu.Unlock()
			if tag == LocalTag {
				time.Sleep(10 * time.Millisecond)
			}
			ip := policy.capture.ExpectedPublicIP
			if bad {
				ip = "203.0.113.99"
			}
			_, _ = w.Write([]byte("ip=" + ip + "\n"))
		}))
		t.Cleanup(e.public[tag].Close)
	}
	e.trust = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	return e
}

func externalExecutionRequest(t *testing.T, selection, restored string) (*ExternalProofRequest, *externalExecutionEngine) {
	t.Helper()
	source, capture := externalExecutionFixture(t, selection)
	return externalExecutionCapturedRequest(t, source, capture, restored)
}

func externalExecutionCapturedRequest(t *testing.T, source, capture, restored string) (*ExternalProofRequest, *externalExecutionEngine) {
	t.Helper()
	prepared, err := PrepareExternalExecutionCapture(source, capture, restored)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewExternalPolicy(source, prepared)
	if err != nil {
		t.Fatal(err)
	}
	e := newExternalExecutionEngine(t, policy)
	r, err := NewExternalProofRequest(context.Background(), policy, "owned-session", e)
	if err != nil {
		t.Fatal(err)
	}
	r.execution.externalResponseTLS = e.trust
	// Production echo origins remain verified HTTPS. This loopback routing fixture
	// tests real request/response/ownership through each captured candidate.
	r.public = func(ctx context.Context, tag, expected string) error {
		body, err := externalProofHTTP(ctx, e.Dial, tag, Targets[0], "", nil)
		if err != nil {
			return err
		}
		return externalTraceAddress(body, expected)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, e
}

func TestExternalExecutionRunsOwnedLeaseExactScoreRepeatAndPolicyProof(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public-a", "http://1.0.0.1/public-b"}
	defer func() { Targets = previous }()
	r, e := externalExecutionRequest(t, "auto", "")
	result, err := r.Run()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Healthy() || r.Execution() != "server" || e.Selected() != ServerTag {
		t.Fatal("proved lower server score not retained", result, r.ProgressJSON())
	}
	var progress Progress
	if json.Unmarshal([]byte(r.ProgressJSON()), &progress) != nil || len(progress.Measurements) != 2 || progress.LastNodeMeasurement != "https-response-time" {
		t.Fatal("missing truthful comparison", r.ProgressJSON())
	}
	for _, m := range progress.Measurements {
		if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != m.LastNodeMS/2+m.ExternalMS/2 {
			t.Fatal("exact average changed")
		}
	}
	if e.nodeCalls[ServerTag] < 2 || e.nodeCalls[LocalTag] != 1 || e.dnsCalls[LocalTag] < 1 || e.dnsCalls[ServerTag] < 2 || len(e.errors) > 0 {
		t.Fatal("missing repeat winner or independent policy proof", e.nodeCalls, e.dnsCalls, e.errors)
	}
	// Each trial independently proves its public exit at public-a, then probes
	// the selected random target. The final winner repeats both operations.
	local, server := e.probeTargets[LocalTag], e.probeTargets[ServerTag]
	if len(local) != 2 || len(server) != 5 || local[0] != "1.1.1.1/public-a" || local[1] != server[1] || server[1] != server[3] {
		t.Fatal("comparison or winner repeat changed the common endpoint", e.probeTargets)
	}
	e.mu.Lock()
	e.closeFailure = true
	e.mu.Unlock()
	if r.Close() == nil || r.Healthy() {
		t.Fatal("failed lease cleanup claimed success")
	}
	e.mu.Lock()
	e.closeFailure = false
	e.mu.Unlock()
	if r.Close() != nil {
		t.Fatal("retained owned cleanup could not retry")
	}
	for _, p := range e.runner.processes {
		if p.Alive() {
			t.Fatal("external lease engine retained after confirmed close")
		}
	}
}
func TestExternalExecutionRestoresWinnerWithoutAnotherComparison(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public"}
	defer func() { Targets = previous }()
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			r, e := externalExecutionRequest(t, "auto", winner)
			if _, err := r.Run(); err != nil {
				t.Fatal(err)
			}
			if r.Execution() != winner || len(e.nodeCalls) != 1 {
				t.Fatal("restoration compared other runtime", e.nodeCalls)
			}
			if r.policy.capture.Profile["multihop_execution"] != "auto" {
				t.Fatal("saved Compare changed")
			}
		})
	}
}

func TestExternalExecutionFinalProofCannotPublishChangedSelectionLeaseOrCancellation(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public"}
	defer func() { Targets = previous }()
	for _, change := range []string{"selector", "lease-expired", "cancel"} {
		t.Run(change, func(t *testing.T) {
			r, e := externalExecutionRequest(t, "server", "")
			proof := r.public
			r.public = func(ctx context.Context, tag, expected string) error {
				if err := proof(ctx, tag, expected); err != nil {
					return err
				}
				switch change {
				case "selector":
					_ = e.Select(LocalTag)
				case "lease-expired":
					expired := time.Now().Add(-time.Second)
					r.execution.leaseDeadline.Store(&expired)
				case "cancel":
					r.Cancel()
				}
				return nil
			}
			if raw, err := r.Run(); err == nil || raw != "" || r.Healthy() || r.Execution() != "" {
				t.Fatal("stale final proof published an execution receipt")
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExternalExecutionCloseWaitsForLateProofBeforeReleasingNativeOwner(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public"}
	defer func() { Targets = previous }()
	r, e := externalExecutionRequest(t, "server", "")
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.private = func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release // A late native callback must still retain this exact owner.
		return ctx.Err()
	}
	ran := make(chan error, 1)
	go func() { _, err := r.Run(); ran <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("final captured proof did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel captured proof")
	}
	if r.Healthy() || r.Execution() != "" {
		t.Fatal("canceled owner retained success")
	}
	select {
	case err := <-closed:
		t.Fatal("Close overtook the retained final callback", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-ran; err == nil {
		t.Fatal("late proof published after Close")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	for _, p := range e.runner.processes {
		if p.Alive() {
			t.Fatal("canceled proof leaked its private lease")
		}
	}
	if _, err := r.Run(); err == nil {
		t.Fatal("closed proof owner reused")
	}
}

func TestExternalExecutionEditorValidatorRejectsAmbiguousOrUnboundedInput(t *testing.T) {
	valid := `{"url":"https://203.0.113.20/response","server_name":"node.example"}`
	if err := ValidateExternalResponseProbe("203.0.113.20", valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"url":"https://203.0.113.20/response","url":"https://203.0.113.20/other"}`, `{"url":"https://203.0.113.20/response","insecure":true}`, `{"url":null}`, `null`, valid + valid, strings.Repeat(" ", 4097)} {
		if err := ValidateExternalResponseProbe("203.0.113.20", raw); err == nil {
			t.Fatal("ambiguous comparison endpoint accepted")
		}
	}
}

func TestExternalExecutionFreshCaptureRejectsNonScalarIdentities(t *testing.T) {
	source, capture := externalExecutionFixture(t, "auto")
	for _, malformed := range []any{map[string]any{"id": "nested"}, []any{"nested"}, nil, true, 42} {
		value := externalTestRead(t, capture)
		value["entry"].(map[string]any)["id"] = malformed
		value["profile"].(map[string]any)["multihop_entry_id"] = malformed
		if _, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, value), ""); err == nil {
			t.Fatal("non-scalar captured entry identity accepted")
		}
	}
}

func TestExternalExecutionFailedLastNodeDNSOrExitGetsNoScore(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public"}
	defer func() { Targets = previous }()
	for _, protocol := range externalExecutionProtocols {
		for _, failure := range []string{"node-response", "dns", "exit", "tls"} {
			t.Run(protocol+"/"+failure, func(t *testing.T) {
				source, capture := externalExecutionProtocolFixture(t, protocol, "auto", "aes-256-gcm+xor-whitening")
				r, e := externalExecutionCapturedRequest(t, source, capture, "")
				switch failure {
				case "node-response":
					e.badNode[ServerTag] = true
				case "dns":
					e.badDNS[ServerTag] = true
				case "exit":
					e.badPublic[ServerTag] = true
				case "tls":
					r.execution.externalResponseTLS = &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
				}
				_, err := r.Run()
				if failure == "tls" {
					if err == nil || r.Healthy() || r.Execution() != "" {
						t.Fatal("unverified TLS node endpoint won")
					}
				} else if err != nil || r.Execution() != "local" {
					t.Fatal("valid local not retained after rejected server", err, r.ProgressJSON())
				}
				var p Progress
				if json.Unmarshal([]byte(r.ProgressJSON()), &p) != nil || len(p.Measurements) != 2 {
					t.Fatal("rejected candidates lost their truthful progress record")
				}
				for _, m := range p.Measurements {
					if (m.Candidate.Execution == "server" || failure == "tls") && (m.Eligible || m.ScoreMS != nil) {
						t.Fatal("failed candidate received a score")
					}
				}
			})
		}
	}
}
