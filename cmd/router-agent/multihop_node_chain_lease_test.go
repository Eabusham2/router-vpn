//go:build go1.25

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/multihoprelay"
)

type chainHTTPWorker struct {
	capture                multihoprelay.NodeChainCapture
	alive, ready, failStop atomic.Bool
	sequence               atomic.Uint64
	proofAt                atomic.Int64
	release                chan struct{}
}

func (p *chainHTTPWorker) Alive() bool { return p.alive.Load() }
func (p *chainHTTPWorker) Stop(context.Context) error {
	if p.failStop.Load() {
		return errors.New("original native close pending")
	}
	p.alive.Store(false)
	return nil
}
func (p *chainHTTPWorker) Bootstrap(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.release:
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.proofAt.Store(time.Now().UnixMilli())
	p.ready.Store(true)
	return nil
}
func (p *chainHTTPWorker) Snapshot(ctx context.Context, nonce string) (multihoprelay.NodeChainReceipt, error) {
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
	return r, nil
}

type chainHTTPRunner struct {
	mu      sync.Mutex
	workers []*chainHTTPWorker
	fail    bool
}

func (r *chainHTTPRunner) Start(context.Context, []byte, multihoprelay.Lease) (multihoprelay.Process, error) {
	return nil, errors.New("ordinary fallback is forbidden")
}
func (r *chainHTTPRunner) StartChain(ctx context.Context, c multihoprelay.NodeChainCapture) (multihoprelay.NodeChainProcess, error) {
	if r.fail {
		return nil, errors.New("private operator token must not escape")
	}
	p := &chainHTTPWorker{capture: c.Clone(), release: make(chan struct{})}
	p.alive.Store(true)
	r.mu.Lock()
	r.workers = append(r.workers, p)
	r.mu.Unlock()
	return p, nil
}
func chainHTTPFixture(t *testing.T, runner multihoprelay.Runner) (*server, *http.ServeMux, multihoprelay.NodeChainRequest) {
	t.Helper()
	capture := chainPipeCapture(t)
	manager, err := multihoprelay.New(multihoprelay.Config{ListenIP: capture.Host, FirstPort: 28440, LastPort: 28442, TTLSeconds: 300, NodeChains: []multihoprelay.NodeChainDescriptor{capture.Source}}, capture.Request.EntryNodeID, runner)
	if err != nil {
		t.Fatal(err)
	}
	_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
	s := &server{cfg: cfg{Token: "private-agent-token", NodeID: capture.Request.EntryNodeID}, nets: []*net.IPNet{subnet}, relay: manager}
	mux := http.NewServeMux()
	registerMultihopRelayRoute(mux, s)
	challenge, err := manager.PacketChallenge(netip.MustParseAddr(capture.Peer))
	if err != nil {
		t.Fatal(err)
	}
	q := capture.Request.Clone()
	q.Port = 28441
	q.Epoch, q.Peer, q.AcquireExpiresAt = challenge.Epoch, challenge.Peer, challenge.ExpiresAt
	return s, mux, q
}
func chainHTTPBody(t *testing.T, q multihoprelay.NodeChainRequest, nonce string) string {
	t.Helper()
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if nonce == "" {
		return string(raw)
	}
	return string(raw[:len(raw)-1]) + `,"status_nonce":"` + nonce + `"}`
}
func chainHTTPCall(mux *http.ServeMux, method, peer, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, multihopNodeChainLeasePath, strings.NewReader(body))
	r.RemoteAddr = peer
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Forwarded-For", "10.77.0.2")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}
func TestNodeChainHTTPAbsentWorkerNeverAdvertises(t *testing.T) {
	s, mux, q := chainHTTPFixture(t, relayExecRunner{})
	defer s.relay.Close(context.Background())
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete} {
		nonce := ""
		if method == http.MethodPost {
			nonce = strings.Repeat("a", 64)
		}
		w := chainHTTPCall(mux, method, "10.77.0.2:1234", s.cfg.Token, chainHTTPBody(t, q, nonce))
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), q.SourceSHA256) {
			t.Fatal("absent native worker advertised or accepted ordered source", method, w.Code, w.Body.String())
		}
	}
}
func TestNodeChainHTTPAuthenticatedExactConfiguredDiscovery(t *testing.T) {
	s, mux, q := chainHTTPFixture(t, &chainHTTPRunner{})
	defer s.relay.Close(context.Background())
	for _, test := range []struct{ peer, token string }{{"10.77.0.2:1234", ""}, {"10.77.0.2:1234", "wrong"}, {"203.0.113.2:1234", s.cfg.Token}} {
		w := chainHTTPCall(mux, http.MethodGet, test.peer, test.token, "")
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), q.SourceSHA256) {
			t.Fatal("untrusted/forwarded peer read original source", w.Code)
		}
	}
	w := chainHTTPCall(mux, http.MethodGet, "10.77.0.2:1234", s.cfg.Token, "")
	var result struct {
		NodeID      string                                `json:"node_id"`
		Challenge   multihoprelay.ExternalPacketChallenge `json:"challenge"`
		Sources     []multihoprelay.NodeChainDescriptor   `json:"sources"`
		First, Last int
	}
	var fields map[string]json.RawMessage
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || json.Unmarshal(w.Body.Bytes(), &fields) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	_ = json.Unmarshal(fields["first_port"], &result.First)
	_ = json.Unmarshal(fields["last_port"], &result.Last)
	if len(fields) != 5 || result.First != 28440 || result.Last != 28442 || result.NodeID != q.EntryNodeID || result.Challenge.Epoch != q.Epoch || result.Challenge.Peer != q.Peer || len(result.Sources) != 1 {
		t.Fatal("GET lost original configured authority", w.Body.String())
	}
	for _, private := range []string{"api_token", "private_key", q.Users[0].Password, q.Users[0].Username} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("GET exposed private source/credentials")
		}
	}
}
func TestNodeChainHTTPPendingProofOriginalDeleteAndRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runner := &chainHTTPRunner{}
		s, mux, q := chainHTTPFixture(t, runner)
		defer s.relay.Close(context.Background())
		body := chainHTTPBody(t, q, "")
		w := chainHTTPCall(mux, http.MethodPut, "10.77.0.2:1234", s.cfg.Token, body)
		var lease multihoprelay.NodeChainLease
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &lease) != nil || lease.Phase != multihoprelay.NodeChainPending || !reflect.DeepEqual(lease.Request, q) || lease.Port != q.Port {
			t.Fatal("original pending lease changed proposal", w.Code, w.Body.String())
		}
		nonce := strings.Repeat("e", 64)
		w = chainHTTPCall(mux, http.MethodPost, "10.77.0.2:1234", s.cfg.Token, chainHTTPBody(t, q, nonce))
		var status multihoprelay.NodeChainLeaseStatus
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Receipt.Nonce != nonce || status.Receipt.TrafficAllowed || status.Receipt.ProofAt != 0 {
			t.Fatal("pending listener became traffic/proof", w.Code, w.Body.String())
		}
		runner.mu.Lock()
		worker := runner.workers[0]
		runner.mu.Unlock()
		close(worker.release)
		synctest.Wait()
		w = chainHTTPCall(mux, http.MethodPost, "10.77.0.2:1234", s.cfg.Token, chainHTTPBody(t, q, strings.Repeat("f", 64)))
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Lease.Phase != multihoprelay.NodeChainReady || !status.Receipt.DNSProven || len(status.Receipt.Prefixes) != 1 {
			t.Fatal("whole original proof missing", w.Code, w.Body.String())
		}
		wrong := q.Clone()
		wrong.Users[0].Password = strings.Repeat("f", 48)
		if w := chainHTTPCall(mux, http.MethodDelete, "10.77.0.2:1234", s.cfg.Token, chainHTTPBody(t, wrong, "")); w.Code != http.StatusForbidden || !worker.Alive() {
			t.Fatal("foreign credentials retired original lease", w.Code)
		}
		if w := chainHTTPCall(mux, http.MethodPost, "10.77.0.3:1234", s.cfg.Token, chainHTTPBody(t, q, nonce)); w.Code != http.StatusForbidden {
			t.Fatal("other tunnel peer read original source", w.Code)
		}
		worker.failStop.Store(true)
		w = chainHTTPCall(mux, http.MethodDelete, "10.77.0.2:1234", s.cfg.Token, body)
		if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), `"stopped":true`) || !worker.Alive() {
			t.Fatal("pending actual native close was acknowledged", w.Code, w.Body.String())
		}
		worker.failStop.Store(false)
		w = chainHTTPCall(mux, http.MethodDelete, "10.77.0.2:1234", s.cfg.Token, body)
		if w.Code != http.StatusOK || worker.Alive() || !strings.Contains(w.Body.String(), `"stopped":true`) {
			t.Fatal("exact retained original close could not retry", w.Code, w.Body.String())
		}
		if w := chainHTTPCall(mux, http.MethodPut, "10.77.0.2:1234", s.cfg.Token, body); w.Code != http.StatusForbidden {
			t.Fatal("late PUT resurrected retired attempt", w.Code)
		}
	})
}
func TestNodeChainHTTPStrictRequestDoesNotUploadNativeSource(t *testing.T) {
	runner := &chainHTTPRunner{}
	s, mux, q := chainHTTPFixture(t, runner)
	defer s.relay.Close(context.Background())
	body := chainHTTPBody(t, q, "")
	tests := map[string]string{"private-upload": body[:len(body)-1] + `,"config":"private-native-config"}`, "duplicate-port": strings.Replace(body, `"listen_port":28441`, `"listen_port":28441,"listen_port":28441`, 1), "case-alias": strings.Replace(body, `"session_id"`, `"Session_ID"`, 1), "null-users": strings.Replace(body, `"users":[`, `"users":null,"ignored":[`, 1), "missing-port": strings.Replace(body, `"listen_port":28441,`, "", 1), "status-on-put": chainHTTPBody(t, q, strings.Repeat("e", 64)), "oversize": body + strings.Repeat(" ", 4096)}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			w := chainHTTPCall(mux, http.MethodPut, "10.77.0.2:1234", s.cfg.Token, raw)
			if w.Code != http.StatusBadRequest {
				t.Fatal("ambiguous/private upload reached Manager", w.Code, w.Body.String())
			}
		})
	}
	runner.mu.Lock()
	started := len(runner.workers)
	runner.mu.Unlock()
	if started != 0 {
		t.Fatal("bad HTTP source started native worker")
	}
}
