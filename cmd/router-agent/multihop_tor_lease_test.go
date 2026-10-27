package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/multihoprelay"
)

type torHTTPWorker struct {
	capture  multihoprelay.TorCapture
	alive    atomic.Bool
	ready    atomic.Bool
	sequence atomic.Uint64
	release  chan struct{}
}

func (p *torHTTPWorker) Alive() bool                { return p.alive.Load() }
func (p *torHTTPWorker) Stop(context.Context) error { p.alive.Store(false); return nil }
func (p *torHTTPWorker) Bootstrap(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.release:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p.ready.Store(true)
		return nil
	}
}
func (p *torHTTPWorker) Snapshot(ctx context.Context, nonce string) (multihoprelay.TorReceipt, error) {
	c, now := p.capture, time.Now().UnixMilli()
	r := multihoprelay.TorReceipt{Schema: 1, SessionID: c.Request.SessionID, OwnerID: c.OwnerID, Peer: c.Peer, SourceSHA256: c.Source.SourceSHA256,
		RegistrySHA256: c.RegistrySHA256, DNSPolicySHA256: c.Source.DNSPolicySHA256, FrontSHA256: c.FrontSHA256(), Nonce: nonce,
		Sequence: p.sequence.Add(1), HeartbeatAt: now, Phase: multihoprelay.TorPending, Bootstrap: 50, FrontReady: true}
	if p.ready.Load() {
		r.Phase, r.Bootstrap, r.TrafficAllowed = multihoprelay.TorReady, 100, true
		r.ExitIP, r.IsTor, r.DNSProven, r.ProofAt = "203.0.113.40", true, true, now
	}
	return r, nil
}

type torHTTPRunner struct {
	mu      sync.Mutex
	workers []*torHTTPWorker
	fail    bool
}

func (r *torHTTPRunner) Start(context.Context, []byte, multihoprelay.Lease) (multihoprelay.Process, error) {
	return nil, errors.New("ordinary route was not expected")
}
func (r *torHTTPRunner) StartTor(ctx context.Context, c multihoprelay.TorCapture) (multihoprelay.TorProcess, error) {
	if r.fail {
		return nil, errors.New("private imported bridge credential must not escape")
	}
	p := &torHTTPWorker{capture: c, release: make(chan struct{})}
	p.alive.Store(true)
	r.mu.Lock()
	r.workers = append(r.workers, p)
	r.mu.Unlock()
	return p, nil
}
func torHTTPFixture(t *testing.T, runner multihoprelay.Runner) (*server, *http.ServeMux, multihoprelay.TorRequest) {
	t.Helper()
	node := strings.Repeat("a", 64)
	source := multihoprelay.TorExitSource{ID: "paired-tor", Mode: "tor-bridge", SourceSHA256: strings.Repeat("b", 64), DNSPolicySHA256: strings.Repeat("c", 64)}
	m, err := multihoprelay.New(multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26242, TTLSeconds: 300, TorExits: []multihoprelay.TorExitSource{source}}, node, runner)
	if err != nil {
		t.Fatal(err)
	}
	_, subnet, _ := net.ParseCIDR("10.77.0.0/24")
	s := &server{cfg: cfg{Token: "private-agent-token", NodeID: node}, nets: []*net.IPNet{subnet}, relay: m}
	mux := http.NewServeMux()
	registerMultihopRelayRoute(mux, s)
	challenge, err := m.PacketChallenge(netip.MustParseAddr("10.77.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	q := multihoprelay.TorRequest{SessionID: strings.Repeat("d", 32), EntryNodeID: node, ExitID: source.ID, ExitMode: source.Mode, SourceSHA256: source.SourceSHA256, DNSPolicySHA256: source.DNSPolicySHA256,
		Epoch: challenge.Epoch, Peer: challenge.Peer, AcquireExpiresAt: challenge.ExpiresAt}
	return s, mux, q
}
func torHTTPBody(t *testing.T, q multihoprelay.TorRequest, nonce string) string {
	t.Helper()
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if nonce == "" {
		return string(raw)
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("invalid request fixture")
	}
	fields["status_nonce"] = nonce
	raw, _ = json.Marshal(fields)
	return string(raw)
}
func torHTTPCall(mux *http.ServeMux, method, peer, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, multihopTorLeasePath, strings.NewReader(body))
	r.RemoteAddr = peer
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Forwarded-For", "10.77.0.2")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestTorHTTPProductionWorkerAbsentAndUnadvertised(t *testing.T) {
	s, mux, q := torHTTPFixture(t, relayExecRunner{})
	defer s.relay.Close(context.Background())
	w := torHTTPCall(mux, http.MethodPut, "10.77.0.2:1234", s.cfg.Token, torHTTPBody(t, q, ""))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "password") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("production without a Tor worker accepted or leaked the source", w.Code, w.Body.String())
	}
	if w := torHTTPCall(mux, http.MethodGet, "10.77.0.2:1234", s.cfg.Token, ""); w.Code != http.StatusServiceUnavailable {
		t.Fatal("production without a Tor worker advertised acquisition", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, multihopRelayPath, nil)
	r.RemoteAddr = "10.77.0.2:1234"
	r.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "paired-tor") || strings.Contains(w.Body.String(), "tor-bridge") {
		t.Fatal("legacy capability catalog advertised the unimplemented worker", w.Body.String())
	}
}

func TestTorHTTPDiscoveryContainsOnlyAuthenticatedDetachedSourceReferences(t *testing.T) {
	runner := &torHTTPRunner{}
	s, mux, q := torHTTPFixture(t, runner)
	defer s.relay.Close(context.Background())
	for _, test := range []struct{ peer, token string }{{"10.77.0.2:1234", ""}, {"10.77.0.2:1234", "wrong"}, {"203.0.113.2:1234", s.cfg.Token}} {
		w := torHTTPCall(mux, http.MethodGet, test.peer, test.token, "")
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), q.SourceSHA256) || strings.Contains(w.Body.String(), q.ExitID) {
			t.Fatal("unauthenticated or forwarded peer read source discovery", w.Code, w.Body.String())
		}
	}
	w := torHTTPCall(mux, http.MethodGet, "10.77.0.2:1234", s.cfg.Token, "")
	var response map[string]json.RawMessage
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response) != 3 ||
		w.Header().Get("Cache-Control") != "no-store" || len(runner.workers) != 0 {
		t.Fatal("source discovery acquired traffic or returned an invalid envelope", w.Code, w.Body.String())
	}
	var node string
	var challenge multihoprelay.ExternalPacketChallenge
	var references []map[string]string
	if json.Unmarshal(response["node_id"], &node) != nil || node != q.EntryNodeID ||
		json.Unmarshal(response["challenge"], &challenge) != nil || challenge.Validate() != nil || challenge.Peer != q.Peer || challenge.Epoch != q.Epoch ||
		json.Unmarshal(response["sources"], &references) != nil || len(references) != 1 || len(references[0]) != 4 {
		t.Fatal("discovery lost exact node/challenge/source ownership", w.Body.String())
	}
	want := map[string]string{"id": q.ExitID, "mode": q.ExitMode, "source_sha256": q.SourceSHA256, "dns_policy_sha256": q.DNSPolicySHA256}
	for key, value := range want {
		if references[0][key] != value {
			t.Fatal("discovery exposed an unrelated or private source field", key, w.Body.String())
		}
	}
	if err := s.relay.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	w = torHTTPCall(mux, http.MethodGet, "10.77.0.2:1234", s.cfg.Token, "")
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), q.SourceSHA256) {
		t.Fatal("closed manager still exposed an acquirable source", w.Code, w.Body.String())
	}
}

func TestTorHTTPLeasePendingReadyAndExactOwnedDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runner := &torHTTPRunner{}
		s, mux, q := torHTTPFixture(t, runner)
		defer s.relay.Close(context.Background())
		body := torHTTPBody(t, q, "")
		for _, test := range []struct{ peer, token string }{{"10.77.0.2:1234", ""}, {"10.77.0.2:1234", "wrong"}, {"203.0.113.2:1234", s.cfg.Token}} {
			if w := torHTTPCall(mux, http.MethodPut, test.peer, test.token, body); w.Code != http.StatusForbidden {
				t.Fatal("token or actual tunnel peer was bypassed", w.Code)
			}
		}
		challengeResponse := torHTTPCall(mux, http.MethodGet, "10.77.0.2:1234", s.cfg.Token, "")
		var issued struct {
			NodeID    string                                `json:"node_id"`
			Challenge multihoprelay.ExternalPacketChallenge `json:"challenge"`
		}
		if challengeResponse.Code != http.StatusOK || json.Unmarshal(challengeResponse.Body.Bytes(), &issued) != nil || issued.NodeID != q.EntryNodeID || issued.Challenge.Epoch != q.Epoch || issued.Challenge.Peer != q.Peer || issued.Challenge.ExpiresAt != q.AcquireExpiresAt {
			t.Fatal("actual HTTP challenge did not bind the observed peer and manager")
		}
		w := torHTTPCall(mux, http.MethodPut, "10.77.0.2:1234", s.cfg.Token, body)
		var lease multihoprelay.TorLease
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &lease) != nil || lease.Phase != multihoprelay.TorPending || lease.Request != q || lease.OwnerID == "" {
			t.Fatal("actual HTTP manager seam did not return its owned pending lease", w.Code, w.Body.String())
		}
		challenge := strings.Repeat("e", 64)
		w = torHTTPCall(mux, http.MethodPost, "10.77.0.2:1234", s.cfg.Token, torHTTPBody(t, q, challenge))
		var status multihoprelay.TorLeaseStatus
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Receipt.Nonce != challenge || status.Receipt.TrafficAllowed || status.Receipt.IsTor || status.Receipt.DNSProven {
			t.Fatal("pending status invented or reused proof", w.Code, w.Body.String())
		}
		runner.mu.Lock()
		worker := runner.workers[0]
		runner.mu.Unlock()
		close(worker.release)
		synctest.Wait()
		w = torHTTPCall(mux, http.MethodPost, "10.77.0.2:1234", s.cfg.Token, torHTTPBody(t, q, strings.Repeat("f", 64)))
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Lease.Phase != multihoprelay.TorReady || !status.Receipt.DNSProven || !status.Receipt.IsTor {
			t.Fatal("proved worker did not become ready at the actual HTTP seam", w.Code, w.Body.String())
		}
		if w := torHTTPCall(mux, http.MethodPost, "10.77.0.3:1234", s.cfg.Token, torHTTPBody(t, q, challenge)); w.Code != http.StatusForbidden {
			t.Fatal("other authenticated tunnel peer read this session", w.Code)
		}
		wrong := q
		wrong.SessionID = strings.Repeat("f", 32)
		if w := torHTTPCall(mux, http.MethodDelete, "10.77.0.2:1234", s.cfg.Token, torHTTPBody(t, wrong, "")); w.Code != http.StatusForbidden || !worker.Alive() {
			t.Fatal("wrong session stopped owned Tor", w.Code)
		}
		w = torHTTPCall(mux, http.MethodDelete, "10.77.0.2:1234", s.cfg.Token, body)
		if w.Code != http.StatusOK || worker.Alive() || !strings.Contains(w.Body.String(), `"stopped":true`) {
			t.Fatal("owned HTTP delete did not join the worker", w.Code, w.Body.String())
		}
		if w := torHTTPCall(mux, http.MethodPut, "10.77.0.2:1234", s.cfg.Token, body); w.Code != http.StatusForbidden {
			t.Fatal("late HTTP PUT resurrected a deleted attempt", w.Code)
		}
	})
}

func TestTorHTTPStrictRequestCannotUploadNativeConfig(t *testing.T) {
	s, mux, q := torHTTPFixture(t, relayExecRunner{})
	defer s.relay.Close(context.Background())
	valid := torHTTPBody(t, q, "")
	for _, body := range []string{
		valid + `{}`, `[]`, `{}`, strings.Replace(valid, `"exit_id":"paired-tor"`, `"exit_id":"paired-tor","exit_id":"other"`, 1),
		strings.Replace(valid, `"exit_id":"paired-tor"`, `"exit_id":null`, 1),
		strings.TrimSuffix(valid, "}") + `,"command":"tor --unsafe"}`,
		strings.TrimSuffix(valid, "}") + `,"torrc":"DisableNetwork 0"}`,
		strings.TrimSuffix(valid, "}") + `,"expected_public_ip":"203.0.113.4"}`,
		strings.TrimSuffix(valid, "}") + `,"listen_port":26240}`,
		strings.TrimSuffix(valid, "}") + `,"status_nonce":"` + strings.Repeat("e", 64) + `"}`,
		strings.Replace(valid, q.DNSPolicySHA256, "", 1),
		strings.TrimSuffix(valid, "}") + `,"oversized":"` + strings.Repeat("x", 4096) + `"}`,
	} {
		if w := torHTTPCall(mux, http.MethodPut, "10.77.0.2:1234", s.cfg.Token, body); w.Code != http.StatusBadRequest {
			t.Fatal("malformed or arbitrary native input reached manager", w.Code)
		}
	}
	if w := torHTTPCall(mux, http.MethodPost, "10.77.0.2:1234", s.cfg.Token, valid); w.Code != http.StatusBadRequest {
		t.Fatal("status accepted without a fresh caller nonce", w.Code)
	}
}

func TestTorHTTPNativeStartupErrorDoesNotLeakPrivateSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, mux, q := torHTTPFixture(t, &torHTTPRunner{fail: true})
		defer s.relay.Close(context.Background())
		w := torHTTPCall(mux, http.MethodPut, "10.77.0.2:1234", s.cfg.Token, torHTTPBody(t, q, ""))
		if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "credential") || strings.Contains(w.Body.String(), "bridge") {
			t.Fatal("failed startup became an acquired lease or exposed worker secrets", w.Code, w.Body.String())
		}
	})
}
