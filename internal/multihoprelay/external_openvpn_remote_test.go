package multihoprelay

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
)

func externalOpenVPNMappedSource(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	ext, server, _ := externalOpenVPNSource(t, "")
	for _, value := range []map[string]any{ext["openvpn"].(map[string]any), server["openvpn"].(map[string]any)} {
		value["config"] = strings.Replace(value["config"].(string), "203.0.113.20 443", "203.0.113.21 443", 1)
	}
	descriptor, err := ExternalOpenVPNServerDescriptor(server)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(descriptor)
	var public map[string]any
	_ = json.Unmarshal(raw, &public)
	ext["openvpn_pairing"].(map[string]any)["server"] = public
	delete(ext, "response_probe")
	ext["openvpn_response_probes"] = map[string]any{
		"203.0.113.20": map[string]any{"url": "https://203.0.113.20/response", "server_name": "provider.example"},
		"203.0.113.21": map[string]any{"url": "https://203.0.113.21:9443/response", "server_name": "provider.example"},
	}
	return ext, server
}

func externalOpenVPNMappedPair(t *testing.T) (Exit, Exit, Request) {
	t.Helper()
	ext, serverSource := externalOpenVPNMappedSource(t)
	client, err := ExternalSelection("exit", "openvpn", ext, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := PairExternalOpenVPN("exit", ext, serverSource, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := req()
	q.ExitMode = "openvpn"
	q.Port = 26240
	q.Username = strings.Repeat("1", 48)
	q.Password = strings.Repeat("2", 48)
	q, err = AuthenticateExternalRequest(client, q)
	if err != nil {
		t.Fatal(err)
	}
	return client, server, q
}

type openVPNRemoteTestProcess struct {
	alive    atomic.Bool
	failStop atomic.Bool
	receipt  atomic.Pointer[nativeopenvpn.RemoteReceipt]
	read     func()
}

func (p *openVPNRemoteTestProcess) Alive() bool { return p.alive.Load() }
func (p *openVPNRemoteTestProcess) Stop(context.Context) error {
	if p.failStop.Load() {
		return errors.New("owned cleanup pending")
	}
	p.alive.Store(false)
	return nil
}
func (p *openVPNRemoteTestProcess) OpenVPNRemote(ctx context.Context) (nativeopenvpn.RemoteReceipt, error) {
	if p.read != nil {
		p.read()
	}
	receipt := p.receipt.Load()
	if ctx.Err() != nil || receipt == nil || !p.Alive() {
		return nativeopenvpn.RemoteReceipt{}, errors.New("native endpoint not ready")
	}
	return *receipt, nil
}

type openVPNRemoteTestRunner struct {
	process *openVPNRemoteTestProcess
	starts  int
	lease   Lease
	config  []byte
}

func (r *openVPNRemoteTestRunner) Start(_ context.Context, raw []byte, lease Lease) (Process, error) {
	r.starts++
	r.lease = lease
	r.config = append([]byte(nil), raw...)
	r.process = &openVPNRemoteTestProcess{}
	r.process.alive.Store(true)
	return r.process, nil
}

func TestOpenVPNMappedPairRequiresCompleteProofMapAndPreservesLegacyFingerprints(t *testing.T) {
	client, server, q := externalOpenVPNMappedPair(t)
	if !OpenVPNRemoteRequired(client) || !OpenVPNRemoteRequired(server) || ValidateExternalRequest(server, q) != nil {
		t.Fatal("mapped owners lost distinct authenticated identities")
	}
	legacy, _, legacyRequest := externalOpenVPNPair(t, "")
	if legacyRequest.ExternalFingerprint == q.ExternalFingerprint || ValidateExternalRequest(server, legacyRequest) == nil || ValidateExternalRequest(legacy, q) == nil {
		t.Fatal("v4 and v5 ownership domains mixed")
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing host":         func(p map[string]any) { delete(p["openvpn_response_probes"].(map[string]any), "203.0.113.21") },
		"legacy endpoint":      func(p map[string]any) { p["response_probe"] = map[string]any{"url": "https://203.0.113.20/response"} },
		"null legacy endpoint": func(p map[string]any) { p["response_probe"] = nil },
		"foreign host": func(p map[string]any) {
			p["openvpn_response_probes"].(map[string]any)["203.0.113.22"] = map[string]any{"url": "https://203.0.113.22/response"}
		},
		"unmapped layer": func(p map[string]any) { p["start_layer"] = map[string]any{"mode": "aes-256-gcm"} },
		"missing map": func(p map[string]any) {
			delete(p, "openvpn_response_probes")
			p["response_probe"] = map[string]any{"url": "https://203.0.113.20/response"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ext, private := externalOpenVPNMappedSource(t)
			mutate(ext)
			if _, err := ExternalSelection("exit", "openvpn", ext, nil); err == nil {
				t.Fatal("invalid Local/server capture accepted")
			}
			if _, err := PairExternalOpenVPN("exit", ext, private, nil); err == nil {
				t.Fatal("invalid private server registry accepted")
			}
		})
	}
	ext, _ := externalOpenVPNMappedSource(t)
	if err := ValidateExternalOpenVPNResponseProbes("openvpn", ext); err != nil {
		t.Fatal("Local map was rejected", err)
	}
	delete(ext["openvpn_response_probes"].(map[string]any), "203.0.113.21")
	if err := ValidateExternalOpenVPNResponseProbes("openvpn", ext); err == nil {
		t.Fatal("Local map skipped coverage validation")
	}
}

func TestOpenVPNRemoteStatusRequiresExactActiveLeaseNativeOwnerAndConnectedRemote(t *testing.T) {
	client, server, prepared := externalOpenVPNMappedPair(t)
	cfg := config()
	cfg.Exits = []Exit{server}
	runner := &openVPNRemoteTestRunner{}
	manager, err := New(cfg, prepared.EntryNodeID, runner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runner.process.failStop.Store(false); _ = manager.Close(context.Background()) })
	peer := netip.MustParseAddr("10.77.0.2")
	q := challengedExternalFixture(t, manager, client, prepared, peer)
	lease, err := manager.Create(context.Background(), peer, q)
	if err != nil || !lease.OpenVPNRemote || !runner.lease.OpenVPNRemote {
		t.Fatal("runtime was not instructed to own a native receipt", err)
	}
	if _, err := manager.OpenVPNRemote(context.Background(), peer, q); err == nil {
		t.Fatal("listener readiness impersonated a connected OpenVPN remote")
	}
	receipt := nativeopenvpn.RemoteReceipt{Remote: nativeopenvpn.Remote{Host: "203.0.113.21", Port: 443, Network: "tcp"}, Generation: 2, ConnectedAt: time.Now().UnixMilli()}
	runner.process.receipt.Store(&receipt)
	response, err := manager.OpenVPNRemote(context.Background(), peer, q)
	if err != nil || response.Remote != receipt || response.SessionID != q.SessionID || response.ExternalAttempt != q.ExternalAttempt || response.ExternalEpoch != q.ExternalEpoch || response.ExternalFingerprint != q.ExternalFingerprint {
		t.Fatal("exact second-remote receipt lost ownership", err)
	}
	raw, _ := json.Marshal(response)
	for _, secret := range []string{q.Password, q.Username, q.ExternalAuthentication, server.External.OpenVPN.PrivateKey, server.External.OpenVPN.Profile.Username, server.External.OpenVPN.Profile.Password, "provider_identity", "client_certificate"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private runtime details leaked from status")
		}
	}
	for name, mutate := range map[string]func(*Request){
		"session":     func(q *Request) { q.SessionID = strings.Repeat("f", 32) },
		"attempt":     func(q *Request) { q.ExternalAttempt = strings.Repeat("e", 32) },
		"epoch":       func(q *Request) { q.ExternalEpoch = strings.Repeat("d", 32) },
		"fingerprint": func(q *Request) { q.ExternalFingerprint = strings.Repeat("a", 64) },
		"credentials": func(q *Request) { q.Password = strings.Repeat("f", 48) },
	} {
		t.Run(name, func(t *testing.T) {
			other := q
			mutate(&other)
			if _, err := manager.OpenVPNRemote(context.Background(), peer, other); err == nil {
				t.Fatal("wrong lease acquired runtime observation")
			}
		})
	}
	if _, err := manager.OpenVPNRemote(context.Background(), netip.MustParseAddr("10.77.0.3"), q); err == nil {
		t.Fatal("other tunnel peer read owned status")
	}
	wrong := receipt
	wrong.Network = "udp"
	runner.process.receipt.Store(&wrong)
	if _, err := manager.OpenVPNRemote(context.Background(), peer, q); err == nil {
		t.Fatal("remote protocol mismatch accepted")
	}
	runner.process.receipt.Store(&receipt)
	ctx, cancel := context.WithCancel(context.Background())
	runner.process.read = cancel
	if _, err := manager.OpenVPNRemote(ctx, peer, q); err == nil {
		t.Fatal("cancelled remote read published")
	}
	runner.process.read = nil
	runner.process.failStop.Store(true)
	if manager.Delete(context.Background(), peer, q) == nil {
		t.Fatal("fixture did not retain failed cleanup")
	}
	if _, err := manager.OpenVPNRemote(context.Background(), peer, q); err == nil {
		t.Fatal("retired but still-live process returned an eligible remote")
	}
	runner.process.failStop.Store(false)
	if manager.Delete(context.Background(), peer, q) != nil {
		t.Fatal("owned cleanup failed")
	}
	if _, err := manager.OpenVPNRemote(context.Background(), peer, q); err == nil {
		t.Fatal("deleted receipt replayed")
	}
}

func TestOpenVPNMappedLeaseRejectsUnobservableNativeRunner(t *testing.T) {
	client, server, prepared := externalOpenVPNMappedPair(t)
	cfg := config()
	cfg.Exits = []Exit{server}
	runner := &runner{}
	manager, err := New(cfg, prepared.EntryNodeID, runner)
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("10.77.0.2")
	q := challengedExternalFixture(t, manager, client, prepared, peer)
	if _, err := manager.Create(context.Background(), peer, q); err == nil || len(runner.processes) != 1 || runner.processes[0].Alive() {
		t.Fatal("old native runner advertised multi-host support or leaked its lease")
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
