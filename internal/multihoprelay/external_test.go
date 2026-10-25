package multihoprelay

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func externalFixture(t *testing.T) (Config, Request) {
	t.Helper()
	cfg := config()
	cfg.Exits[0].NodeID, cfg.Exits[0].DNS = "", ""
	cfg.Exits[0].External = &ExternalExit{ExpectedPublicIP: "203.0.113.88", ResponseProbe: ResponseProbe{URL: "https://192.0.2.2/status", ServerName: "exit.example"}}
	request := req()
	request.Port, request.Username, request.Password = 26240, strings.Repeat("1", 48), strings.Repeat("2", 48)
	request, err := AuthenticateExternalRequest(cfg.Exits[0], request)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, request
}

func challengedExternalFixture(t *testing.T, m *Manager, exit Exit, q Request, peer netip.Addr) Request {
	t.Helper()
	challenge, err := m.PacketChallenge(peer)
	if err != nil {
		t.Fatal(err)
	}
	q, err = ChallengeExternalRequest(exit, q, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestExternalRelayRetainsTypedIdentityPrivateCredentialsAndOwnedLifecycle(t *testing.T) {
	cfg, request := externalFixture(t)
	runner := &runner{}
	m, err := New(cfg, request.EntryNodeID, runner)
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := json.Marshal(Capabilities{NodeID: request.EntryNodeID, Execution: "server", Exits: []Capability{{ID: request.ExitID, Mode: request.ExitMode, ExternalFingerprint: request.ExternalFingerprint, ExpectedPublicIP: cfg.Exits[0].External.ExpectedPublicIP}}})
	var caps Capabilities
	if json.Unmarshal(catalog, &caps) != nil || caps.Validate(request.EntryNodeID) != nil {
		t.Fatal("typed external catalog rejected")
	}
	available, _ := json.Marshal(m.Available())
	if strings.Contains(string(available), cfg.Exits[0].Transport["password"].(string)) || strings.Contains(string(available), request.ExternalAuthentication) {
		t.Fatal("private credential/proof entered catalog")
	}
	peer := netip.MustParseAddr("10.77.0.2")
	request = challengedExternalFixture(t, m, cfg.Exits[0], request, peer)
	lease, err := m.Create(context.Background(), peer, request)
	if err != nil || lease.ExitNodeID != "" || lease.ExternalFingerprint != request.ExternalFingerprint || lease.Request != request {
		t.Fatal("external relay identity/owner changed", err)
	}
	var graph map[string]any
	if json.Unmarshal(runner.configs[0], &graph) != nil {
		t.Fatal("bad graph")
	}
	if graph["dns"] != nil || graph["endpoints"] != nil || graph["services"] != nil {
		t.Fatal("invented external DNS or system tunnel")
	}
	route := graph["route"].(map[string]any)
	rules := route["rules"].([]any)
	if len(rules) != 2 || rules[1].(map[string]any)["action"] != "reject" || rules[1].(map[string]any)["domain_regex"].([]any)[0] != "." || route["default_domain_resolver"] != nil {
		t.Fatal("relay may override captured client DNS")
	}
	if again, err := m.Create(context.Background(), peer, request); err != nil || again.Password != lease.Password || runner.starts != 1 {
		t.Fatal("external renewal recreated owner", err)
	}
	wrong := request
	wrong.SessionID = strings.Repeat("c", 32)
	if m.Delete(context.Background(), peer, wrong) == nil || !runner.processes[0].alive {
		t.Fatal("foreign session closed external relay")
	}
	runner.processes[0].stopFail = true
	if m.Delete(context.Background(), peer, request) == nil || len(m.leases) != 1 {
		t.Fatal("unconfirmed external cleanup lost owner")
	}
	runner.processes[0].stopFail = false
	if m.Delete(context.Background(), peer, request) != nil || len(m.leases) != 0 {
		t.Fatal("owned external cleanup failed")
	}
}

func TestExternalRelayRejectsCredentialOrGraphSubstitutionBeforeStarting(t *testing.T) {
	for name, change := range map[string]func(*Request){
		"bare Router request": func(q *Request) { q.ExternalFingerprint, q.ExternalAuthentication = "", "" },
		"wrong fingerprint":   func(q *Request) { q.ExternalFingerprint = strings.Repeat("e", 64) },
		"wrong credentials":   func(q *Request) { q.ExternalAuthentication = strings.Repeat("e", 64) },
		"different session":   func(q *Request) { q.SessionID = strings.Repeat("f", 32) },
		"different listener":  func(q *Request) { q.Password = strings.Repeat("f", 48) },
		"different port":      func(q *Request) { q.Port++ },
		"different exit":      func(q *Request) { q.ExitID = "other" },
		"extra layer":         func(q *Request) { q.ExitStartLayer = "aes-256-gcm" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, q := externalFixture(t)
			r := &runner{}
			m, err := New(cfg, req().EntryNodeID, r)
			if err != nil {
				t.Fatal(err)
			}
			q = challengedExternalFixture(t, m, cfg.Exits[0], q, netip.MustParseAddr("10.77.0.2"))
			change(&q)
			if _, err = m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err == nil || r.starts != 0 {
				t.Fatal("changed capture started external relay")
			}
		})
	}
	cfg, q := externalFixture(t)
	original := cfg.Exits[0]
	original.Transport, _ = copyMap(original.Transport)
	cfg.Exits[0].Transport["password"] = "BBBBBBBBBBBBBBBBBBBBBB=="
	r := &runner{}
	m, err := New(cfg, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	q = challengedExternalFixture(t, m, original, q, netip.MustParseAddr("10.77.0.2"))
	if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err == nil || r.starts != 0 {
		t.Fatal("same endpoint substituted another password")
	}
}

func TestExternalCatalogFingerprintCannotBecomeAPasswordVerifier(t *testing.T) {
	cfg, first := externalFixture(t)
	exit := cfg.Exits[0]
	before, err := ExternalFingerprint(exit)
	if err != nil {
		t.Fatal(err)
	}
	exit.Transport["password"] = "BBBBBBBBBBBBBBBBBBBBBB=="
	after, err := ExternalFingerprint(exit)
	if err != nil || after != before {
		t.Fatal("public catalog fingerprint includes private credential material", err)
	}
	second, err := AuthenticateExternalRequest(exit, first)
	if err != nil || second.ExternalAuthentication == first.ExternalAuthentication || ValidateExternalRequest(exit, first) == nil {
		t.Fatal("private request failed to bind the exact captured credential", err)
	}
}

func TestExternalRelayCannotImpersonateRouterOrUseUnsupportedPolicy(t *testing.T) {
	for name, change := range map[string]func(*Exit){
		"Router identity":      func(e *Exit) { e.NodeID = strings.Repeat("b", 64) },
		"DNS override":         func(e *Exit) { e.DNS = "8.8.8.8" },
		"private egress":       func(e *Exit) { e.External.ExpectedPublicIP = "192.168.50.1" },
		"private listener":     func(e *Exit) { e.Transport["server"] = "192.168.50.1" },
		"hostname listener":    func(e *Exit) { e.Transport["server"] = "exit.example" },
		"opaque transport":     func(e *Exit) { e.Transport["udp_over_tcp"] = true },
		"unsupported UDP exit": func(e *Exit) { e.Mode = "hysteria2" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := externalFixture(t)
			change(&cfg.Exits[0])
			if _, err := New(cfg, req().EntryNodeID, &runner{}); err == nil {
				t.Fatal("invalid external registry accepted")
			}
		})
	}
	cfg, q := externalFixture(t)
	m, err := New(cfg, req().EntryNodeID, &runner{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.now = func() time.Time { return now }
	q = challengedExternalFixture(t, m, cfg.Exits[0], q, netip.MustParseAddr("10.77.0.2"))
	if _, err := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err != nil {
		t.Fatal(err)
	}
	now = now.Add(16 * time.Second)
	if m.Sweep(context.Background()) != nil || len(m.leases) != 0 {
		t.Fatal("external expiry lost its bounded cleanup")
	}
}
