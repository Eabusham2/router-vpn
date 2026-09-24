package multihoprelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type process struct {
	alive    bool
	stopFail bool
	stops    int
}

func (p *process) Alive() bool { return p.alive }
func (p *process) Stop(ctx context.Context) error {
	p.stops++
	if p.stopFail {
		return errors.New("not stopped")
	}
	p.alive = false
	return nil
}

type runner struct {
	starts    int
	configs   [][]byte
	processes []*process
	fail      bool
}

func (r *runner) Start(ctx context.Context, b []byte, l Lease) (Process, error) {
	r.starts++
	r.configs = append(r.configs, b)
	p := &process{alive: true}
	r.processes = append(r.processes, p)
	if r.fail {
		return p, errors.New("private key must not escape")
	}
	return p, nil
}
func config() Config {
	return Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26241, TTLSeconds: 15, Exits: []Exit{{ID: "exit", Mode: "shadowsocks", DNS: "10.77.0.1", NodeID: strings.Repeat("b", 64), Transport: map[string]any{"type": "shadowsocks", "server": "192.0.2.2", "server_port": 8388, "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}}}}
}
func req() Request {
	return Request{SessionID: strings.Repeat("a", 32), EntryNodeID: strings.Repeat("a", 64), ExitID: "exit", ExitMode: "shadowsocks"}
}
func manager(t *testing.T) (*Manager, *runner) {
	t.Helper()
	r := &runner{}
	m, e := New(config(), req().EntryNodeID, r)
	if e != nil {
		t.Fatal(e)
	}
	return m, r
}
func TestLeaseOwnsRealServerPlan(t *testing.T) {
	m, r := manager(t)
	peer := netip.MustParseAddr("10.77.0.2")
	l, e := m.Create(context.Background(), peer, req())
	if e != nil {
		t.Fatal(e)
	}
	if l.Port != 26240 || len(l.Password) < 32 || l.Password == l.Username || l.NodeID != req().EntryNodeID {
		t.Fatal("invalid private lease")
	}
	var cfg map[string]any
	if json.Unmarshal(r.configs[0], &cfg) != nil {
		t.Fatal("invalid plan")
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["listen"] != "10.77.0.1" || in["type"] != "socks" || len(in["users"].([]any)) != 1 {
		t.Fatal("unowned/public listener")
	}
	rule := cfg["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["source_ip_cidr"].([]any)[0] != "10.77.0.2/32" || rule["invert"] != true || rule["action"] != "reject" {
		t.Fatal("peer isolation missing")
	}
	if len(cfg["outbounds"].([]any)) != 1 || cfg["endpoints"] != nil || cfg["services"] != nil {
		t.Fatal("extra dataplane")
	}
}
func TestRenewIdempotentAndTeardownOwned(t *testing.T) {
	m, r := manager(t)
	peer := netip.MustParseAddr("10.77.0.2")
	a, e := m.Create(context.Background(), peer, req())
	if e != nil {
		t.Fatal(e)
	}
	b, e := m.Create(context.Background(), peer, req())
	if e != nil || a.Password != b.Password || r.starts != 1 {
		t.Fatal("renewal changed engine")
	}
	other := req()
	other.SessionID = strings.Repeat("c", 32)
	if _, e = m.Create(context.Background(), peer, other); !errors.Is(e, ErrBusy) {
		t.Fatal("overlap accepted")
	}
	if e = m.Delete(context.Background(), peer, other); !errors.Is(e, ErrOwnership) || !r.processes[0].alive {
		t.Fatal("foreign deletion")
	}
	if e = m.Delete(context.Background(), peer, req()); e != nil || r.processes[0].alive {
		t.Fatal("owned delete failed")
	}
	if e = m.Delete(context.Background(), peer, req()); e != nil {
		t.Fatal("idempotent delete failed")
	}
}
func TestDistinctPeersSeparateCredentialsAndPorts(t *testing.T) {
	m, _ := manager(t)
	a, _ := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), req())
	b, _ := m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), req())
	if a.Port == b.Port || a.Password == b.Password {
		t.Fatal("sessions share ownership")
	}
	if _, e := m.Create(context.Background(), netip.MustParseAddr("10.77.0.4"), req()); e == nil {
		t.Fatal("pool overflow")
	}
}
func TestExpiredLeaseStopsEvenWithoutClient(t *testing.T) {
	m, r := manager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	_, e := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), req())
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(16 * time.Second)
	if e = m.Sweep(context.Background()); e != nil || r.processes[0].alive || len(m.leases) != 0 {
		t.Fatal("expired relay survived")
	}
}
func TestFailedCleanupNeverReusesPort(t *testing.T) {
	m, r := manager(t)
	p := netip.MustParseAddr("10.77.0.2")
	_, _ = m.Create(context.Background(), p, req())
	r.processes[0].stopFail = true
	if e := m.Delete(context.Background(), p, req()); e == nil || len(m.leases) != 1 {
		t.Fatal("lost ownership")
	}
	q := req()
	q.SessionID = strings.Repeat("c", 32)
	if _, e := m.Create(context.Background(), p, q); !errors.Is(e, ErrBusy) {
		t.Fatal("overlapping relay")
	}
}
func TestStartupFailureIsCleaned(t *testing.T) {
	m, r := manager(t)
	r.fail = true
	if _, e := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), req()); e == nil || strings.Contains(e.Error(), "private key") {
		t.Fatal("bad error")
	}
	if r.processes[0].alive || len(m.leases) != 0 {
		t.Fatal("failed engine leaked")
	}
}
func TestBadRequestsDoNotStartEngine(t *testing.T) {
	for _, mutate := range []func(*Request){func(q *Request) { q.SessionID = "bad" }, func(q *Request) { q.EntryNodeID = strings.Repeat("c", 64) }, func(q *Request) { q.ExitID = "../exit" }, func(q *Request) { q.ExitMode = "direct" }} {
		m, r := manager(t)
		q := req()
		mutate(&q)
		if _, e := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); e == nil || r.starts != 0 {
			t.Fatal("invalid request starts engine")
		}
	}
}
func TestRejectPublicAndWildcardListeners(t *testing.T) {
	for _, ip := range []string{"0.0.0.0", "::", "127.0.0.1", "8.8.8.8", "example.com", "fe80::1%eth0"} {
		c := config()
		c.ListenIP = ip
		if _, e := New(c, req().EntryNodeID, &runner{}); e == nil {
			t.Fatal(ip)
		}
	}
}
func TestUnsupportedOrWeakenedTransportRejected(t *testing.T) {
	for _, fn := range []func(map[string]any){func(p map[string]any) { p["type"] = "direct" }, func(p map[string]any) { p["server"] = "127.0.0.1" }, func(p map[string]any) { p["method"] = "none" }, func(p map[string]any) { p["detour"] = "escape" }, func(p map[string]any) { p["bind_interface"] = "wan" }, func(p map[string]any) { p["password"] = "" }, func(p map[string]any) { p["server_port"] = 1.5 }} {
		c := config()
		fn(c.Exits[0].Transport)
		if _, e := New(c, req().EntryNodeID, &runner{}); e == nil {
			t.Fatal("unsafe transport")
		}
	}
}
func TestConfigCopiedAndNoSecretCapabilities(t *testing.T) {
	c := config()
	r := &runner{}
	m, e := New(c, req().EntryNodeID, r)
	if e != nil {
		t.Fatal(e)
	}
	c.Exits[0].Transport["server"] = "127.0.0.1"
	_, e = m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), req())
	if e != nil {
		t.Fatal("config mutation changed plan")
	}
	data, _ := json.Marshal(m.Available())
	if strings.Contains(string(data), "password") {
		t.Fatal("secret capabilities")
	}
	if e = m.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), req()); !errors.Is(e, ErrUnavailable) {
		t.Fatal("closed manager reopens")
	}
}

func TestRelayDNSCannotFallbackToEntryResolver(t *testing.T) {
	m, r := manager(t)
	if _, e := m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), req()); e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if e := json.Unmarshal(r.configs[0], &v); e != nil {
		t.Fatal(e)
	}
	dns := v["dns"].(map[string]any)
	resolver := dns["servers"].([]any)[0].(map[string]any)
	if resolver["detour"] != "exit" || dns["final"] != "exit-dns" || v["route"].(map[string]any)["default_domain_resolver"] != "exit-dns" {
		t.Fatal("exit DNS route lost")
	}
}
func TestRelayRejectsUnownedTransportCapabilities(t *testing.T) {
	for _, field := range []string{"plugin", "plugin_opts", "certificate_path", "detour", "system", "bind_interface", "made_up_setting"} {
		c := config()
		c.Exits[0].Transport[field] = "forbidden"
		if _, e := New(c, req().EntryNodeID, &runner{}); e == nil {
			t.Fatal(field)
		}
	}
	c := config()
	c.Exits[0].Mode = "hysteria2"
	c.Exits[0].Transport = map[string]any{"type": "hysteria2", "server": "192.0.2.2", "server_port": 443, "password": "fixture-only", "tls": map[string]any{"enabled": true, "certificate_path": "/private/host/file"}}
	if _, e := New(c, req().EntryNodeID, &runner{}); e == nil {
		t.Fatal("host certificate file permitted")
	}
}
func TestWireGuardClientKeyCannotRoamBetweenRelayProcesses(t *testing.T) {
	c := config()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	c.Exits[0].Mode = "wg"
	c.Exits[0].Transport = map[string]any{"type": "wireguard", "private_key": key, "address": []string{"10.78.0.2/32"}, "peers": []any{map[string]any{"address": "192.0.2.2", "port": 51820, "public_key": key, "allowed_ips": []string{"0.0.0.0/0", "::/0"}}}}
	m, e := New(c, req().EntryNodeID, &runner{})
	if e != nil {
		t.Fatal(e)
	}
	q := req()
	q.ExitMode = "wg"
	if _, e = m.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), q); e == nil {
		t.Fatal("concurrent key reuse accepted")
	}
	if e = m.Delete(context.Background(), netip.MustParseAddr("10.77.0.2"), q); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Create(context.Background(), netip.MustParseAddr("10.77.0.3"), q); e != nil {
		t.Fatal(e)
	}
}
