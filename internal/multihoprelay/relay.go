// Package multihoprelay manages isolated, private, server-owned exit engines.
// It never edits a default route, firewall policy or another client's session.
package multihoprelay

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ident = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var nonce = regexp.MustCompile(`^[0-9a-f]{32}$`)
var listenerSecret = regexp.MustCompile(`^[0-9a-f]{48}$`)
var proofID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ErrUnavailable = errors.New("requested server-side exit is not provisioned")
var ErrOwnership = errors.New("relay lease does not belong to this peer and session")
var ErrBusy = errors.New("this peer already owns another relay session")

type Exit struct {
	ID     string `json:"id"`
	Mode   string `json:"mode"`
	NodeID string `json:"node_id"`
	DNS    string `json:"dns_server"`
	// Operator-owned, private configuration. A client request never supplies
	// arbitrary sing-box configuration, executable paths or remote credentials.
	Transport map[string]any `json:"transport"`
}
type Config struct {
	ListenIP   string `json:"listen_ip"`
	FirstPort  int    `json:"first_port"`
	LastPort   int    `json:"last_port"`
	TTLSeconds int    `json:"ttl_seconds"`
	Exits      []Exit `json:"exits"`
}
type Request struct {
	SessionID   string `json:"session_id"`
	EntryNodeID string `json:"entry_node_id"`
	ExitID      string `json:"exit_id"`
	ExitMode    string `json:"exit_mode"`
	// Optional client-generated listener proposal allows the client to prepare
	// its final graph before acquiring a lease, without restarting its TUN.
	Port     int    `json:"listen_port,omitempty"`
	Username string `json:"listener_username,omitempty"`
	Password string `json:"listener_password,omitempty"`
}
type Lease struct {
	Request
	NodeID     string    `json:"node_id"`
	ExitNodeID string    `json:"exit_node_id"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Username   string    `json:"username"`
	Password   string    `json:"password"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type Process interface {
	Alive() bool
	Stop(context.Context) error
}

// Start returns only after the owned engine has bound its authenticated
// listener. The process must outlive the start request but not its lease.
type Runner interface {
	Start(context.Context, []byte, Lease) (Process, error)
}
type live struct {
	Lease
	peer netip.Addr
	p    Process
}
type Manager struct {
	mu     sync.Mutex
	cfg    Config
	node   string
	runner Runner
	leases map[string]*live
	now    func() time.Time
	closed bool
}

func New(c Config, node string, r Runner) (*Manager, error) {
	ip, err := netip.ParseAddr(c.ListenIP)
	if err != nil || ip.Zone() != "" || !ip.IsPrivate() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return nil, errors.New("relay listener must be a literal private tunnel IP")
	}
	c.ListenIP = ip.Unmap().String()
	if !proofID.MatchString(node) || r == nil || c.FirstPort < 1024 || c.LastPort > 65535 || c.LastPort < c.FirstPort || c.LastPort-c.FirstPort > 63 {
		return nil, errors.New("invalid relay identity, runner or bounded port pool")
	}
	if c.TTLSeconds == 0 {
		c.TTLSeconds = 90
	}
	if c.TTLSeconds < 15 || c.TTLSeconds > 300 || len(c.Exits) > 64 {
		return nil, errors.New("relay TTL or exit limit is invalid")
	}
	seen := map[string]bool{}
	for _, e := range c.Exits {
		if !ident.MatchString(e.ID) || !proofID.MatchString(e.NodeID) || e.NodeID == node || seen[e.ID+"/"+e.Mode] {
			return nil, errors.New("relay exits require distinct paired identities and unique modes")
		}
		if _, err := validateTransport(e); err != nil {
			return nil, err
		}
		seen[e.ID+"/"+e.Mode] = true
	}
	// Copy the supplied private configuration so callers cannot mutate live plans.
	raw, _ := json.Marshal(c)
	var frozen Config
	if err := json.Unmarshal(raw, &frozen); err != nil {
		return nil, err
	}
	return &Manager{cfg: frozen, node: node, runner: r, leases: map[string]*live{}, now: time.Now}, nil
}
func PeerKey(peer netip.Addr) string { return peer.Unmap().String() }
func (m *Manager) Available() []map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []map[string]string{}
	for _, e := range m.cfg.Exits {
		item := map[string]string{"exit_id": e.ID, "exit_mode": e.Mode, "exit_node_id": e.NodeID}
		if e.Mode == "wg" {
			if text, ok := e.Transport["private_key"].(string); ok {
				raw, err := base64.StdEncoding.Strict().DecodeString(text)
				if err == nil {
					if key, err := ecdh.X25519().NewPrivateKey(raw); err == nil {
						item["client_public_key"] = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
					}
				}
			}
		}
		out = append(out, item)
	}
	return out
}
func (m *Manager) validate(peer netip.Addr, q Request) error {
	if !peer.IsValid() || peer.Zone() != "" || peer.IsUnspecified() || !nonce.MatchString(q.SessionID) || q.EntryNodeID != m.node || !ident.MatchString(q.ExitID) {
		return ErrOwnership
	}
	if q.Port != 0 || q.Username != "" || q.Password != "" {
		if q.Port < m.cfg.FirstPort || q.Port > m.cfg.LastPort ||
			!listenerSecret.MatchString(q.Username) || !listenerSecret.MatchString(q.Password) || q.Username == q.Password {
			return ErrOwnership
		}
	}
	return nil
}
func secret() (string, error) {
	b := make([]byte, 24)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func (m *Manager) Create(ctx context.Context, peer netip.Addr, q Request) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Lease{}, ErrUnavailable
	}
	if err := m.validate(peer, q); err != nil {
		return Lease{}, err
	}
	if err := m.reapLocked(ctx); err != nil {
		return Lease{}, err
	}
	key := PeerKey(peer)
	if old := m.leases[key]; old != nil {
		if old.Request != q {
			return Lease{}, ErrBusy
		}
		if !old.p.Alive() {
			return Lease{}, errors.New("relay engine is not alive")
		}
		old.ExpiresAt = m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)
		return old.Lease, nil
	}
	var exit *Exit
	for i := range m.cfg.Exits {
		e := &m.cfg.Exits[i]
		if e.ID == q.ExitID && e.Mode == q.ExitMode {
			exit = e
			break
		}
	}
	if exit == nil {
		return Lease{}, ErrUnavailable
	}
	if exit.Mode == "wg" {
		// A WireGuard peer key identifies one roaming endpoint. Two independent
		// processes using that key would steal each other's reply endpoint.
		for _, active := range m.leases {
			if active.ExitMode != "wg" {
				continue
			}
			for _, paired := range m.cfg.Exits {
				if paired.ID == active.ExitID && paired.Mode == "wg" && paired.Transport["private_key"] == exit.Transport["private_key"] {
					return Lease{}, errors.New("paired WireGuard credentials already own another relay; provision distinct client credentials for concurrent use")
				}
			}
		}
	}
	used := map[int]bool{}
	for _, s := range m.leases {
		used[s.Port] = true
	}
	port := q.Port
	if port != 0 && used[port] {
		return Lease{}, ErrBusy
	}
	for p := m.cfg.FirstPort; p <= m.cfg.LastPort; p++ {
		if port == 0 && !used[p] {
			port = p
			break
		}
	}
	if port == 0 {
		return Lease{}, errors.New("server relay session limit reached")
	}
	username, err := secret()
	if err != nil {
		return Lease{}, err
	}
	password, err := secret()
	if err != nil {
		return Lease{}, err
	}
	if q.Port != 0 {
		username, password = q.Username, q.Password
	}
	lease := Lease{Request: q, NodeID: m.node, ExitNodeID: exit.NodeID, Host: m.cfg.ListenIP, Port: port, Username: username, Password: password, ExpiresAt: m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)}
	config, err := Build(*exit, peer, lease)
	if err != nil {
		return Lease{}, err
	}
	process, err := m.runner.Start(ctx, config, lease)
	if err != nil || process == nil || ctx.Err() != nil || !process.Alive() {
		if process != nil {
			// Retain ownership on cleanup failure. Its port must not be reused.
			m.leases[key] = &live{Lease: lease, peer: peer, p: process}
			if clean := m.stopLocked(context.Background(), key); clean != nil {
				return Lease{}, clean
			}
		}
		return Lease{}, errors.New("server exit engine failed to start")
	}
	m.leases[key] = &live{Lease: lease, peer: peer, p: process}
	return lease, nil
}
func (m *Manager) Delete(ctx context.Context, peer netip.Addr, q Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validate(peer, q); err != nil {
		return err
	}
	key := PeerKey(peer)
	s := m.leases[key]
	if s == nil {
		return nil
	}
	if s.Request != q {
		return ErrOwnership
	}
	return m.stopLocked(ctx, key)
}
func (m *Manager) stopLocked(ctx context.Context, key string) error {
	s := m.leases[key]
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.p.Stop(ctx); err != nil || s.p.Alive() {
		return errors.New("relay teardown unverified; owned lease retained")
	}
	delete(m.leases, key)
	return nil
}
func (m *Manager) reapLocked(ctx context.Context) error {
	for key, s := range m.leases {
		if !s.ExpiresAt.After(m.now()) || !s.p.Alive() {
			if err := m.stopLocked(ctx, key); err != nil {
				return err
			}
		}
	}
	return nil
}
func (m *Manager) Sweep(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reapLocked(ctx)
}
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	var last error
	for key := range m.leases {
		if err := m.stopLocked(ctx, key); err != nil {
			last = err
		}
	}
	return last
}
func copyMap(v map[string]any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil || len(b) > 256*1024 {
		return nil, errors.New("exit transport exceeds safety limit")
	}
	var out map[string]any
	err = json.Unmarshal(b, &out)
	return out, err
}
func literalServer(raw any) bool {
	s, ok := raw.(string)
	if !ok {
		return false
	}
	ip, e := netip.ParseAddr(s)
	if e != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}
func key32(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 32
}
func validateTransport(e Exit) (map[string]any, error) {
	if !literalServer(e.DNS) {
		return nil, errors.New("relay exit requires a literal exit-routed DNS server")
	}
	p, err := copyMap(e.Transport)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{"type": true, "tag": true}
	var keys []string
	switch e.Mode {
	case "wg":
		keys = []string{"private_key", "address", "mtu", "peers", "workers", "udp_timeout"}
	case "shadowsocks":
		keys = []string{"server", "server_port", "method", "password", "network", "udp_over_tcp"}
	case "hysteria2":
		keys = []string{"server", "server_port", "password", "tls", "up_mbps", "down_mbps", "obfs"}
	}
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range p {
		if !allowed[key] {
			return nil, errors.New("unsupported server relay transport field; it was not silently ignored")
		}
	}
	if containsHostPath(p) {
		return nil, errors.New("server relay credentials must be inline; host file references are not permitted")
	}
	for _, k := range []string{"detour", "bind_interface", "routing_mark", "domain_resolver", "system", "inet4_bind_address", "inet6_bind_address"} {
		if _, ok := p[k]; ok {
			return nil, fmt.Errorf("relay transport cannot override %s", k)
		}
	}
	if e.Mode == "wg" {
		if p["type"] != "wireguard" || !key32(p["private_key"]) {
			return nil, errors.New("relay WireGuard transport requires its native key")
		}
		peers, ok := p["peers"].([]any)
		if !ok || len(peers) != 1 {
			return nil, errors.New("relay WireGuard requires one paired server")
		}
		peer, ok := peers[0].(map[string]any)
		if !ok || !literalServer(peer["address"]) || !key32(peer["public_key"]) || !validPort(peer["port"]) {
			return nil, errors.New("invalid relay WireGuard peer")
		}
	} else {
		if (e.Mode != "shadowsocks" && e.Mode != "hysteria2") || p["type"] != e.Mode || !literalServer(p["server"]) || !validPort(p["server_port"]) {
			return nil, errors.New("relay exit must be a native paired WG/Shadowsocks/Hysteria2 transport")
		}
		password, ok := p["password"].(string)
		if !ok || password == "" {
			return nil, errors.New("relay exit lacks credentials")
		}
		if e.Mode == "shadowsocks" {
			method, _ := p["method"].(string)
			switch method {
			case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
			default:
				return nil, errors.New("relay Shadowsocks requires an authenticated cipher")
			}
		}
		if e.Mode == "hysteria2" {
			tls, ok := p["tls"].(map[string]any)
			if !ok || tls["enabled"] != true || (tls["insecure"] != nil && tls["insecure"] != false) {
				return nil, errors.New("relay Hysteria2 must verify TLS")
			}
		}
	}
	p["tag"] = "exit"
	return p, nil
}
func validPort(v any) bool {
	n, ok := v.(float64)
	return ok && n >= 1 && n <= 65535 && n == float64(int(n))
}
func Build(exit Exit, peer netip.Addr, lease Lease) ([]byte, error) {
	transport, err := validateTransport(exit)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(lease.Host)
	if err != nil || ip.Zone() != "" || !ip.IsPrivate() || ip.IsLoopback() || !peer.IsValid() || lease.Username == "" || lease.Password == "" || lease.Port < 1024 || lease.Port > 65535 {
		return nil, errors.New("unsafe relay listener, peer or credentials")
	}
	peer = peer.Unmap()
	bits := 128
	if peer.Is4() {
		bits = 32
	}
	config := map[string]any{
		"log":      map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{"type": "socks", "tag": "leased-client", "listen": ip.String(), "listen_port": lease.Port, "users": []any{map[string]string{"username": lease.Username, "password": lease.Password}}}},
		"dns":      map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "exit-dns", "server": exit.DNS, "detour": "exit"}}, "final": "exit-dns"},
		"route":    map[string]any{"default_domain_resolver": "exit-dns", "rules": []any{map[string]any{"source_ip_cidr": []string{netip.PrefixFrom(peer, bits).String()}, "invert": true, "action": "reject"}}, "final": "exit"},
	}
	if exit.Mode == "wg" {
		config["endpoints"] = []any{transport}
		config["outbounds"] = []any{}
	} else {
		config["outbounds"] = []any{transport}
	}
	return json.Marshal(config)
}

func containsHostPath(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			if strings.HasSuffix(key, "_path") || key == "path" || containsHostPath(value) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if containsHostPath(value) {
				return true
			}
		}
	}
	return false
}
