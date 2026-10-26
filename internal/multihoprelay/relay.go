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

	"router-vpn/internal/applexray"
	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/mobilepq"
	"router-vpn/internal/nativecomposite"
	"router-vpn/internal/nativeopenvpn"
)

var ident = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var nonce = regexp.MustCompile(`^[0-9a-f]{32}$`)
var listenerSecret = regexp.MustCompile(`^[0-9a-f]{48}$`)
var proofID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ErrUnavailable = errors.New("requested server-side exit is not provisioned")
var ErrOwnership = errors.New("relay lease does not belong to this peer and session")
var ErrBusy = errors.New("this peer already owns another relay session")

type Exit struct {
	ID       string        `json:"id"`
	Mode     string        `json:"mode"`
	NodeID   string        `json:"node_id"`
	DNS      string        `json:"dns_server"`
	External *ExternalExit `json:"external,omitempty"`
	// Operator-owned, private configuration. A client request never supplies
	// arbitrary sing-box configuration, executable paths or remote credentials.
	Transport  map[string]any `json:"transport"`
	StartLayer *StartLayer    `json:"start_layer,omitempty"`
}

// MaxRegistryBytes bounds private paired key material, including two public
// McEliece keys per PQ exit. This is not a network request or lease-body limit.
const MaxRegistryBytes = 32 << 20

type Config struct {
	ListenIP   string `json:"listen_ip"`
	FirstPort  int    `json:"first_port"`
	LastPort   int    `json:"last_port"`
	TTLSeconds int    `json:"ttl_seconds"`
	Exits      []Exit `json:"exits"`
}
type Request struct {
	SessionID      string `json:"session_id"`
	EntryNodeID    string `json:"entry_node_id"`
	ExitID         string `json:"exit_id"`
	ExitMode       string `json:"exit_mode"`
	ExitStartLayer string `json:"exit_start_layer,omitempty"`
	// Public identities pinned by a client after authenticated discovery.
	// PQ and complete MAX bind both independent identities together. Legacy
	// requests may omit both; a pinned request may never partially drop them.
	// Enforced under the lease lock, including renewals, so registry replacement
	// cannot substitute a different packet peer or KEM rekey owner.
	ExpectedPacketPublicKey  string `json:"expected_packet_public_key,omitempty"`
	ExpectedPQClientIdentity string `json:"expected_pq_client_identity,omitempty"`
	ExternalFingerprint      string `json:"external_fingerprint,omitempty"`
	ExternalAuthentication   string `json:"external_authentication,omitempty"`
	ExternalEpoch            string `json:"external_epoch,omitempty"`
	ExternalPeer             string `json:"external_peer,omitempty"`
	ExternalExpiresAt        int64  `json:"external_expires_at,omitempty"`
	ExternalAttempt          string `json:"external_attempt,omitempty"`
	// Optional client-generated listener proposal allows the client to prepare
	// its final graph before acquiring a lease, without restarting its TUN.
	Port     int    `json:"listen_port,omitempty"`
	Username string `json:"listener_username,omitempty"`
	Password string `json:"listener_password,omitempty"`
}
type Lease struct {
	Request
	NodeID        string    `json:"node_id"`
	ExitNodeID    string    `json:"exit_node_id"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	ExpiresAt     time.Time `json:"expires_at"`
	OpenVPNRemote bool      `json:"openvpn_remote,omitempty"`
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
	peer    netip.Addr
	p       Process
	retired bool
}
type Manager struct {
	mu             sync.Mutex
	cfg            Config
	node           string
	runner         Runner
	leases         map[string]*live
	now            func() time.Time
	closed         bool
	packetEpoch    string
	packetAttempts map[string]int64
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
	if c.TTLSeconds < 15 || c.TTLSeconds > 300 || len(c.Exits) > MaxPairedExits {
		return nil, errors.New("relay TTL or exit limit is invalid")
	}
	seen := map[string]bool{}
	for _, e := range c.Exits {
		if ExternalIndependentMode(e.Mode) && e.External == nil {
			return nil, errors.New("external packet mode requires its explicit paired identity")
		}
		if !ident.MatchString(e.ID) || (e.External == nil && (!proofID.MatchString(e.NodeID) || e.NodeID == node)) || seen[e.ID+"/"+e.Mode+"/"+ExitLayerMode(e)] {
			return nil, errors.New("relay exits require distinct paired identities and unique modes")
		}
		if e.External != nil {
			if ExternalIndependentMode(e.Mode) && externalIndependentOwner(e) != "server" {
				return nil, errors.New("private packet registry requires only its separately provisioned server credential owner")
			}
			if _, err := ExternalFingerprint(e); err != nil {
				return nil, err
			}
		}
		validated, err := validateTransport(e)
		if err != nil {
			return nil, err
		}
		if e.StartLayer != nil {
			if CompleteMAXMode(e.Mode) {
				if _, _, err := maxRelayChain(e); err != nil {
					return nil, err
				}
			} else if nativecomposite.Mode(e.Mode) {
				if _, err := compositePlan(e); err != nil {
					return nil, err
				}
			} else {
				if _, _, err := WrapStartLayer(validated, e.Mode, e.StartLayer, ExitStartLayerTag, ""); err != nil {
					return nil, err
				}
			}
		}
		seen[e.ID+"/"+e.Mode+"/"+ExitLayerMode(e)] = true
	}
	// Copy the supplied private configuration so callers cannot mutate live plans.
	raw, _ := json.Marshal(c)
	var frozen Config
	if err := json.Unmarshal(raw, &frozen); err != nil {
		return nil, err
	}
	epochBytes := make([]byte, 32)
	if _, err := rand.Read(epochBytes); err != nil {
		return nil, errors.New("relay ownership epoch could not be generated")
	}
	return &Manager{cfg: frozen, node: node, runner: r, leases: map[string]*live{}, now: time.Now,
		packetEpoch: hex.EncodeToString(epochBytes), packetAttempts: map[string]int64{}}, nil
}
func PeerKey(peer netip.Addr) string { return peer.Unmap().String() }
func (m *Manager) Available() []map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []map[string]string{}
	for _, e := range m.cfg.Exits {
		item := map[string]string{"exit_id": e.ID, "exit_mode": e.Mode, "exit_node_id": e.NodeID}
		if e.External != nil {
			item["external_fingerprint"], _ = ExternalFingerprint(e)
			item["expected_public_ip"] = e.External.ExpectedPublicIP
		}
		if OpenVPNRemoteRequired(e) {
			item["openvpn_remote"] = "fresh-connected-transport-v1"
		}
		if OpenVPNLayersRequired(e) {
			item["openvpn_layers"] = "captured-per-remote-v1"
		}
		if layer := ExitLayerMode(e); layer != "" {
			item["exit_start_layer"] = layer
		}
		transport := e.Transport
		if CompleteMAXMode(e.Mode) {
			// New validated and froze this exact complete-chain owner. Public
			// discovery fingerprints its base; no private chain is exposed.
			transport = e.Transport["endpoint"].(map[string]any)
		}
		if PacketMode(e.Mode) || CompleteMAXMode(e.Mode) {
			if identity, err := clientIdentity(transport); err == nil {
				item["client_public_key"] = identity
			}
		}
		if mobilepq.IsMode(e.Mode) || CompleteMAXMode(e.Mode) {
			if identity, err := pqIdentity(transport); err == nil {
				item["pq_client_identity"] = identity
			}
		}
		out = append(out, item)
	}
	return out
}

// ValidateIdentityPins validates only the public Router-node pin contract.
// Possession, authenticated discovery and independence from the local owner
// are separate checks. External nodes keep their own challenged credential
// ownership and cannot use these fields to claim a Router packet/PQ identity.
func ValidateIdentityPins(mode, packetPublic, pqClientIdentity string) error {
	pq := mobilepq.IsMode(mode) || CompleteMAXMode(mode)
	if packetPublic != "" && ((!awgpolicy.WireGuardFamily(mode) && !pq) || !canonicalPacketPublic(packetPublic)) {
		return ErrOwnership
	}
	if pq {
		if (packetPublic == "") != (pqClientIdentity == "") || pqClientIdentity != "" && !proofID.MatchString(pqClientIdentity) {
			return ErrOwnership
		}
	} else if pqClientIdentity != "" {
		return ErrOwnership
	}
	return nil
}

func (m *Manager) validate(peer netip.Addr, q Request) error {
	if err := ValidateIdentityPins(q.ExitMode, q.ExpectedPacketPublicKey, q.ExpectedPQClientIdentity); err != nil {
		return err
	}
	if q.ExternalFingerprint != "" && (q.ExpectedPacketPublicKey != "" || q.ExpectedPQClientIdentity != "") {
		return ErrOwnership
	}
	if err := validatePacketRequestShape(q, false); err != nil {
		return err
	}
	if externalRequestRequiresChallenge(q) && (q.ExternalEpoch != m.packetEpoch || q.ExternalPeer != PeerKey(peer)) {
		return ErrOwnership
	}
	if (q.ExternalFingerprint == "") != (q.ExternalAuthentication == "") || q.ExternalFingerprint != "" && (!proofID.MatchString(q.ExternalFingerprint) || !proofID.MatchString(q.ExternalAuthentication)) {
		return ErrOwnership
	}
	if q.ExitStartLayer != "" && !ValidLayerMode(q.ExitStartLayer) {
		return ErrOwnership
	}
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

// Acquisition and renewal bind to the registry under the same lock. DELETE
// still accepts the exact old owned request if a registry identity changed;
// otherwise a failed renewal could prevent cleanup of its existing engine.
func (m *Manager) validateExpectedIdentitiesLocked(q Request) error {
	if q.ExpectedPacketPublicKey == "" && q.ExpectedPQClientIdentity == "" {
		return nil
	}
	for _, exit := range m.cfg.Exits {
		if exit.ID != q.ExitID || exit.Mode != q.ExitMode || ExitLayerMode(exit) != q.ExitStartLayer || exit.External != nil {
			continue
		}
		transport := relayPacketTransport(exit)
		identity, err := clientIdentity(transport)
		if err != nil || identity != q.ExpectedPacketPublicKey {
			return ErrOwnership
		}
		if q.ExpectedPQClientIdentity != "" {
			identity, err := pqIdentity(transport)
			if err != nil || identity != q.ExpectedPQClientIdentity {
				return ErrOwnership
			}
		}
		return nil
	}
	return ErrOwnership
}
func secret() (string, error) {
	b := make([]byte, 24)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func (m *Manager) Create(ctx context.Context, peer netip.Addr, q Request) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// The request may have been cancelled while another owned engine was
	// starting or stopping. Do not turn stale work into a new lease/renewal.
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	if m.closed {
		return Lease{}, ErrUnavailable
	}
	if err := m.validate(peer, q); err != nil {
		return Lease{}, err
	}
	if err := m.validateExpectedIdentitiesLocked(q); err != nil {
		return Lease{}, err
	}
	if err := m.reapLocked(ctx); err != nil {
		return Lease{}, err
	}
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	key := PeerKey(peer)
	if old := m.leases[key]; old != nil {
		if old.Request != q {
			return Lease{}, ErrBusy
		}
		if old.retired || !old.p.Alive() {
			return Lease{}, errors.New("relay engine is not alive")
		}
		old.ExpiresAt = m.now().Add(time.Duration(m.cfg.TTLSeconds) * time.Second)
		return old.Lease, nil
	}
	var exit *Exit
	for i := range m.cfg.Exits {
		e := &m.cfg.Exits[i]
		if e.ID == q.ExitID && e.Mode == q.ExitMode && ExitLayerMode(*e) == q.ExitStartLayer {
			exit = e
			break
		}
	}
	if exit == nil {
		return Lease{}, ErrUnavailable
	}
	if err := ValidateExternalRequest(*exit, q); err != nil {
		return Lease{}, err
	}
	if err := m.validateNewPacketAttemptLocked(q); err != nil {
		return Lease{}, err
	}
	if err := m.validateOpenVPNConcurrentOwnerLocked(*exit); err != nil {
		return Lease{}, err
	}
	if PacketMode(exit.Mode) || CompleteMAXMode(exit.Mode) {
		// A WireGuard peer key identifies one roaming endpoint. Two independent
		// processes using that key would steal each other's reply endpoint.
		// X25519 clamps scalar bits: distinct private-key encodings can be the
		// same peer. Use the public identity already advertised to clients, not
		// private-key text or the remote server's public key.
		identity, err := clientIdentity(relayPacketTransport(*exit))
		if err != nil {
			return Lease{}, err
		}
		for _, active := range m.leases {
			if !PacketMode(active.ExitMode) && !CompleteMAXMode(active.ExitMode) {
				continue
			}
			for _, paired := range m.cfg.Exits {
				if paired.ID != active.ExitID || paired.Mode != active.ExitMode || ExitLayerMode(paired) != active.ExitStartLayer || (!PacketMode(paired.Mode) && !CompleteMAXMode(paired.Mode)) {
					continue
				}
				other, err := clientIdentity(relayPacketTransport(paired))
				if err != nil {
					return Lease{}, err
				}
				if identity == other {
					return Lease{}, errors.New("paired WireGuard credentials already own another relay; provision distinct client credentials for concurrent use")
				}
			}
		}
	}
	if mobilepq.IsMode(exit.Mode) || CompleteMAXMode(exit.Mode) {
		identity, err := pqIdentity(relayPacketTransport(*exit))
		if err != nil {
			return Lease{}, err
		}
		for _, active := range m.leases {
			if !mobilepq.IsMode(active.ExitMode) && !CompleteMAXMode(active.ExitMode) {
				continue
			}
			for _, paired := range m.cfg.Exits {
				if paired.ID != active.ExitID || paired.Mode != active.ExitMode || ExitLayerMode(paired) != active.ExitStartLayer {
					continue
				}
				other, err := pqIdentity(relayPacketTransport(paired))
				if err != nil {
					return Lease{}, err
				}
				if identity == other {
					return Lease{}, errors.New("paired PQ credentials already own another relay; provision independent PQ client keys")
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
	lease.OpenVPNRemote = OpenVPNRemoteRequired(*exit)
	config, err := Build(*exit, peer, lease)
	if err != nil {
		return Lease{}, err
	}
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	if err := m.rememberPacketAttemptLocked(q); err != nil {
		return Lease{}, err
	}
	process, err := m.runner.Start(ctx, config, lease)
	if err == nil && lease.OpenVPNRemote {
		if _, ok := process.(OpenVPNRemoteProcess); !ok {
			err = errors.New("server core cannot attest its owned connected OpenVPN remote")
		}
	}
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
		if externalRequestRequiresChallenge(q) {
			var paired *Exit
			for i := range m.cfg.Exits {
				e := &m.cfg.Exits[i]
				if e.ID == q.ExitID && e.Mode == q.ExitMode && ExitLayerMode(*e) == q.ExitStartLayer {
					paired = e
					break
				}
			}
			if paired == nil || ValidateExternalRequest(*paired, q) != nil {
				return ErrOwnership
			}
			// A cancelled PUT may not have arrived yet. Its signed attempt is
			// retired even when no process exists, so it cannot start after DELETE.
			if err := m.rememberPacketAttemptLocked(q); err != nil {
				return err
			}
		}
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
	// Revocation precedes cleanup. A failed Stop retains process/key ownership,
	// but never permits this exact attempt to renew or resurrect the path.
	s.retired = true
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.p.Stop(ctx); err != nil || s.p.Alive() {
		return errors.New("relay teardown unverified; owned lease retained")
	}
	delete(m.leases, key)
	return nil
}
func (m *Manager) reapLocked(ctx context.Context) error {
	m.sweepPacketAttemptsLocked()
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

const maxTransportBytes = 256 * 1024

func copyMap(v map[string]any) (map[string]any, error) {
	return copyMapBounded(v, maxTransportBytes)
}

func copyMapBounded(v map[string]any, limit int) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil || len(b) > limit {
		return nil, errors.New("exit transport exceeds safety limit")
	}
	var out map[string]any
	err = json.Unmarshal(b, &out)
	return out, err
}

// Complete MAX owns a packet/PQ base inside its validated chain. Labels and
// wrappers cannot create a second roaming owner for the same underlying key.
func relayPacketTransport(exit Exit) map[string]any {
	if CompleteMAXMode(exit.Mode) {
		value, _ := exit.Transport["endpoint"].(map[string]any)
		return value
	}
	return exit.Transport
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

// clientIdentity returns only the canonical public identity. Errors never
// echo a private key, and WG/AWG transport labels cannot split its ownership.
func clientIdentity(transport map[string]any) (string, error) {
	bad := errors.New("invalid paired WireGuard client identity")
	text, ok := transport["private_key"].(string)
	if !ok {
		return "", bad
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(raw) != 32 {
		return "", bad
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", bad
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
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
	return validateTransportForSelection(e, false)
}

func validateTransportForSelection(e Exit, allowHostname bool) (map[string]any, error) {
	if e.External == nil && !literalServer(e.DNS) {
		return nil, errors.New("relay exit requires a literal exit-routed DNS server")
	}
	if e.External != nil && e.DNS != "" {
		return nil, errors.New("external relay DNS remains owned by the captured client policy")
	}
	if CompleteMAXMode(e.Mode) {
		return validateMAXTransport(e)
	}
	if nativecomposite.Mode(e.Mode) {
		if err := nativecomposite.ValidatePlan(e.Transport, e.Mode, e.NodeID, ""); err != nil {
			return nil, err
		}
		return copyMap(e.Transport)
	}
	if e.Mode == "openvpn" {
		if _, exists := e.Transport["detour"]; exists {
			return nil, errExternalOpenVPN
		}
		p, err := nativeopenvpn.ValidateEndpoint(e.Transport)
		if err != nil {
			return nil, errExternalOpenVPN
		}
		p["tag"] = "exit"
		return p, nil
	}
	// Validate before JSON copying: encoding/json normalizes invalid UTF-8,
	// which would silently change an authentication credential.
	if NaiveMode(e.Mode) {
		if err := ValidateNaiveTransport(e.Transport, e.Mode); err != nil {
			return nil, err
		}
	}
	if e.Mode == "socks5" || e.Mode == "http-connect" || e.Mode == "https-connect" {
		if err := validateExternalProxyCredentials(e.Transport); err != nil {
			return nil, err
		}
	}
	p, err := copyTransportMap(e.Transport, e.Mode)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{"type": true, "tag": true}
	var keys []string
	switch e.Mode {
	case "wg", "wireguard":
		keys = []string{"private_key", "address", "mtu", "peers", "workers", "udp_timeout"}
	case "awg2-fast", "awg2-strong", "amneziawg":
		keys = []string{"private_key", "address", "mtu", "peers", "amnezia"}
	case "wg-pq", "awg2-pq":
		keys = []string{"private_key", "address", "mtu", "peers", "amnezia", "mode", "node_id", "pq"}
	case "naive-h2", "naive-h3":
		keys = []string{"server", "server_port", "username", "password", "quic", "udp_over_tcp", "tls"}
	case "shadowsocks":
		keys = []string{"server", "server_port", "method", "password", "network", "udp_over_tcp"}
	case "reality-vision", "reality-pq-vision", "reality-xhttp":
		keys = []string{"mode", "config_json"}
	case "hysteria2":
		keys = []string{"server", "server_port", "password", "tls", "up_mbps", "down_mbps", "obfs"}
	case "socks5":
		keys = []string{"server", "server_port", "username", "password", "version"}
	case "http-connect", "https-connect":
		keys = []string{"server", "server_port", "username", "password", "tls"}
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
	if e.Mode == "socks5" || e.Mode == "http-connect" || e.Mode == "https-connect" {
		if err := validateExternalProxyTransport(p, e.Mode); err != nil {
			return nil, err
		}
	} else if NaiveMode(e.Mode) {
		if err := ValidateNaiveTransport(p, e.Mode); err != nil {
			return nil, err
		}
	} else if applexray.SingleTransportMode(e.Mode) {
		validate := applexray.ValidateSingleTransport
		if allowHostname {
			validate = applexray.ValidateSingleTransportForSelection
		}
		if err := validate(p, e.Mode); err != nil {
			return nil, err
		}
	} else if mobilepq.IsMode(e.Mode) {
		if err := validatePQTransport(p, e.Mode, e.NodeID); err != nil {
			return nil, err
		}
	} else if awgpolicy.WireGuardFamily(e.Mode) || ExternalPacketMode(e.Mode) {
		expectedType := "wireguard"
		if awgpolicy.IsMode(e.Mode) || e.Mode == "amneziawg" {
			expectedType = awgpolicy.Type
		}
		if p["type"] != expectedType || !key32(p["private_key"]) {
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
		if awgpolicy.IsMode(e.Mode) || e.Mode == "amneziawg" {
			if err := validateAmnezia(p, peer); err != nil {
				return nil, err
			}
		} else if ExternalPacketMode(e.Mode) {
			if err := validatePacketPeer(p, peer); err != nil {
				return nil, err
			}
		}
	} else {
		validHost := literalServer(p["server"]) || (allowHostname && e.Mode == "hysteria2" && applexray.ValidNodeHostname(stringValue(p["server"])))
		if (e.Mode != "shadowsocks" && e.Mode != "hysteria2") || p["type"] != e.Mode || !validHost || !validPort(p["server_port"]) {
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
	if lease.OpenVPNRemote != OpenVPNRemoteRequired(exit) {
		return nil, errors.New("OpenVPN relay remote proof ownership differs from its captured transport")
	}
	if exit.External != nil {
		if ExternalIndependentMode(exit.Mode) && externalIndependentOwner(exit) != "server" {
			return nil, errors.New("external packet relay cannot run the client's local credentials")
		}
		if err := ValidateExternalRequest(exit, lease.Request); err != nil {
			return nil, err
		}
	}
	if ExitLayerMode(exit) != lease.ExitStartLayer {
		return nil, errors.New("relay lease does not match paired exit encryption")
	}
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
	if exit.External != nil {
		// The captured client resolves through its selected DNS policy and sends
		// literal destinations. Never let the relay or third-party provider
		// silently resolve a SOCKS hostname with another DNS policy.
		delete(config, "dns")
		route := config["route"].(map[string]any)
		delete(route, "default_domain_resolver")
		route["rules"] = append(route["rules"].([]any), map[string]any{"domain_regex": []string{"."}, "action": "reject"})
	}
	if CompleteMAXMode(exit.Mode) {
		base, outputs, err := maxRelayChain(exit)
		if err != nil {
			return nil, err
		}
		config["endpoints"] = []any{base}
		config["outbounds"] = outputs
	} else if nativecomposite.Mode(exit.Mode) {
		plan, err := compositePlan(exit)
		if err != nil {
			return nil, err
		}
		owner, children, err := nativecomposite.Relabel(plan, exit.Mode, exit.NodeID, ExitLayerMode(exit), "exit", CompositePrefix, "")
		if err != nil {
			return nil, err
		}
		config["outbounds"] = append([]any{owner}, children...)
	} else if PacketMode(exit.Mode) || exit.Mode == "openvpn" {
		config["endpoints"] = []any{transport}
		config["outbounds"] = []any{}
	} else {
		config["outbounds"] = []any{transport}
	}
	if exit.StartLayer != nil && !CompleteMAXMode(exit.Mode) && !nativecomposite.Mode(exit.Mode) {
		inner, outer, err := WrapStartLayer(transport, exit.Mode, exit.StartLayer, ExitStartLayerTag, "")
		if err != nil {
			return nil, err
		}
		if PacketMode(exit.Mode) || exit.Mode == "openvpn" {
			config["endpoints"] = []any{inner}
			config["outbounds"] = []any{outer}
		} else {
			config["outbounds"] = []any{inner, outer}
		}
	}
	if OpenVPNLayersRequired(exit) {
		inner, mapping, err := WrapOpenVPNStartLayers(transport, exit.External.OpenVPNResponseProbes, exit.External.OpenVPNStartLayers, ExitLayerMode(exit), OpenVPNStartLayerMapTag, "")
		if err != nil {
			return nil, err
		}
		config["endpoints"] = []any{inner}
		config["outbounds"] = []any{mapping}
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
