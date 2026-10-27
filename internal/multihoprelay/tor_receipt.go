package multihoprelay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"time"
)

// TorExitSource is a reference to an operator-owned, immutable Tor selection.
// It deliberately contains no executable, torrc, imported bridge secret or
// client-supplied configuration. A native TorRunner must resolve these exact
// digests against its own validated private source before creating a worker.
// A reference alone does not make the server capable of running Tor.
type TorExitSource struct {
	ID              string `json:"id"`
	Mode            string `json:"mode"`
	SourceSHA256    string `json:"source_sha256"`
	DNSPolicySHA256 string `json:"dns_policy_sha256"`
}

func torMode(mode string) bool { return mode == "tor" || mode == "tor-bridge" }

func (s TorExitSource) validate() error {
	if !ident.MatchString(s.ID) || !torMode(s.Mode) || !proofID.MatchString(s.SourceSHA256) || !proofID.MatchString(s.DNSPolicySHA256) {
		return errors.New("invalid private Tor source reference")
	}
	return nil
}

func (s TorExitSource) registrySHA256(node string) string {
	raw, _ := json.Marshal(struct {
		Node   string        `json:"node_id"`
		Source TorExitSource `json:"source"`
	}{node, s})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// TorRequest is intentionally separate from the ordinary relay request. Tor
// has a dynamic circuit exit; neither a fixed Router node proof nor a provider
// public-IP descriptor is authority for that circuit.
type TorRequest struct {
	SessionID        string `json:"session_id"`
	EntryNodeID      string `json:"entry_node_id"`
	ExitID           string `json:"exit_id"`
	ExitMode         string `json:"exit_mode"`
	SourceSHA256     string `json:"source_sha256"`
	DNSPolicySHA256  string `json:"dns_policy_sha256"`
	Epoch            string `json:"epoch"`
	Peer             string `json:"peer"`
	AcquireExpiresAt int64  `json:"acquire_expires_at"`
	Port             int    `json:"listen_port,omitempty"`
	Username         string `json:"listener_username,omitempty"`
	Password         string `json:"listener_password,omitempty"`
}

func (q TorRequest) request() Request {
	return Request{SessionID: q.SessionID, EntryNodeID: q.EntryNodeID, ExitID: q.ExitID, ExitMode: q.ExitMode, Port: q.Port, Username: q.Username, Password: q.Password}
}

// TorCapture is delivered only to the private native worker. Its front must
// require these fresh SOCKS credentials and this exact tunnel peer. Tor's own
// IsolateSOCKSAuth feature is circuit isolation, not this authentication gate.
type TorCapture struct {
	Schema            int           `json:"schema"`
	Request           TorRequest    `json:"request"`
	Source            TorExitSource `json:"source"`
	RegistrySHA256    string        `json:"registry_sha256"`
	OwnerID           string        `json:"owner_id"`
	Peer              string        `json:"peer"`
	Host              string        `json:"host"`
	Port              int           `json:"port"`
	Username          string        `json:"username"`
	Password          string        `json:"password"`
	BootstrapDeadline time.Time     `json:"bootstrap_deadline"`
}

func (c TorCapture) FrontSHA256() string {
	raw, _ := json.Marshal(struct {
		Peer, Host, Username, Password string
		Port                           int
	}{c.Peer, c.Host, c.Username, c.Password, c.Port})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (c TorCapture) Validate() error {
	bad := errors.New("invalid native Tor lease capture")
	peer, peerErr := netip.ParseAddr(c.Peer)
	host, hostErr := netip.ParseAddr(c.Host)
	if c.Schema != 1 || c.Source.validate() != nil || !proofID.MatchString(c.Request.EntryNodeID) || !nonce.MatchString(c.Request.SessionID) ||
		!proofID.MatchString(c.Request.Epoch) || c.Request.Peer != c.Peer || c.Request.AcquireExpiresAt <= 0 ||
		c.Request.ExitID != c.Source.ID || c.Request.ExitMode != c.Source.Mode || c.Request.SourceSHA256 != c.Source.SourceSHA256 || c.Request.DNSPolicySHA256 != c.Source.DNSPolicySHA256 ||
		c.RegistrySHA256 != c.Source.registrySHA256(c.Request.EntryNodeID) || !proofID.MatchString(c.OwnerID) || c.BootstrapDeadline.IsZero() ||
		peerErr != nil || peer.Zone() != "" || !peer.IsPrivate() || peer.String() != c.Peer || hostErr != nil || host.Zone() != "" || !host.IsPrivate() || host.String() != c.Host ||
		c.Port < 1024 || c.Port > 65535 || !listenerSecret.MatchString(c.Username) || !listenerSecret.MatchString(c.Password) || c.Username == c.Password {
		return bad
	}
	if c.Request.Port != 0 || c.Request.Username != "" || c.Request.Password != "" {
		if c.Request.Port != c.Port || c.Request.Username != c.Username || c.Request.Password != c.Password {
			return bad
		}
	}
	return nil
}

type TorPhase string

const (
	TorPending TorPhase = "pending"
	TorReady   TorPhase = "ready"
	TorFailed  TorPhase = "failed"
	TorRetired TorPhase = "retired"
)

// TorReceipt is a no-TUN receipt for the exact leased native worker. Readiness
// requires both the selected DNS proof and a genuine dynamic Tor exit proof.
// There is deliberately no latency/score field: circuit proof is not a probe
// of the last Tor relay and cannot supply either Compare measurement.
type TorReceipt struct {
	Schema          int                `json:"schema"`
	SessionID       string             `json:"session_id"`
	OwnerID         string             `json:"owner_id"`
	Peer            string             `json:"peer"`
	SourceSHA256    string             `json:"source_sha256"`
	RegistrySHA256  string             `json:"registry_sha256"`
	DNSPolicySHA256 string             `json:"dns_policy_sha256"`
	FrontSHA256     string             `json:"front_sha256"`
	Nonce           string             `json:"nonce"`
	Sequence        uint64             `json:"sequence"`
	HeartbeatAt     int64              `json:"heartbeat_at"`
	Phase           TorPhase           `json:"phase"`
	Bootstrap       int                `json:"bootstrap"`
	FrontReady      bool               `json:"front_ready"`
	TrafficAllowed  bool               `json:"traffic_allowed"`
	ExitIP          string             `json:"exit_ip,omitempty"`
	IsTor           bool               `json:"is_tor"`
	DNSProven       bool               `json:"dns_proven"`
	ProofAt         int64              `json:"proof_at,omitempty"`
	Padding         *TorPaddingReceipt `json:"padding,omitempty"`
}

// TorPaddingReceipt reports the native outgoing link-cell counter from this
// exact leased worker. It is not a claim of remote delivery or bidirectional
// traffic shaping. The containing authenticated receipt binds session, source,
// nonce and worker identity; these timestamps retain the original control
// observation instead of relabeling an old cached counter as a fresh one.
type TorPaddingReceipt struct {
	Direction    string `json:"direction"`
	Accounting   string `json:"accounting"`
	Generation   uint64 `json:"generation"`
	RateKbps     int    `json:"rate_kbps"`
	ChannelCells uint64 `json:"channel_cells"`
	ChannelBytes uint64 `json:"channel_cell_bytes"`
	ObservedAt   int64  `json:"observed_at"`
	ExpiresAt    int64  `json:"expires_at"`
}

func validTorPaddingReceipt(p *TorPaddingReceipt, proof, heartbeat, now time.Time) bool {
	if p == nil || p.Direction != "outgoing" || p.Accounting != "tor-link-cell" || p.Generation == 0 || p.Generation > math.MaxInt64 || p.RateKbps < 32 || p.RateKbps > 192 || p.ChannelCells == 0 || p.ChannelCells > math.MaxUint64/514 ||
		p.ChannelBytes < p.ChannelCells*512 || p.ChannelBytes > p.ChannelCells*514 || p.ChannelBytes%2 != 0 || p.ObservedAt <= 0 || p.ExpiresAt <= 0 {
		return false
	}
	observed, expires := time.UnixMilli(p.ObservedAt), time.UnixMilli(p.ExpiresAt)
	return !observed.After(heartbeat) && now.Sub(observed) <= 5*time.Second && expires.After(now) &&
		!expires.After(observed.Add(10*time.Second)) && !expires.After(proof.Add(30*time.Second))
}

// ValidateTorReceipt checks data from an already authenticated, exact native
// worker channel. It does not authenticate an arbitrary JSON file or process;
// that is a mandatory responsibility of the native TorProcess adapter.
func ValidateTorReceipt(receipt TorReceipt, capture TorCapture, challenge string, started, now time.Time) error {
	bad := errors.New("native Tor receipt does not match the owned lease")
	if capture.Validate() != nil || !proofID.MatchString(challenge) ||
		receipt.Schema != 1 || receipt.OwnerID != capture.OwnerID || receipt.SessionID != capture.Request.SessionID || receipt.Peer != capture.Peer ||
		receipt.SourceSHA256 != capture.Source.SourceSHA256 || receipt.RegistrySHA256 != capture.RegistrySHA256 || receipt.DNSPolicySHA256 != capture.Source.DNSPolicySHA256 ||
		receipt.FrontSHA256 != capture.FrontSHA256() || receipt.Nonce != challenge || receipt.Sequence == 0 || !receipt.FrontReady || receipt.Bootstrap < 0 || receipt.Bootstrap > 100 {
		return bad
	}
	heartbeat := time.UnixMilli(receipt.HeartbeatAt)
	if heartbeat.After(now) || now.Sub(heartbeat) > 5*time.Second || heartbeat.Before(started.Add(-time.Second)) {
		return bad
	}
	switch receipt.Phase {
	case TorPending:
		if receipt.TrafficAllowed || receipt.ExitIP != "" || receipt.IsTor || receipt.DNSProven || receipt.ProofAt != 0 || receipt.Padding != nil {
			return bad
		}
	case TorReady:
		ip, err := netip.ParseAddr(receipt.ExitIP)
		proof := time.UnixMilli(receipt.ProofAt)
		if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
			!receipt.TrafficAllowed || receipt.Bootstrap != 100 || !receipt.IsTor || !receipt.DNSProven || receipt.ProofAt == 0 || proof.After(heartbeat) || now.Sub(proof) > 30*time.Second {
			return bad
		}
		if receipt.Padding != nil && !validTorPaddingReceipt(receipt.Padding, proof, heartbeat, now) {
			return bad
		}
	default:
		return bad
	}
	return nil
}

// TorLease discloses only the requesting peer's private front and source
// identities. No fixed exit node, measured MTU, successful packet proof or
// Compare score is fabricated for a pending Tor bootstrap.
type TorLease struct {
	Request           TorRequest `json:"request"`
	NodeID            string     `json:"node_id"`
	OwnerID           string     `json:"owner_id"`
	Host              string     `json:"host"`
	Port              int        `json:"port"`
	Username          string     `json:"username"`
	Password          string     `json:"password"`
	RegistrySHA256    string     `json:"registry_sha256"`
	DNSPolicySHA256   string     `json:"dns_policy_sha256"`
	Phase             TorPhase   `json:"phase"`
	ExpiresAt         time.Time  `json:"expires_at"`
	BootstrapDeadline time.Time  `json:"bootstrap_deadline"`
}

type TorLeaseStatus struct {
	Lease   TorLease   `json:"lease"`
	Receipt TorReceipt `json:"receipt"`
}
