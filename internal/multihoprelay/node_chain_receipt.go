package multihoprelay

import (
	"errors"
	"math"
	"time"
)

type NodeChainPhase string

const (
	NodeChainPending NodeChainPhase = "pending"
	NodeChainReady   NodeChainPhase = "ready"
	NodeChainFailed  NodeChainPhase = "failed"
	NodeChainRetired NodeChainPhase = "retired"
)

// Each row refers to one original suffix member, in its captured order.
// ResponseMS is the routed authenticated HTTP proof, not ICMP, throughput,
// or either fresh candidate probe required by Local/Server comparison.
type NodeChainPrefixReceipt struct {
	Position   int     `json:"position"`
	ProfileID  string  `json:"profile_id"`
	NodeID     string  `json:"node_id"`
	Mode       string  `json:"mode"`
	Proven     bool    `json:"proven"`
	ResponseMS float64 `json:"response_ms"`
}

// A receipt is meaningful only on the original authenticated worker channel.
// It does not authenticate an arbitrary file or establish client Connected.
// CaptureSHA256 binds the listener, all positional credentials, local key pins,
// exact operator source, selected DNS, original peer and bootstrap deadline.
type NodeChainReceipt struct {
	Schema          int                      `json:"schema"`
	SessionID       string                   `json:"session_id"`
	OwnerID         string                   `json:"owner_id"`
	Peer            string                   `json:"peer"`
	SourceSHA256    string                   `json:"source_sha256"`
	RegistrySHA256  string                   `json:"registry_sha256"`
	DNSPolicySHA256 string                   `json:"dns_policy_sha256"`
	CaptureSHA256   string                   `json:"capture_sha256"`
	Nonce           string                   `json:"nonce"`
	Sequence        uint64                   `json:"sequence"`
	HeartbeatAt     int64                    `json:"heartbeat_at"`
	Phase           NodeChainPhase           `json:"phase"`
	FrontReady      bool                     `json:"front_ready"`
	TrafficAllowed  bool                     `json:"traffic_allowed"`
	DNSProven       bool                     `json:"dns_proven"`
	PublicProven    bool                     `json:"public_proven"`
	ProofAt         int64                    `json:"proof_at,omitempty"`
	Prefixes        []NodeChainPrefixReceipt `json:"prefixes,omitempty"`
}

func (r NodeChainReceipt) Clone() NodeChainReceipt {
	r.Prefixes = append([]NodeChainPrefixReceipt(nil), r.Prefixes...)
	return r
}

func ValidateNodeChainReceipt(receipt NodeChainReceipt, capture NodeChainCapture, challenge string, started, now time.Time) error {
	bad := errors.New("native ordered receipt does not match its original lease")
	digest, err := capture.Digest()
	if err != nil || capture.Validate() != nil || !proofID.MatchString(challenge) || started.IsZero() || now.Before(started) ||
		receipt.Schema != 1 || receipt.OwnerID != capture.OwnerID || receipt.SessionID != capture.Request.SessionID || receipt.Peer != capture.Peer ||
		receipt.SourceSHA256 != capture.Source.SourceSHA256 || receipt.RegistrySHA256 != capture.RegistrySHA256 ||
		receipt.DNSPolicySHA256 != capture.Source.DNSPolicySHA256 || receipt.CaptureSHA256 != digest ||
		receipt.Nonce != challenge || receipt.Sequence == 0 || !receipt.FrontReady {
		return bad
	}
	heartbeat := time.UnixMilli(receipt.HeartbeatAt)
	if receipt.HeartbeatAt <= 0 || heartbeat.After(now) || now.Sub(heartbeat) > 5*time.Second || heartbeat.Before(started.Add(-time.Second)) {
		return bad
	}
	switch receipt.Phase {
	case NodeChainPending:
		if receipt.TrafficAllowed || receipt.DNSProven || receipt.PublicProven || receipt.ProofAt != 0 || len(receipt.Prefixes) != 0 {
			return bad
		}
	case NodeChainReady:
		proof := time.UnixMilli(receipt.ProofAt)
		if !receipt.TrafficAllowed || !receipt.DNSProven || !receipt.PublicProven || receipt.ProofAt <= 0 || proof.After(heartbeat) ||
			now.Sub(proof) > time.Duration(15+5*len(capture.Source.Members))*time.Second || len(receipt.Prefixes) != len(capture.Source.Members) {
			return bad
		}
		for i, row := range receipt.Prefixes {
			member := capture.Source.Members[i]
			if row.Position != member.Position || row.ProfileID != member.ProfileID || row.NodeID != member.NodeID || row.Mode != member.Mode ||
				!row.Proven || math.IsNaN(row.ResponseMS) || math.IsInf(row.ResponseMS, 0) || row.ResponseMS <= 0 || row.ResponseMS > 120000 {
				return bad
			}
		}
	default:
		return bad
	}
	return nil
}

// The complete request is returned only to its authenticated original peer.
// Positional credentials do not grant traffic before native proof succeeds.
type NodeChainLease struct {
	Request           NodeChainRequest `json:"request"`
	NodeID            string           `json:"node_id"`
	OwnerID           string           `json:"owner_id"`
	Host              string           `json:"host"`
	Port              int              `json:"port"`
	Users             []NodeChainUser  `json:"users"`
	RegistrySHA256    string           `json:"registry_sha256"`
	DNSPolicySHA256   string           `json:"dns_policy_sha256"`
	Phase             NodeChainPhase   `json:"phase"`
	ExpiresAt         time.Time        `json:"expires_at"`
	BootstrapDeadline time.Time        `json:"bootstrap_deadline"`
}

type NodeChainLeaseStatus struct {
	Lease   NodeChainLease   `json:"lease"`
	Receipt NodeChainReceipt `json:"receipt"`
}
