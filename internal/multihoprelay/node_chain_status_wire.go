package multihoprelay

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// An extended status read follows a successful PUT to the same lease. A status
// read cannot extend expiry or replace its listener, owner or request. Commit
// every field of the actual lease, including all original position credentials.
type NodeChainStatusUpdate struct {
	Schema      int              `json:"schema"`
	LeaseSHA256 string           `json:"lease_sha256"`
	Phase       NodeChainPhase   `json:"phase"`
	Receipt     NodeChainReceipt `json:"receipt"`
}

func MarshalNodeChainStatus(status NodeChainLeaseStatus) ([]byte, error) {
	if len(status.Lease.Request.Users) <= NodeChainMaximumMembers {
		raw, err := json.Marshal(status)
		if err != nil {
			return nil, err
		}
		// Preserve the original Encoder response for already-supported clients.
		return append(raw, '\n'), nil
	}
	digest, err := nodeChainDigest("routervpn-extended-status-lease-v1", status.Lease)
	if err != nil || status.Lease.Request.Schema != 6 {
		return nil, nodeChainCaptureError
	}
	raw, err := json.Marshal(NodeChainStatusUpdate{Schema: 1, LeaseSHA256: digest, Phase: status.Lease.Phase, Receipt: status.Receipt})
	if err != nil || len(raw) > MaxControlResponseBytes {
		return nil, errors.New("ordered lease status exceeds its original response budget")
	}
	return raw, nil
}

func (u NodeChainStatusUpdate) RestoreLease(previous NodeChainLease) (NodeChainLeaseStatus, error) {
	if u.Schema != 1 || previous.Request.Schema != 6 || len(previous.Request.Users) <= NodeChainMaximumMembers || u.Phase != NodeChainReady && u.Phase != NodeChainPending {
		return NodeChainLeaseStatus{}, nodeChainCaptureError
	}
	previous.Phase = u.Phase
	digest, err := nodeChainDigest("routervpn-extended-status-lease-v1", previous)
	if err != nil || u.LeaseSHA256 != digest {
		return NodeChainLeaseStatus{}, nodeChainCaptureError
	}
	return NodeChainLeaseStatus{Lease: previous, Receipt: u.Receipt}, nil
}

// CheckNodeChainLeaseResponseCapacity checks the actual source identities and
// credentials against every mandatory reply and staged worker file before
// acquisition. These private wire shapes are used only for sizing. No receipt,
// grant or worker is returned, and runtime still validates every real frame.
func CheckNodeChainLeaseResponseCapacity(source NodeChainDescriptor, request NodeChainRequest, host string) error {
	// Each unknown owner, nonce or digest is exactly 64 ASCII hex bytes.
	hash := request.DescriptorSHA256
	// Ready measurements are integer nanoseconds divided by 1e6, positive
	// and at most 120000ms. This is the longest possible decimal spelling.
	const longestResponseMS = 119999.999999
	receipt := NodeChainReceipt{
		Schema: 1, SessionID: request.SessionID, OwnerID: hash, Peer: request.Peer,
		SourceSHA256: source.SourceSHA256, RegistrySHA256: hash, DNSPolicySHA256: source.DNSPolicySHA256,
		CaptureSHA256: hash, Nonce: hash, Sequence: math.MaxUint64, HeartbeatAt: math.MaxInt64,
		Phase: NodeChainReady, FrontReady: true, TrafficAllowed: true, DNSProven: true, PublicProven: true, ProofAt: math.MaxInt64,
	}
	for _, m := range source.Members {
		receipt.Prefixes = append(receipt.Prefixes, NodeChainPrefixReceipt{Position: m.Position, ProfileID: m.ProfileID,
			NodeID: m.NodeID, Mode: m.Mode, Proven: true, ResponseMS: longestResponseMS, NodeKind: m.NodeKind, ProofKind: m.ProofKind, SourceSHA256: m.SourceSHA256})
	}
	// The worker bootstrap uses UTC; the Manager expiry may have an offset.
	// Both use RFC3339Nano with at most nine fractional digits.
	expiry := time.Date(2000, 1, 1, 1, 1, 1, 999999999, time.FixedZone("", 3600))
	capture := NodeChainCapture{Schema: 1, Request: request, Source: source, RegistrySHA256: hash,
		OwnerID: hash, Peer: request.Peer, Host: host, BootstrapDeadline: expiry.UTC()}
	grant := NodeChainLease{Request: request, NodeID: source.EntryNodeID, OwnerID: hash, Host: host, Port: request.Port,
		Users: request.Users, RegistrySHA256: hash, DNSPolicySHA256: source.DNSPolicySHA256, Phase: NodeChainPending,
		ExpiresAt: expiry, BootstrapDeadline: expiry.UTC()}
	for _, frame := range []struct {
		name         string
		value        any
		limit, extra int
	}{
		{"ready worker IPC", NodeChainIPCResponse{Schema: 1, Operation: "snapshot", Nonce: hash, CaptureSHA256: hash, OK: true, Receipt: &receipt}, NodeChainIPCMaximumBytes, 0},
		{"ready HTTP status", NodeChainStatusUpdate{Schema: 1, LeaseSHA256: hash, Phase: NodeChainReady, Receipt: receipt}, MaxControlResponseBytes, 0},
		{"worker capture", capture, NodeChainCaptureMaximumBytes, 0},
		// The HTTP PUT Encoder includes a newline in the bounded response.
		{"lease grant", grant, MaxControlResponseBytes, 1},
	} {
		raw, err := json.Marshal(frame.value)
		if err != nil {
			return err
		}
		size := len(raw) + frame.extra
		clear(raw)
		if size > frame.limit {
			return fmt.Errorf("%d nodes require capacity for a %d-byte %s (limit %d bytes)", len(source.Members)+1, size, frame.name, frame.limit)
		}
	}
	return nil
}
