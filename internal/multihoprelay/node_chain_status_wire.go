package multihoprelay

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
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
	if status.Lease.Request.HasRegisteredFronts() {
		return marshalPublicNodeChainStatus(status)
	}
	if len(status.Lease.Request.Users) <= NodeChainMaximumMembers {
		raw, err := json.Marshal(status)
		if err != nil {
			return nil, err
		}
		// Preserve the original Encoder response for already-supported clients.
		if status.Lease.Request.Schema == 8 && len(raw)+1 > MaxControlResponseBytes {
			return nil, errors.New("ordered lease status exceeds its original response budget")
		}
		return append(raw, '\n'), nil
	}
	digest, err := nodeChainDigest("routervpn-extended-status-lease-v1", status.Lease)
	if err != nil || status.Lease.Request.Schema != 6 && status.Lease.Request.Schema != 8 {
		return nil, nodeChainCaptureError
	}
	raw, err := json.Marshal(NodeChainStatusUpdate{Schema: 1, LeaseSHA256: digest, Phase: status.Lease.Phase, Receipt: status.Receipt})
	if err != nil || len(raw) > MaxControlResponseBytes {
		return nil, errors.New("ordered lease status exceeds its original response budget")
	}
	return raw, nil
}

func (u NodeChainStatusUpdate) RestoreLease(previous NodeChainLease) (NodeChainLeaseStatus, error) {
	if u.Schema != 1 || previous.Request.Schema != 6 && previous.Request.Schema != 8 || len(previous.Request.Users) <= NodeChainMaximumMembers || u.Phase != NodeChainReady && u.Phase != NodeChainPending {
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
	if source.Schema == 8 {
		if source.Validate() != nil {
			return nodeChainCaptureError
		}
		receipt.ExitIP = source.Members[len(source.Members)-1].ExpectedPublicIP
		if request.FrontSeed == "" {
			statusRequest := struct {
				NodeChainRequest
				Nonce string `json:"status_nonce"`
			}{request, hash}
			raw, err := json.Marshal(statusRequest)
			size := len(raw)
			clear(raw)
			if err != nil || size > NodeChainLeaseRequestMaximumBytes {
				return fmt.Errorf("%d nodes exceed authenticated status request capacity (%d bytes, limit %d)", len(source.Members)+1, size, NodeChainLeaseRequestMaximumBytes)
			}
		}
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
	if request.HasRegisteredFronts() {
		return checkRegisteredNodeChainFrameCapacity(capture, grant, receipt)
	}
	var status any = NodeChainStatusUpdate{Schema: 1, LeaseSHA256: hash, Phase: NodeChainReady, Receipt: receipt}
	statusExtra := 0
	if source.Schema == 8 && len(source.Members) <= NodeChainMaximumMembers {
		ready := grant
		ready.Phase = NodeChainReady
		status, statusExtra = NodeChainLeaseStatus{Lease: ready, Receipt: receipt}, 1
	}
	for _, frame := range []struct {
		name         string
		value        any
		limit, extra int
	}{
		{"ready worker IPC", NodeChainIPCResponse{Schema: 1, Operation: "snapshot", Nonce: hash, CaptureSHA256: hash, OK: true, Receipt: &receipt}, NodeChainIPCMaximumBytes, 0},
		{"ready HTTP status", status, MaxControlResponseBytes, statusExtra},
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

// Construct the largest valid unknown fields for the same source-bound
// encoders used by HTTP, disk and IPC. No source data or receipts escape this
// preflight. A future wire change must still fit the original size bounds.
func checkRegisteredNodeChainFrameCapacity(c NodeChainCapture, grant NodeChainLease, receipt NodeChainReceipt) error {
	digest, err := c.Digest()
	if err != nil {
		return err
	}
	receipt.CaptureSHA256 = digest
	ready := grant
	ready.Phase = NodeChainReady
	hash := c.RegistrySHA256
	// Select an unused, maximum-length identity without assuming anything
	// about the operator's original names or public source digests.
	ids := map[string]bool{c.Source.EntryID: true}
	sources := map[string]bool{}
	for _, m := range c.Source.Members {
		ids[m.ProfileID] = true
		sources[m.SourceSHA256] = true
	}
	var id, source string
	for i := 0; id == "" || source == ""; i++ {
		name, sha := fmt.Sprintf("%0128x", i), fmt.Sprintf("%064x", i)
		if id == "" && !ids[name] {
			id = name
		}
		if source == "" && !sources[sha] {
			source = sha
		}
	}
	candidate := NodeChainCandidateRequest{Schema: 3, Lease: c.Request, OwnerID: c.OwnerID, CaptureSHA256: digest, Operation: hash, ExecutionSHA256: hash,
		Trial: strings.Repeat("0", 32), SelectionEpoch: math.MaxUint64, InventorySHA256: hash, Position: len(c.Source.Members) - 1, CandidateID: id,
		CandidateSourceSHA256: source, Address: "[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535", DeadlineAt: math.MaxInt64, Password: hash}
	if c.Source.Schema == 6 {
		candidate.Schema = 2
	}
	op := NodeChainCandidateCapture{1, c, candidate, c.Source.Members[candidate.Position-1], hash}
	for _, frame := range []struct {
		name   string
		encode func() ([]byte, error)
	}{
		{"status request", func() ([]byte, error) { return MarshalNodeChainLeaseRequest(c.Request, hash) }},
		{"lease grant", func() ([]byte, error) { return MarshalNodeChainLeaseGrant(grant) }},
		{"worker capture", func() ([]byte, error) { return MarshalNodeChainWorkerCapture(c) }},
		{"ready HTTP status", func() ([]byte, error) { return MarshalNodeChainStatus(NodeChainLeaseStatus{ready, receipt}) }},
		{"ready worker IPC", func() ([]byte, error) {
			return MarshalNodeChainWorkerResponse(NodeChainIPCResponse{1, "snapshot", hash, digest, true, &receipt}, c)
		}},
		{"candidate request", func() ([]byte, error) { return MarshalNodeChainCandidateRequest(candidate) }},
		{"candidate worker IPC", func() ([]byte, error) {
			return MarshalNodeChainCandidateWorkerRequest(NodeChainCandidateIPCRequest{1, "candidate-prepare", hash, op})
		}},
	} {
		raw, err := frame.encode()
		clear(raw)
		if err != nil {
			family, _ := c.Request.registeredBinding()
			return fmt.Errorf("%d nodes exceed %s %s capacity: %w", len(c.Source.Members)+1, family, frame.name, err)
		}
	}
	return nil
}
