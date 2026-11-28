package multihoprelay

import (
	"encoding/json"
	"time"
)

const NodeChainPrefixIPCMaximumBytes = 512 << 10

// Only the original inherited parent/worker pipe carries these frames. A prefix
// capture and an optional exact child capture replace no complete-path authority.
type NodeChainPrefixIPCRequest struct {
	Schema        int                              `json:"schema"`
	Operation     string                           `json:"operation"`
	Nonce         string                           `json:"nonce"`
	CaptureSHA256 string                           `json:"capture_sha256"`
	Candidate     *NodeChainPrefixCandidateCapture `json:"candidate,omitempty"`
}

func (q NodeChainPrefixIPCRequest) Valid() bool {
	if q.Schema != 1 || !proofID.MatchString(q.Nonce) || !proofID.MatchString(q.CaptureSHA256) {
		return false
	}
	switch q.Operation {
	case "snapshot", "prepare", "stop":
		return q.Candidate == nil
	case "candidate-prepare", "candidate-status", "candidate-close":
		if q.Candidate == nil || q.Candidate.Validate() != nil {
			return false
		}
		capture, err := q.Candidate.Lease.Digest()
		return err == nil && capture == q.CaptureSHA256
	default:
		return false
	}
}
func (q NodeChainPrefixIPCRequest) Clone() NodeChainPrefixIPCRequest {
	if q.Candidate != nil {
		c := q.Candidate.Clone()
		q.Candidate = &c
	}
	return q
}

type NodeChainPrefixIPCResponse struct {
	Schema           int                              `json:"schema"`
	Operation        string                           `json:"operation"`
	Nonce            string                           `json:"nonce"`
	CaptureSHA256    string                           `json:"capture_sha256"`
	OK               bool                             `json:"ok"`
	Receipt          *NodeChainPrefixExecutionReceipt `json:"receipt,omitempty"`
	CandidateReceipt *NodeChainPrefixCandidateReceipt `json:"candidate_receipt,omitempty"`
}

func (r NodeChainPrefixIPCResponse) Valid() bool {
	if r.Schema != 1 || !proofID.MatchString(r.Nonce) || !proofID.MatchString(r.CaptureSHA256) {
		return false
	}
	switch r.Operation {
	case "snapshot":
		return r.CandidateReceipt == nil && r.OK == (r.Receipt != nil)
	case "prepare", "stop":
		return r.Receipt == nil && r.CandidateReceipt == nil
	case "closed":
		return r.OK && r.Receipt == nil && r.CandidateReceipt == nil
	case "candidate-prepare", "candidate-status", "candidate-close":
		return r.Receipt == nil && r.OK == (r.CandidateReceipt != nil)
	default:
		return false
	}
}
func DecodeNodeChainPrefixIPCRequest(raw []byte) (NodeChainPrefixIPCRequest, error) {
	var q NodeChainPrefixIPCRequest
	if decodeNodeChainPrefixJSON(raw, &q, NodeChainPrefixIPCMaximumBytes) != nil || !q.Valid() {
		return NodeChainPrefixIPCRequest{}, errNodeChainPrefix
	}
	return q.Clone(), nil
}
func DecodeNodeChainPrefixIPCResponse(raw []byte) (NodeChainPrefixIPCResponse, error) {
	var r NodeChainPrefixIPCResponse
	if decodeNodeChainPrefixJSON(raw, &r, NodeChainPrefixIPCMaximumBytes) != nil || !r.Valid() {
		return NodeChainPrefixIPCResponse{}, errNodeChainPrefix
	}
	return r, nil
}
func MarshalNodeChainPrefixWorkerCapture(c NodeChainPrefixCapture) ([]byte, error) {
	if c.Validate() != nil {
		return nil, errNodeChainPrefix
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > NodeChainPrefixIPCMaximumBytes {
		return nil, errNodeChainPrefix
	}
	return raw, nil
}

// Every returned HTTP value is checked against the original admitted request;
// the public descriptor alone cannot replace the original lease's identity.
func (l NodeChainPrefixLease) Validate(q NodeChainPrefixRequest, s NodeChainPrefixDescriptor) error {
	digest, err := s.Digest()
	_, eo := l.ExpiresAt.Zone()
	_, bo := l.BootstrapDeadline.Zone()
	if err != nil || q.Validate(s) != nil || !sameNodeChainPrefixRequest(l.Request, q) || l.NodeID != s.EntryNodeID || !proofID.MatchString(l.OwnerID) || !nodeChainPrivateAddress(l.Host) || l.Port != q.Port || l.RegistrySHA256 != digest || l.ExpiresAt.IsZero() || l.BootstrapDeadline.IsZero() || eo != 0 || bo != 0 {
		return errNodeChainPrefix
	}
	if l.Phase != NodeChainPrefixPending && l.Phase != NodeChainPrefixPrepared && l.Phase != NodeChainPrefixFailed && l.Phase != NodeChainPrefixRetired {
		return errNodeChainPrefix
	}
	return nil
}
func (l NodeChainPrefixLease) Capture(s NodeChainPrefixDescriptor) (NodeChainPrefixCapture, error) {
	if l.Validate(l.Request, s) != nil {
		return NodeChainPrefixCapture{}, errNodeChainPrefix
	}
	c := NodeChainPrefixCapture{Schema: 1, Request: l.Request.Clone(), Source: s.Clone(), RegistrySHA256: l.RegistrySHA256, OwnerID: l.OwnerID, Peer: l.Request.Peer, Host: l.Host, BootstrapDeadline: l.BootstrapDeadline}
	return c, c.Validate()
}
func DecodeNodeChainPrefixLease(raw []byte, q NodeChainPrefixRequest, s NodeChainPrefixDescriptor) (NodeChainPrefixLease, error) {
	var v NodeChainPrefixLease
	if decodeNodeChainPrefixJSON(raw, &v, NodeChainPrefixIPCMaximumBytes) != nil || v.Validate(q, s) != nil {
		return NodeChainPrefixLease{}, errNodeChainPrefix
	}
	return v, nil
}
func DecodeNodeChainPrefixLeaseStatus(raw []byte, c NodeChainPrefixCapture, challenge string, started, now time.Time) (NodeChainPrefixLeaseStatus, error) {
	var v NodeChainPrefixLeaseStatus
	if decodeNodeChainPrefixJSON(raw, &v, NodeChainPrefixIPCMaximumBytes) != nil || c.Validate() != nil || v.Lease.Validate(c.Request, c.Source) != nil || v.Lease.OwnerID != c.OwnerID || v.Lease.Host != c.Host || !v.Lease.BootstrapDeadline.Equal(c.BootstrapDeadline) || ValidateNodeChainPrefixExecutionReceipt(v.Receipt, c, challenge, started, now) != nil {
		return NodeChainPrefixLeaseStatus{}, errNodeChainPrefix
	}
	return v, nil
}
func DecodeNodeChainPrefixCandidateReceipt(raw []byte, c NodeChainPrefixCandidateCapture, challenge string, started, now time.Time) (NodeChainPrefixCandidateReceipt, error) {
	var v NodeChainPrefixCandidateReceipt
	if decodeNodeChainPrefixJSON(raw, &v, NodeChainPrefixIPCMaximumBytes) != nil || v.Validate(c, challenge, started, now) != nil {
		return NodeChainPrefixCandidateReceipt{}, errNodeChainPrefix
	}
	return v, nil
}
