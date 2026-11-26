package multihoprelay

// This separate future worker frame does not widen the legacy three-operation
// parser. A capture (16 KiB), request (8 KiB), one member and fixed framing fit
// within 32 KiB. No source contents or arbitrary command are accepted.
const NodeChainCandidateIPCMaximumBytes = 32 << 10

// One fixed receipt plus three hashes and framing fits in the original small
// request budget; no source, member list or error string may enter a response.
const NodeChainCandidateResponseMaximumBytes = 1024

type NodeChainCandidateIPCRequest struct {
	Schema    int                       `json:"schema"`
	Operation string                    `json:"operation"`
	Nonce     string                    `json:"nonce"`
	Capture   NodeChainCandidateCapture `json:"capture"`
}

func (q NodeChainCandidateIPCRequest) Validate() error {
	if q.Schema != 1 || !proofID.MatchString(q.Nonce) || q.Capture.Validate() != nil || (q.Operation != "candidate-prepare" && q.Operation != "candidate-status" && q.Operation != "candidate-close") {
		return errNodeChainCandidate
	}
	return nil
}
func DecodeNodeChainCandidateIPCRequest(raw []byte) (NodeChainCandidateIPCRequest, error) {
	var q NodeChainCandidateIPCRequest
	if decodeNodeChainJSON(raw, &q, NodeChainCandidateIPCMaximumBytes) != nil ||
		q.Capture.Lease.Request.HasRegisteredFronts() || q.Validate() != nil {
		return NodeChainCandidateIPCRequest{}, errNodeChainCandidate
	}
	q.Capture = q.Capture.Clone()
	return q, nil
}

type NodeChainCandidateIPCResponse struct {
	Schema        int                        `json:"schema"`
	Operation     string                     `json:"operation"`
	Nonce         string                     `json:"nonce"`
	CaptureSHA256 string                     `json:"capture_sha256"`
	OK            bool                       `json:"ok"`
	Receipt       *NodeChainCandidateReceipt `json:"receipt,omitempty"`
}

func (r NodeChainCandidateIPCResponse) Validate(q NodeChainCandidateIPCRequest) error {
	digest, err := q.Capture.Digest()
	if !r.OK || q.Validate() != nil || err != nil || r.Schema != 1 || r.Operation != q.Operation || r.Nonce != q.Nonce || r.CaptureSHA256 != digest {
		return errNodeChainCandidate
	}
	if q.Operation == "candidate-close" {
		if r.Receipt != nil {
			return errNodeChainCandidate
		}
		return nil
	}
	if r.OK != (r.Receipt != nil) || r.Receipt != nil && r.Receipt.Validate(q.Capture) != nil {
		return errNodeChainCandidate
	}
	return nil
}
func DecodeNodeChainCandidateIPCResponse(raw []byte, q NodeChainCandidateIPCRequest) (NodeChainCandidateIPCResponse, error) {
	var r NodeChainCandidateIPCResponse
	if decodeNodeChainJSON(raw, &r, NodeChainCandidateResponseMaximumBytes) != nil || r.Validate(q) != nil {
		return NodeChainCandidateIPCResponse{}, errNodeChainCandidate
	}
	return r, nil
}
