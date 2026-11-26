package multihoprelay

// Candidate requests carry their own independent operation secret. Only their
// nested reference to the original proposed lease uses compact credentials.
type nodeChainPublicCandidateRequest struct {
	NodeChainCandidateRequest
	LeaseWire nodeChainRequestWire `json:"lease"`
}

func publicCandidateRequest(q NodeChainCandidateRequest) (nodeChainPublicCandidateRequest, error) {
	if !q.Lease.HasRegisteredFronts() || q.Schema != 3 && q.Schema != 2 || (q.Schema == 3) != (q.Lease.Schema == 8) || q.Validate() != nil {
		return nodeChainPublicCandidateRequest{}, errNodeChainCandidate
	}
	w, err := compactNodeChainRequest(q.Lease)
	return nodeChainPublicCandidateRequest{q, w}, err
}
func (w nodeChainPublicCandidateRequest) restore() (NodeChainCandidateRequest, error) {
	q := w.NodeChainCandidateRequest
	if (q.Schema != 3 && q.Schema != 2) || (w.LeaseWire.PublicFrontCount != nil) != (q.Schema == 3) || (w.LeaseWire.PrivateFrontCount != nil) != (q.Schema == 2) || w.LeaseWire.StatusNonce != nil {
		return NodeChainCandidateRequest{}, errNodeChainCandidate
	}
	var err error
	q.Lease, err = w.LeaseWire.restore()
	if err != nil || q.Validate() != nil {
		return NodeChainCandidateRequest{}, errNodeChainCandidate
	}
	return q, nil
}

func MarshalNodeChainCandidateRequest(q NodeChainCandidateRequest) ([]byte, error) {
	if !q.Lease.HasRegisteredFronts() {
		return boundedNodeChainFrame(q, NodeChainCandidateMaximumBytes)
	}
	w, err := publicCandidateRequest(q)
	if err != nil {
		return nil, err
	}
	return boundedNodeChainFrame(w, NodeChainCandidateMaximumBytes)
}

// The receiving process retains the complete original lease. The operation
// capture digest also binds the member and the server's separate operation
// owner. A different retained lease cannot restore this operation.
type nodeChainPublicCandidateIPC struct {
	Protocol         string                          `json:"protocol"`
	Operation        string                          `json:"operation"`
	Nonce            string                          `json:"nonce"`
	LeaseSHA256      string                          `json:"lease_sha256"`
	CaptureSHA256    string                          `json:"capture_sha256"`
	Request          nodeChainPublicCandidateRequest `json:"request"`
	OperationOwnerID string                          `json:"operation_owner_id"`
}

func MarshalNodeChainCandidateWorkerRequest(q NodeChainCandidateIPCRequest) ([]byte, error) {
	c := q.Capture
	if !c.Lease.Request.HasRegisteredFronts() {
		return boundedNodeChainFrame(q, NodeChainCandidateIPCMaximumBytes)
	}
	if q.Validate() != nil {
		return nil, errNodeChainCandidate
	}
	digest, err := c.Digest()
	if err != nil {
		return nil, err
	}
	request, err := publicCandidateRequest(c.Request)
	if err != nil {
		return nil, err
	}
	return boundedNodeChainFrame(nodeChainPublicCandidateIPC{c.Lease.Request.registeredProtocol("candidate-ipc"), q.Operation, q.Nonce, c.Request.CaptureSHA256, digest, request, c.OperationOwnerID}, NodeChainCandidateIPCMaximumBytes)
}

func DecodeNodeChainCandidateWorkerRequest(raw []byte, lease NodeChainCapture) (NodeChainCandidateIPCRequest, error) {
	if !lease.Request.HasRegisteredFronts() {
		return DecodeNodeChainCandidateIPCRequest(raw)
	}
	var w nodeChainPublicCandidateIPC
	if decodeNodeChainJSON(raw, &w, NodeChainCandidateIPCMaximumBytes) != nil || w.Protocol != lease.Request.registeredProtocol("candidate-ipc") {
		return NodeChainCandidateIPCRequest{}, errNodeChainCandidate
	}
	original, err := lease.Digest()
	if err != nil || original != w.LeaseSHA256 {
		return NodeChainCandidateIPCRequest{}, errNodeChainCandidate
	}
	q, err := w.Request.restore()
	if err != nil || q.Position < 1 || q.Position >= len(lease.Source.Members) {
		return NodeChainCandidateIPCRequest{}, errNodeChainCandidate
	}
	c := NodeChainCandidateCapture{1, lease.Clone(), q, lease.Source.Members[q.Position-1], w.OperationOwnerID}
	digest, err := c.Digest()
	request := NodeChainCandidateIPCRequest{1, w.Operation, w.Nonce, c}
	if err != nil || digest != w.CaptureSHA256 || request.Validate() != nil {
		return NodeChainCandidateIPCRequest{}, errNodeChainCandidate
	}
	return request, nil
}
